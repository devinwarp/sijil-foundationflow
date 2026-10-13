"""Row 18g, guard side: a confirm rule routed to a named approver holds the HTTP tool call until the ledger seals
the decision; the tool_call cites it (spec §17.5.2 step 6, §17.3.4 confirm)."""

import json
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import rows, verify
from govkit import CLOSE, CASE, PACK, gov_node, officer, supervisor
from guard import config, http, identity
from guardkit import guard_yaml, ledger_of
from test_guard_http import SPEC, CaseApi

TOOLS = """rulepack: {tmp}/starter.yaml
repo: {tmp}/repo
http_tools:
  listen: 127.0.0.1:8090
  inbound_auth: {{mode: bearer_env}}
  servers:
    - name: case-api
      upstream: https://case.moi.internal/api/v2
      spec: {tmp}/case-api.json
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    def make(pack=PACK):
        monkeypatch.setenv("SIJIL_TOOLS_TOKEN", "tools-secret")
        (tmp_path / "case-api.json").write_text(json.dumps(SPEC))
        client, s, _ = gov_node(tmp_path, pack=pack)
        client.__enter__()
        cfg = config.load(str(guard_yaml(tmp_path, TOOLS.format(tmp=tmp_path))))
        identity.register(ledger_of(client), cfg.agent_id, identity.create_key(cfg.key_path, cfg.repo),
                          cfg.registered_by)
        api = CaseApi()
        adapter = http.Adapter(cfg, ledger_of(client), httpx.AsyncClient(transport=httpx.MockTransport(api)))
        tools = TestClient(http.app(adapter), headers={"X-Sijil-Tools-Token": "tools-secret"})
        tools.__enter__()
        made.append((client, tools))
        return client, s, tools, api
    made = []
    yield make
    for client, tools in made:
        tools.__exit__(None, None, None)
        client.__exit__(None, None, None)


def close_case(client, tools) -> tuple[dict, list]:
    """The officer's task, the model asking for closeCase, and the adapter call in a thread (it waits)."""
    r = tools.post("/_sijil/task/start", json={"intent": f"Close {CASE}", "session_id": "conv-1"},
                   headers={"X-Sijil-Principal-Token": officer()})
    assert r.status_code == 200, r.text
    t = r.json()
    hdr = {"X-Sijil-Agent-Session": t["agent_session"], "X-Sijil-Task-Seq": str(t["task_seq"])}
    reply = client.post("/v1/chat/completions", headers={**hdr, "X-Sijil-Principal-Token": officer()},
                        json={"model": "llama-3.2-3b-instruct", "messages": [{"role": "user", "content": "close it"}]})
    call_id = reply.json()["choices"][0]["message"]["tool_calls"][0]["id"]
    out = []
    worker = threading.Thread(target=lambda: out.append(tools.post(
        f"/case-api/cases/{CASE}/close", json={"resolution": CLOSE["resolution"]},
        headers={"X-Sijil-Tool-Use-Id": call_id, "X-Sijil-Task-Seq": str(t["task_seq"])})))
    worker.start()
    out.append(worker)
    return t, out


def pending_approval(s, timeout=5.0) -> str:
    end = time.time() + timeout
    while time.time() < end:
        found = rows(s.db_path, "type = 'approval'")
        if found:
            return json.loads(found[0]["ext"])["approval_id"]
        time.sleep(0.02)
    raise AssertionError("no approval request was sealed")


def test_a_granted_approval_lets_the_call_through_and_the_call_cites_it(env):
    client, s, tools, api = env()
    t, out = close_case(client, tools)
    aid = pending_approval(s)
    assert api.seen == []                                          # held while the approver decides
    assert client.post(f"/api/approval/{aid}/decide", json={"decision": "grant", "token": supervisor()}).status_code == 200
    out[0].join(10)
    r = out[1]
    assert r.status_code == 200 and len(api.seen) == 1
    request, decision = rows(s.db_path, "type = 'approval'")
    call = rows(s.db_path, "type = 'tool_call'")[0]
    x = json.loads(call["ext"])
    assert (call["decision"], x["confirmation"], x["approval_seq"], x["qualified"]) == \
        ("flag", "granted", decision["seq"], "http:case-api:closeCase")
    assert json.loads(request["ext"])["qualified"] == x["qualified"] and request["input_hash"] == call["input_hash"]
    assert tools.post("/_sijil/task/end", json={"task_seq": t["task_seq"]}).json()["confirmed"] == 1
    code, line = verify(s.db_path, s.pubkey_path)
    assert code == 0 and " approvals=granted:1,refused:0,timeout:0 " in line, line


@pytest.mark.parametrize("how", ["refuse", "timeout"])
def test_a_refused_or_timed_out_approval_blocks_and_the_upstream_is_never_called(env, how):
    client, s, tools, api = env(PACK.replace("timeout_seconds: 900", "timeout_seconds: 1") if how == "timeout"
                                else PACK)
    t, out = close_case(client, tools)
    aid = pending_approval(s)
    if how == "refuse":
        client.post(f"/api/approval/{aid}/decide", json={"decision": "refuse", "token": supervisor()})
    out[0].join(10)
    r = out[1]
    assert r.status_code == 403 and r.json()["error"]["rule_hits"] == ["case-closure-needs-approval"]
    assert api.seen == []
    x = json.loads(rows(s.db_path, "type = 'tool_call'")[0]["ext"])
    assert (x["confirmation"], x["approval_seq"]) == ("denied", rows(s.db_path, "type = 'approval'")[1]["seq"])
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_no_route_for_the_rule_is_an_unavailable_confirm(env):
    client, s, tools, api = env(PACK.replace('rules: ["case-closure-*"]', 'rules: ["payment-*"]'))
    t, out = close_case(client, tools)
    out[0].join(10)
    assert out[1].status_code == 403 and api.seen == [] and rows(s.db_path, "type = 'approval'") == []
    assert json.loads(rows(s.db_path, "type = 'tool_call'")[0]["ext"])["confirmation"] == "unavailable"
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_a_tool_call_under_the_entra_channel_always_cites_its_approval(env):
    client, s, tools, api = env()
    t, out = close_case(client, tools)
    aid = pending_approval(s)
    client.post(f"/api/approval/{aid}/decide", json={"decision": "refuse", "token": supervisor()})
    out[0].join(10)
    x = json.loads(rows(s.db_path, "type = 'tool_call'")[0]["ext"])
    assert x["confirmation"] in ("granted", "denied") and isinstance(x["approval_seq"], int)


class Stub:
    """A ledger that answers the request, then whatever the test hands back for the status."""

    def __init__(self, status):
        self.status = status

    def call(self, method, path, *a, **kw):
        if method == "POST":
            return {"approval_id": "ap1", "deadline": "2099-01-01T00:00:00Z"}
        return self.status


@pytest.mark.parametrize("status", [
    {"approval_id": "ap1", "status": "granted", "decision_seq": None},
    {"approval_id": "ap1", "status": "granted", "decision_seq": True},
    {"approval_id": "ap1", "status": "granted"},
    {"approval_id": "other", "status": "granted", "decision_seq": 5},
    {"status": "granted", "decision_seq": 5},
    "granted", None, [], {"approval_id": "ap1"},
])
def test_a_malformed_decision_is_never_a_grant(status):
    from guard.pipeline import Pipeline
    p = object.__new__(Pipeline)
    p.ledger, p.session = Stub(status), "s"
    call = type("C", (), {"tool": "t", "server": "s", "args": {}, "task_seq": None})()
    confirmation, _ = p.named(call, "1", "tool_use_id", "q", "h", ["r"], {})
    assert confirmation in ("denied", "unavailable")


def test_pending_approvals_do_not_stall_an_ordinary_check(env):
    from guard import pipeline
    client, s, tools, api = env(PACK.replace("timeout_seconds: 900", "timeout_seconds: 3"))
    held = [close_case(client, tools) for _ in range(pipeline.APPROVALS)]
    end = time.time() + 5
    while len(rows(s.db_path, "type = 'approval'")) < pipeline.APPROVALS and time.time() < end:
        time.sleep(0.02)
    t0 = time.time()
    r = tools.post("/_sijil/task/start", json={"intent": f"Read {CASE}", "session_id": "conv-2"},
                   headers={"X-Sijil-Principal-Token": officer()})
    assert r.status_code == 200, r.text
    t = r.json()
    reply = client.post("/v1/chat/completions", headers={"X-Sijil-Agent-Session": t["agent_session"],
                        "X-Sijil-Task-Seq": str(t["task_seq"]), "X-Sijil-Principal-Token": officer()},
                        json={"model": "llama-3.2-3b-instruct", "messages": [{"role": "user", "content": "get it"}]})
    call_id = reply.json()["choices"][0]["message"]["tool_calls"][0]["id"]
    t0 = time.time()
    got = tools.get(f"/case-api/cases/{CASE}", headers={"X-Sijil-Tool-Use-Id": call_id,
                                                         "X-Sijil-Task-Seq": str(t["task_seq"])})
    assert got.status_code == 200, got.text
    assert time.time() - t0 < 1.5      # an ordinary check, through CHECKS, while 8 wait
    for _, out in held:
        out[0].join(15)


def test_a_cancelled_call_frees_its_approval_slot_promptly():
    import asyncio
    from guard import pipeline
    from guard.pipeline import Call, Pipeline

    class Slow:
        def call(self, method, path, *a, **kw):
            if method == "POST":
                return {"approval_id": "ap", "deadline": "2099-01-01T00:00:00Z"}
            time.sleep(0.2)                      # a short poll: still pending
            return {"approval_id": "ap", "status": "pending", "decision_seq": None}

    p = object.__new__(Pipeline)
    p.ledger, p.session = Slow(), "s"
    calls = [Call("r", "t", "s", {}, "h", "x", "y") for _ in range(pipeline.APPROVALS + 1)]

    def check(self, c, *a):                     # stands in for Pipeline.check: just the named wait
        return self.named(c, "1", "tool_use_id", "q", "h", ["r"], {})
    Pipeline.check, saved = check, Pipeline.check
    try:
        async def go():
            tasks = [asyncio.create_task(pipeline.check(p, c)) for c in calls[:pipeline.APPROVALS]]
            await asyncio.sleep(0.5)
            assert (await asyncio.to_thread(p.named, calls[-1], "1", "t", "q", "h", ["r"], {}))[0] == "unavailable"
            for t in tasks:
                t.cancel()
            await asyncio.sleep(0.6)             # one short poll later the threads let go
            t0 = time.time()
            nine = asyncio.create_task(pipeline.check(p, calls[-1]))
            await asyncio.sleep(0.5)
            assert not nine.done()               # it holds a slot rather than being refused at once
            calls[-1].cancel.set()
            assert (await nine)[0] == "unavailable" and time.time() - t0 < 3
        asyncio.run(go())
    finally:
        Pipeline.check = saved
