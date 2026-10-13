"""Row 41: autonomy budgets (spec §17.6). The ledger counts per task and prices model spend; the guard asks
before a tool call or an egress and enforces the answer; every evaluated record carries the budget object the
verifier recounts (W-W2, with --rulepack)."""

import json
import threading

import httpx

from agentkit import register, session
from conftest import MODEL, StubResolver, rows, verify
import govkit
from govkit import CASE, CLOSE, NOTE, PACK, gov_node, officer, supervisor
from guard.ledger import Ledger
from test_approvals import h, open_task, seal_call, think
from test_guard_approval import env, pending_approval  # noqa: F401  (env is a fixture)

BUDGETS = """budgets:
  - id: case-agent
    match: {harness: [http-agent]}
    limits: {tool_calls: 40, tool_calls_by: {"http:case-api:addCaseNote": 1}, egress_hosts: EGRESS,
             model_spend_micro: 3000000}
    currency: AED
    on_exceed: EXCEED
pricing:
  - {id: local-metered, model: "sha256:*", input_per_mtok_micro: 1000000000, output_per_mtok_micro: 1000000000,
     missing_usage_cost_micro: 50000}
"""


def pack(exceed="block", egress=4) -> str:
    text = PACK + BUDGETS.replace("EXCEED", exceed).replace("EGRESS", str(egress))
    if exceed == "confirm":
        text = text.replace("  notify:", """    - id: budget-overrun
      rules: ["budget:*"]
      approvers: {role: Sijil.Approver.CaseClosure}
  notify:""")
    return text


def start(tools) -> dict:
    r = tools.post("/_sijil/task/start", json={"intent": f"Notes on {CASE}", "session_id": "conv-1"},
                   headers={"X-Sijil-Principal-Token": officer()})
    assert r.status_code == 200, r.text
    return r.json()


def chat(client, t, prompt):
    return client.post("/v1/chat/completions", json={"model": MODEL, "messages": [{"role": "user", "content": prompt}]},
                       headers={"X-Sijil-Agent-Session": t["agent_session"], "X-Sijil-Task-Seq": str(t["task_seq"]),
                                "X-Sijil-Principal-Token": officer()})


def note(client, tools, t, prompt):
    call_id = chat(client, t, prompt).json()["choices"][0]["message"]["tool_calls"][0]["id"]
    return tools.post(f"/case-api/cases/{CASE}/notes", json={"note": NOTE["note"]},
                      headers={"X-Sijil-Tool-Use-Id": call_id, "X-Sijil-Task-Seq": str(t["task_seq"])})


def test_model_spend_is_priced_counted_and_blocked_post_paid(tmp_path):
    seen = []

    def model(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"id": "c", "model": MODEL, "usage": {"prompt_tokens": 1840,
                                                                             "completion_tokens": 96},
                                         "choices": [{"index": 0, "finish_reason": "stop",
                                                      "message": {"role": "assistant", "content": "ok"}}]})
    client, s, _ = gov_node(tmp_path, pack=pack(), handler=model)
    with client:
        register(client)
        sess = session(client)
        r = client.post("/api/agent/task/start", json={"intent_hash": "c" * 64, "harness": "http-agent"},
                        headers={"X-Sijil-Agent-Session": sess["agent_session"], "X-Sijil-Principal-Token": officer()})
        t = {"agent_session": sess["agent_session"], "task_seq": r.json()["seq"]}
        assert chat(client, t, "one").status_code == 200 and chat(client, t, "two").status_code == 200
        r = chat(client, t, "three")
        assert r.status_code == 403 and r.json()["sijill"]["rule_hits"] == ["budget:case-agent:model_spend_micro"]
    assert len(seen) == 2                                              # the third call was never forwarded
    first, second, third = (json.loads(r["ext"]) for r in rows(s.db_path, "type = 'inference'"))
    assert (first["usage"], first["cost_micro"], first["price_rule"]) == \
        ({"input_tokens": 1840, "output_tokens": 96}, 1936000, "local-metered")
    assert [x["budget"]["case-agent"]["model_spend_micro"] for x in (first, second, third)] == \
        [{"limit": 3000000, "used": u} for u in (0, 1936000, 3872000)]
    assert "cost_micro" not in third                                   # a blocked inference costs nothing
    code, line = verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "starter.yaml"))
    assert code == 0 and " budgets=hits:1 " in line, line


def test_a_per_tool_limit_blocks_the_second_note_through_the_adapter(env):
    client, s, tools, api = env(pack())
    t = start(tools)
    assert note(client, tools, t, "add a note").status_code == 201
    r = note(client, tools, t, "add the note again")
    assert r.status_code == 403
    assert r.json()["error"]["rule_hits"] == ["budget:case-agent:tool_calls_by:http:case-api:addCaseNote"]
    assert len(api.seen) == 1
    first, second = rows(s.db_path, "type = 'tool_call'")
    assert json.loads(first["ext"])["budget"] == {"case-agent": {
        "tool_calls": {"limit": 40, "used": 0}, "tool_calls_by:http:case-api:addCaseNote": {"limit": 1, "used": 0}}}
    assert json.loads(second["ext"])["budget"]["case-agent"]["tool_calls_by:http:case-api:addCaseNote"]["used"] == 1
    egress = json.loads(rows(s.db_path, "type = 'egress'")[0]["ext"])
    assert egress["budget"] == {"case-agent": {"egress_hosts": {"limit": 4, "used": 0}}}
    assert tools.post("/_sijil/task/end", json={"task_seq": t["task_seq"]}).json()["blocked"] == 1
    code, line = verify(s.db_path, s.pubkey_path, "--rulepack", str(s.rulepack_path))
    assert code == 0 and " budgets=hits:1 " in line, line


def test_a_stale_budget_answer_is_refused_by_the_ledger_and_asked_again(env, monkeypatch):
    """Two calls of one task race for the last unit: the loser's seal is refused (409) and it counts again."""
    client, s, tools, api = env(pack())
    t = start(tools)
    assert note(client, tools, t, "add a note").status_code == 201
    real, stale = Ledger.call, []

    def call(self, method, path, *args, **kw):
        if path == "/api/agent/budget" and not stale:     # the answer it had before the first note landed
            stale.append(path)
            return {"budget": {}, "exceeded": [], "on_exceed": ""}
        return real(self, method, path, *args, **kw)
    monkeypatch.setattr(Ledger, "call", call)
    r = note(client, tools, t, "add the note again")
    assert stale and r.status_code == 403
    assert r.json()["error"]["rule_hits"] == ["budget:case-agent:tool_calls_by:http:case-api:addCaseNote"]
    assert len(api.seen) == 1 and verify(s.db_path, s.pubkey_path)[0] == 0


def test_an_excess_with_on_exceed_confirm_goes_to_a_named_approver(env):
    client, s, tools, api = env(pack("confirm"))
    t = start(tools)
    assert note(client, tools, t, "add a note").status_code == 201
    out = []
    worker = threading.Thread(target=lambda: out.append(note(client, tools, t, "add the note again")))
    worker.start()
    aid = pending_approval(s)
    request = rows(s.db_path, "type = 'approval'")[0]
    assert json.loads(request["rule_hits"]) == ["budget:case-agent:tool_calls_by:http:case-api:addCaseNote"]
    assert json.loads(request["ext"])["route_id"] == "budget-overrun"
    client.post(f"/api/approval/{aid}/decide", json={"decision": "grant", "token": supervisor()})
    worker.join(10)
    assert out[0].status_code == 201 and len(api.seen) == 2           # the grant admits this call only
    call = rows(s.db_path, "type = 'tool_call'")[1]
    assert (call["decision"], json.loads(call["ext"])["confirmation"]) == ("flag", "granted")
    code, line = verify(s.db_path, s.pubkey_path, "--rulepack", str(s.rulepack_path))
    assert code == 0, line


def test_an_egress_host_over_budget_is_blocked_before_the_upstream(env):
    client, s, tools, api = env(pack(egress=0))
    t = start(tools)
    r = note(client, tools, t, "add a note")
    assert r.status_code == 403 and r.json()["error"]["rule_hits"] == ["budget:case-agent:egress_hosts"]
    assert api.seen == [] and rows(s.db_path, "type = 'egress'")[0]["decision"] == "block"
    assert verify(s.db_path, s.pubkey_path, "--rulepack", str(s.rulepack_path))[0] == 0


def test_a_streamed_answer_asks_for_usage_and_is_priced(tmp_path):
    seen = []

    def model(request):
        seen.append(json.loads(request.content))
        events = [{"model": MODEL, "choices": [{"index": 0, "delta": {"content": "ok"}}]},
                  {"model": MODEL, "choices": [], "usage": {"prompt_tokens": 10, "completion_tokens": 2}}]
        body = "".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n"
        return httpx.Response(200, content=body.encode(), headers={"content-type": "text/event-stream"})
    client, s, _ = gov_node(tmp_path, pack=pack(), handler=model)
    with client:
        r = client.post("/v1/chat/completions", headers={"X-Sijil-Principal-Token": officer()},
                        json={"model": MODEL, "stream": True, "messages": [{"role": "user", "content": "hi"}]})
        assert r.status_code == 200
    assert seen[0]["stream_options"] == {"include_usage": True}
    x = json.loads(rows(s.db_path, "type = 'inference'")[0]["ext"])
    assert (x["usage"], x["cost_micro"]) == ({"input_tokens": 10, "output_tokens": 2}, 12000)
    assert verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "starter.yaml"))[0] == 0


def test_priced_and_unpriced_models_both_verify_strictly_with_the_rulepack(tmp_path, monkeypatch):
    """W2: a priced model's inference seals the pack's price_rule and the recomputed cost; one the pack does not
    price seals neither key (the usage it reports is not sealed either)."""
    other, real = "sha256:" + "ab" * 32, StubResolver.resolve
    monkeypatch.setattr(StubResolver, "resolve", lambda self, m: other if m == "other-model" else real(self, m))
    monkeypatch.setattr(govkit, "POLICY", govkit.POLICY.replace('allow_digests: ["', f'allow_digests: ["{other}", "'))

    def model(request):
        body = json.loads(request.content)
        return httpx.Response(200, json={"id": "c", "model": body["model"],
                                         "usage": {"prompt_tokens": 7, "completion_tokens": 3},
                                         "choices": [{"index": 0, "finish_reason": "stop",
                                                      "message": {"role": "assistant", "content": "ok"}}]})
    client, s, _ = gov_node(tmp_path, pack=pack().replace('model: "sha256:*"', 'model: "sha256:0fbb*"'), handler=model)
    with client:
        for m in (MODEL, "other-model", MODEL):
            r = client.post("/v1/chat/completions", headers={"X-Sijil-Principal-Token": officer()},
                            json={"model": m, "messages": [{"role": "user", "content": "hi"}]})
            assert r.status_code == 200, r.text
    priced, unpriced, _ = (json.loads(r["ext"]) for r in rows(s.db_path, "type = 'inference'"))
    assert (priced["price_rule"], priced["cost_micro"]) == ("local-metered", 10000)
    assert "price_rule" not in unpriced and "cost_micro" not in unpriced and "usage" not in unpriced
    code, line = verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "starter.yaml"))
    assert code == 0, line


def test_a_budget_confirmation_under_the_entra_channel_must_cite_its_grant(tmp_path):
    client, s, _ = gov_node(tmp_path, pack=pack("confirm"))
    with client:
        sess, task = open_task(client)
        parent, call_id = think(client, sess, task)
        hit = "budget:case-agent:tool_calls_by:http:case-api:addCaseNote"
        ext = {"harness": "http-agent", "session_id": "conv-1", "tool": "closeCase", "server": "case-api",
               "qualified": "http:case-api:closeCase", "tool_use_id": call_id, "correlation": "tool_use_id",
               "observed_by": "http_adapter", "summary": {"arg_keys": sorted(CLOSE)}}
        for confirmation in ("granted", "timed-out"):         # anything but a denial is a grant to be cited
            r = seal_call(client, sess, parent, call_id, 0, rule_hits=[hit],
                          ext={**ext, "confirmation": confirmation})
            assert r.status_code == 409 and "must cite its approval_seq" in r.text, r.text
        assert [r["type"] for r in rows(s.db_path)].count("tool_call") == 0
