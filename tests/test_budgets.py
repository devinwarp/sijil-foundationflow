"""Row 41: autonomy budgets (spec §17.6). The ledger counts per task and prices model spend; the guard asks
before a tool call or an egress and enforces the answer; every evaluated record carries the budget object the
verifier recounts (W-W2, with --rulepack)."""

import asyncio
import importlib.util
import json
import threading

import httpx
import pytest

from agentkit import register, session
from conftest import ADMIN, MODEL, VERIFIER, StubResolver, make_node, rows, verify
import govkit
from govkit import CASE, CLOSE, NOTE, PACK, gov_node, officer, supervisor
from guard.ledger import Ledger
from sijill import record
from test_chat_tool_uses import API, API_POLICY, answer, ask
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


def usage_model(usage):
    def model(request):
        return httpx.Response(200, json={"id": "c", "model": MODEL, "usage": usage,
                                         "choices": [{"index": 0, "finish_reason": "stop",
                                                      "message": {"role": "assistant", "content": "ok"}}]})
    return model


def test_a_halted_call_drops_a_client_sent_budget_and_verifies(tmp_path):
    client, s, _ = gov_node(tmp_path, pack=pack())
    with client:
        sess, task = open_task(client)
        parent, call_id = think(client, sess, task)
        assert client.post("/api/admin/halt", json={"halted": True}, headers=ADMIN).status_code == 200
        forged = {"case-agent": {"tool_calls": {"limit": 40, "used": 999}}}
        ext = {"harness": "http-agent", "session_id": "conv-1", "tool": "closeCase", "server": "case-api",
               "qualified": "http:case-api:closeCase", "tool_use_id": call_id, "correlation": "tool_use_id",
               "observed_by": "http_adapter", "budget": forged,
               "summary": {"method": "POST", "host": "case.moi.internal", "path_template": "/cases/{caseId}/close",
                           "arg_keys": sorted(CLOSE)}}
        r = seal_call(client, sess, parent, call_id, 0, granted=False, rule_hits=[], ext=ext)
        assert r.status_code == 200 and r.json()["decision"] == "block"
    x = json.loads(rows(s.db_path, "type = 'tool_call'")[0]["ext"])
    assert "budget" not in x
    assert verify(s.db_path, s.pubkey_path)[0] == 0, verify(s.db_path, s.pubkey_path)
    assert verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "starter.yaml"))[0] == 0


def test_bad_token_counts_are_missing_usage_and_never_lower_spend(tmp_path):
    for i, usage in enumerate(({"prompt_tokens": -10 ** 9, "completion_tokens": 5},
                               {"prompt_tokens": 1.5, "completion_tokens": 5}, {"prompt_tokens": "9"})):
        d = tmp_path / str(i)
        d.mkdir()
        client, s, _ = gov_node(d, pack=pack(), handler=usage_model(usage))
        with client:
            r = client.post("/v1/chat/completions", headers={"X-Sijil-Principal-Token": officer()},
                            json={"model": MODEL, "messages": [{"role": "user", "content": "hi"}]})
            assert r.status_code == 200
        x = json.loads(rows(s.db_path, "type = 'inference'")[0]["ext"])
        assert "usage" not in x and x["cost_micro"] == 50000                # missing_usage_cost_micro
        assert verify(s.db_path, s.pubkey_path, "--rulepack", str(d / "starter.yaml"))[0] == 0


def test_the_verifier_refuses_a_negative_or_non_int_cost():
    spec = importlib.util.spec_from_file_location("sijil_verify", VERIFIER)
    v = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v)
    p = {"pricing": [{"id": "m", "model": "sha256:*", "input_per_mtok_micro": 10 ** 9,
                      "output_per_mtok_micro": 10 ** 9, "missing_usage_cost_micro": 5}]}
    ok = lambda u: v.cost(p, "sha256:ab", {"price_rule": "m", "usage": u})      # noqa: E731
    assert ok({"input_tokens": 2, "output_tokens": 1}) == 3000
    for bad in ({"input_tokens": -1, "output_tokens": 1}, {"input_tokens": 1.5, "output_tokens": 1},
                {"input_tokens": "1", "output_tokens": 1}):
        assert ok(bad) is None


def test_a_forwarded_billed_answer_withheld_in_api_mode_carries_its_cost_and_a_preflight_block_none(tmp_path):
    (tmp_path / "pack.yaml").write_text("""rulepack_id: api-pack
version: 0.1.0
rules: []
pricing:
  - {id: metered, model: "api:*", input_per_mtok_micro: 1000000000, output_per_mtok_micro: 1000000000,
     missing_usage_cost_micro: 700}
""")
    client, s = make_node(tmp_path, answer(model="gpt-4.1-2025-09-30", content="secret"), API_POLICY,
                          rulepack_path=str(tmp_path / "pack.yaml"), **API)
    with client:
        assert ask(client, model="gpt-4.1").status_code == 403          # the answering snapshot is not approved
        assert ask(client, model="gpt-4.1", content="my passport number is X").status_code == 403    # not forwarded
    withheld, preflight = (json.loads(r["ext"]) for r in rows(s.db_path, "type = 'inference'"))
    assert (withheld["price_rule"], withheld["cost_micro"]) == ("metered", 700)
    assert "cost_micro" not in preflight and "price_rule" not in preflight, (withheld, preflight)
    assert verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "pack.yaml"))[0] == 0


def test_a_stream_that_errors_after_tokens_is_charged_for_them(tmp_path):
    def model(request):
        events = [{"model": MODEL, "choices": [{"index": 0, "delta": {"content": "partial"}}]},
                  {"error": {"message": "boom"}}]
        body = "".join(f"data: {json.dumps(e)}\n\n" for e in events)
        return httpx.Response(200, content=body.encode(), headers={"content-type": "text/event-stream"})
    client, s, _ = gov_node(tmp_path, pack=pack(), handler=model)
    with client:
        client.post("/v1/chat/completions", headers={"X-Sijil-Principal-Token": officer()},
                    json={"model": MODEL, "stream": True, "messages": [{"role": "user", "content": "hi"}]})
    x = json.loads(rows(s.db_path, "type = 'inference'")[0]["ext"])
    assert (x["price_rule"], x["cost_micro"]) == ("local-metered", 50000)
    assert verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "starter.yaml"))[0] == 0


def test_a_non_object_stream_options_is_a_400(tmp_path):
    client, s, _ = gov_node(tmp_path, pack=pack())
    with client:
        r = client.post("/v1/chat/completions", headers={"X-Sijil-Principal-Token": officer()},
                        json={"model": MODEL, "stream": True, "stream_options": "yes",
                              "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 400 and rows(s.db_path, "type = 'inference'") == []


def test_racing_tool_calls_admit_exactly_the_limit(env):
    client, s, tools, api = env(pack().replace("3000000", "300000000"))
    t = start(tools)
    ids = [chat(client, t, f"add note {i}").json()["choices"][0]["message"]["tool_calls"][0]["id"] for i in range(5)]
    barrier, out = threading.Barrier(5), []

    def go(call_id):
        barrier.wait()
        out.append(tools.post(f"/case-api/cases/{CASE}/notes", json={"note": NOTE["note"]},
                              headers={"X-Sijil-Tool-Use-Id": call_id, "X-Sijil-Task-Seq": str(t["task_seq"])}
                              ).status_code)
    workers = [threading.Thread(target=go, args=(i,)) for i in ids]
    [w.start() for w in workers]
    [w.join(20) for w in workers]
    assert sorted(out) == [201, 403, 403, 403, 403] and len(api.seen) == 1
    assert verify(s.db_path, s.pubkey_path)[0] == 0
    assert verify(s.db_path, s.pubkey_path, "--rulepack", str(s.rulepack_path))[0] == 0


def test_racing_inferences_are_withheld_once_the_budget_is_spent(tmp_path):
    async def model(request):
        await asyncio.sleep(0.3)                                       # all five pass admission before any seal
        return usage_model({"prompt_tokens": 1840, "completion_tokens": 96})(request)
    client, s, _ = gov_node(tmp_path, pack=pack(), handler=model)
    with client:
        register(client)
        sess = session(client)
        r = client.post("/api/agent/task/start", json={"intent_hash": "c" * 64, "harness": "http-agent"},
                        headers={"X-Sijil-Agent-Session": sess["agent_session"], "X-Sijil-Principal-Token": officer()})
        t = {"agent_session": sess["agent_session"], "task_seq": r.json()["seq"]}
        barrier, out = threading.Barrier(5), []

        def go():
            barrier.wait()
            out.append(chat(client, t, "hi").status_code)
        workers = [threading.Thread(target=go) for _ in range(5)]
        [w.start() for w in workers]
        [w.join(20) for w in workers]
    assert sorted(out) == [200, 200, 403, 403, 403]
    assert verify(s.db_path, s.pubkey_path)[0] == 0
    assert verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "starter.yaml"))[0] == 0


def test_egress_hosts_are_counted_lowercased(env):
    client, s, tools, api = env(pack(egress=1))
    t = start(tools)
    assert note(client, tools, t, "add a note").status_code == 201
    x = json.loads(rows(s.db_path, "type = 'egress'")[0]["ext"])
    assert x["host"] == x["host"].lower()
    from sijill import budgets
    task = client.app.state.node.store.get(t["task_seq"])
    n = client.app.state.node
    assert budgets.evaluate(n.rulepack, n.store, task, "egress", host=x["host"].upper())[1] == []
    assert verify(s.db_path, s.pubkey_path, "--rulepack", str(s.rulepack_path))[0] == 0


def _failed_forward_is_charged_the_fallback(tmp_path, handler, stream=False, status=None):
    client, s, _ = gov_node(tmp_path, pack=pack(), handler=handler)
    with client:
        r = client.post("/v1/chat/completions", headers={"X-Sijil-Principal-Token": officer()},
                        json={"model": MODEL, "stream": stream, "messages": [{"role": "user", "content": "hi"}]})
        if status:
            assert r.status_code == status
    rec = rows(s.db_path, "type = 'inference'")[0]
    x = json.loads(rec["ext"])
    assert "upstream-error" in rec["rule_hits"] or "upstream" in rec["rule_hits"]
    assert (x["price_rule"], x["cost_micro"]) == ("local-metered", 50000) and "usage" not in x
    code, line = verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "starter.yaml"))
    assert code == 0, line


def test_an_upstream_500_is_charged_the_missing_usage_cost(tmp_path):
    _failed_forward_is_charged_the_fallback(
        tmp_path, lambda request: httpx.Response(500, json={"error": {"message": "down"}}), status=500)


def test_an_error_as_the_first_stream_event_is_charged_the_missing_usage_cost(tmp_path):
    body = f"data: {json.dumps({'error': {'message': 'boom'}})}\n\n".encode()
    _failed_forward_is_charged_the_fallback(
        tmp_path, lambda request: httpx.Response(200, content=body, headers={"content-type": "text/event-stream"}),
        stream=True)


def test_an_upstream_timeout_is_charged_the_missing_usage_cost(tmp_path):
    def timeout(request):
        raise httpx.ReadTimeout("slow", request=request)
    _failed_forward_is_charged_the_fallback(tmp_path, timeout, status=502)


def test_a_streamed_answer_withheld_in_api_mode_carries_its_cost(tmp_path):
    from test_chat_tool_uses import chunk, streamed
    (tmp_path / "pack.yaml").write_text("""rulepack_id: api-pack
version: 0.1.0
rules: []
pricing:
  - {id: metered, model: "api:*", input_per_mtok_micro: 1000000000, output_per_mtok_micro: 1000000000,
     missing_usage_cost_micro: 700}
""")
    client, s = make_node(tmp_path, streamed(chunk(model="gpt-5", content="hidden")), API_POLICY,
                          rulepack_path=str(tmp_path / "pack.yaml"), **API)
    with client, client.stream("POST", "/v1/chat/completions", json={
            "model": "gpt-4.1", "stream": True, "messages": [{"role": "user", "content": "hi"}]}) as r:
        assert "decision=block" in "".join(r.iter_text())
    [rec] = rows(s.db_path, "type = 'inference'")
    x = json.loads(rec["ext"])
    assert (rec["decision"], x["price_rule"], x["cost_micro"]) == ("block", "metered", 700)
    assert verify(s.db_path, s.pubkey_path)[0] == 0
    assert verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "pack.yaml"))[0] == 0


USAGE = {"prompt_tokens": 1840, "completion_tokens": 96}            # 1936000 micro: two calls pass the limit
UNHASHABLE = [                                                       # (tool call arguments, answer text)
    ('{"note": NaN}', None),                         # NaN in the arguments
    ('{"note": "\\ud800"}', None),                   # JSON arguments escaping a lone surrogate
    ("{not json \ud800", None),                      # raw arguments carrying one
    ("{}", "lone \udfff"),                           # the answer text carrying one
]


def task_of(client) -> dict:
    register(client)
    sess = session(client)
    r = client.post("/api/agent/task/start", json={"intent_hash": "c" * 64, "harness": "http-agent"},
                    headers={"X-Sijil-Agent-Session": sess["agent_session"], "X-Sijil-Principal-Token": officer()})
    return {"agent_session": sess["agent_session"], "task_seq": r.json()["seq"]}


def spent_then_blocked(tmp_path, s, seen, results):
    """Both unhashable answers are sealed as priced upstream_errors, so the third call is blocked unforwarded."""
    assert len(seen) == 2
    first, second, third = rows(s.db_path, "type = 'inference'")
    for rec in (first, second):
        x = json.loads(rec["ext"])
        assert json.loads(rec["rule_hits"]) == ["upstream_error"] and rec["output_hash"] == ""
        assert (x["usage"], x["cost_micro"], x["price_rule"]) == \
            ({"input_tokens": 1840, "output_tokens": 96}, 1936000, "local-metered")
        assert "tool_uses" not in x and len(x["response_hash"]) == 64
    assert json.loads(second["ext"])["response_hash"] == results[1]
    assert json.loads(third["rule_hits"]) == ["budget:case-agent:model_spend_micro"] and third["decision"] == "block"
    code, line = verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "starter.yaml"))
    assert code == 0 and " budgets=hits:1 " in line, line


@pytest.mark.parametrize("arguments,content", UNHASHABLE)
def test_an_unhashable_answer_is_sealed_priced_and_counts_toward_the_budget(tmp_path, arguments, content):
    """A model answer no record can hash (§2.2) was forwarded and billed: sealed as an upstream_error, priced, its raw
    bytes hashed, so a prompt-injected model cannot spend outside the budget by repeating it."""
    seen, raw = [], []

    def model(request):
        seen.append(request)
        calls = [{"id": "call_U", "type": "function", "function": {"name": "addCaseNote", "arguments": arguments}}]
        body = json.dumps({"id": "c", "model": MODEL, "usage": USAGE, "choices": [{"index": 0, "finish_reason": "stop",
                           "message": {"role": "assistant", "content": content, "tool_calls": calls}}]}).encode()
        raw.append(record.sha256_hex(body))
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})
    client, s, _ = gov_node(tmp_path, pack=pack(), handler=model)
    with client:
        t = task_of(client)
        for _ in range(2):
            r = chat(client, t, "add the note")
            assert r.status_code == 502 and r.json()["error"]["type"] == "upstream_error"
        assert chat(client, t, "add the note").status_code == 403
    spent_then_blocked(tmp_path, s, seen, raw)


@pytest.mark.parametrize("arguments,content", UNHASHABLE)
def test_an_unhashable_streamed_answer_is_sealed_priced_and_counts_toward_the_budget(tmp_path, arguments, content):
    seen, raw = [], []

    def model(request):
        seen.append(request)
        lines = [{"model": MODEL, "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}]},
                 {"model": MODEL, "choices": [{"index": 0, "finish_reason": None, "delta": {"tool_calls": [
                     {"index": 0, "id": "call_U", "function": {"name": "addCaseNote", "arguments": arguments}}]}}]},
                 {"model": MODEL, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": USAGE}]
        events = ["data: " + json.dumps(e) for e in lines]
        raw.append(record.sha256_hex(("\n\n".join(events) + "\n\n").encode()))     # every line relayed
        return httpx.Response(200, content=("\n\n".join(events) + "\n\ndata: [DONE]\n\n").encode(),
                              headers={"content-type": "text/event-stream"})
    client, s, _ = gov_node(tmp_path, pack=pack(), handler=model)
    with client:
        t = task_of(client)
        for _ in range(2):
            r = client.post("/v1/chat/completions", json={"model": MODEL, "stream": True, "messages": [
                {"role": "user", "content": "add the note"}]}, headers={
                "X-Sijil-Agent-Session": t["agent_session"], "X-Sijil-Task-Seq": str(t["task_seq"]),
                "X-Sijil-Principal-Token": officer()})
            assert '"type": "upstream_error"' in r.text and "[DONE]" not in r.text
        assert chat(client, t, "add the note").status_code == 403
    spent_then_blocked(tmp_path, s, seen, raw)


DEEP = "[" * 100000 + "]" * 100000          # past the parser's recursion limit


def deep_post(client, t, stream):
    return client.post("/v1/chat/completions", json={"model": MODEL, "stream": stream, "messages": [
        {"role": "user", "content": "add the note"}]}, headers={
        "X-Sijil-Agent-Session": t["agent_session"], "X-Sijil-Task-Seq": str(t["task_seq"]),
        "X-Sijil-Principal-Token": officer()})


@pytest.mark.parametrize("stream", [False, True])
def test_deeply_nested_tool_arguments_are_sealed_raw_priced_and_counted(tmp_path, stream):
    """Arguments nested past the parser's limit do not parse, so they hash as raw UTF-8 (args_raw): the answer is
    sealed and priced like any other, and a prompt-injected model cannot spend outside the budget with them."""
    def model(request):
        call = {"id": "call_U", "type": "function", "function": {"name": "addCaseNote", "arguments": DEEP}}
        if not stream:
            return httpx.Response(200, json={"id": "c", "model": MODEL, "usage": USAGE, "choices": [{
                "index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": None,
                                                                 "tool_calls": [call]}}]})
        lines = [{"model": MODEL, "choices": [{"index": 0, "finish_reason": None, "delta": {"tool_calls": [
                     {**call, "index": 0}]}}]},
                 {"model": MODEL, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": USAGE}]
        return httpx.Response(200, content=("".join(f"data: {json.dumps(e)}\n\n" for e in lines) +
                                            "data: [DONE]\n\n").encode(), headers={"content-type": "text/event-stream"})
    client, s, _ = gov_node(tmp_path, pack=pack(), handler=model)
    with client:
        t = task_of(client)
        for _ in range(2):
            r = deep_post(client, t, stream)
            assert r.status_code == 200 and (not stream or "data: [DONE]" in r.text)
        assert chat(client, t, "add the note").status_code == 403
    first, second, third = rows(s.db_path, "type = 'inference'")
    for rec in (first, second):
        x = json.loads(rec["ext"])
        assert rec["decision"] == "allow" and x["cost_micro"] == 1936000
        assert x["tool_uses"] == [{"id": "call_U", "name": "addCaseNote", "args_hash": record.sha256_hex(DEEP.encode()),
                                   "args_raw": True}]
    assert json.loads(third["rule_hits"]) == ["budget:case-agent:model_spend_micro"]
    code, line = verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "starter.yaml"))
    assert code == 0, line


def test_a_deeply_nested_streamed_event_is_relayed_and_sealed(tmp_path):
    """An event nested past the parser's limit is relayed as it came and hashed with the rest; the usage still counts."""
    def model(request):
        lines = ['data: {"x": ' + DEEP + "}",
                 "data: " + json.dumps({"model": MODEL, "choices": [{"index": 0, "delta": {"content": "ok"},
                                                                     "finish_reason": "stop"}], "usage": USAGE})]
        return httpx.Response(200, content=("\n\n".join(lines) + "\n\ndata: [DONE]\n\n").encode(),
                              headers={"content-type": "text/event-stream"})
    client, s, _ = gov_node(tmp_path, pack=pack(), handler=model)
    with client:
        t = task_of(client)
        for _ in range(2):
            assert "data: [DONE]" in deep_post(client, t, True).text
        assert chat(client, t, "add the note").status_code == 403
    first, second, _ = rows(s.db_path, "type = 'inference'")
    assert [json.loads(r["ext"])["cost_micro"] for r in (first, second)] == [1936000, 1936000]
    code, line = verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "starter.yaml"))
    assert code == 0, line


def test_a_deeply_nested_answer_is_a_priced_upstream_error(tmp_path):
    """An answer body nested past the parser's limit is malformed: sealed as an upstream_error priced at
    missing_usage_cost_micro, so repeating it reaches the budget like any forwarded call."""
    seen = []

    def model(request):
        seen.append(request)
        return httpx.Response(200, content=('{"x": ' + DEEP + "}").encode(), headers={"content-type": "application/json"})
    client, s, _ = gov_node(tmp_path, pack=pack(), handler=model)
    with client:
        t = task_of(client)
        statuses = [chat(client, t, "add the note").status_code for _ in range(61)]
    assert statuses == [502] * 60 + [403] and len(seen) == 60
    recs = rows(s.db_path, "type = 'inference'")
    assert all(json.loads(r["rule_hits"]) == ["upstream_error"] and json.loads(r["ext"])["cost_micro"] == 50000
               for r in recs[:60])
    code, line = verify(s.db_path, s.pubkey_path, "--rulepack", str(tmp_path / "starter.yaml"))
    assert code == 0, line


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("body", ['{"x": ' + DEEP + "}", "{not json"], ids=["deep", "malformed"])
def test_an_error_answer_that_does_not_parse_is_sealed_as_an_upstream_error(tmp_path, stream, body):
    """A non-200 answer is relayed as the model runtime's error; one that does not parse is still sealed and priced."""
    def model(request):
        return httpx.Response(500, content=body.encode(), headers={"content-type": "application/json"})
    client, s, _ = gov_node(tmp_path, pack=pack(), handler=model)
    with client:
        t = task_of(client)
        assert deep_post(client, t, stream).status_code == 500
    rec, = rows(s.db_path, "type = 'inference'")
    assert json.loads(rec["rule_hits"]) == ["upstream_error"] and json.loads(rec["ext"])["cost_micro"] == 50000
