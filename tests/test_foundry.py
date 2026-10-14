"""Row 42: the Azure AI Foundry Responses relay (spec §17.4). The transcript below is synthetic, shaped like the
OpenAI Responses API that Foundry serves; it stands in for the pilot-tenant capture §17.8 asks for."""

import asyncio
import json
import threading
import time

import httpx
import pytest

from conftest import rows, verify
from govkit import CLOSER, OFFICER, POLICY, gov_node, human, officer, supervisor
from sijill import record

ENDPOINT = "https://moi-pilot.services.ai.azure.com/api/projects/case-agents"
FOUNDRY_AGENT = "spiffe://moi.gov.ae/agent/foundry-case-agent"
FOUNDRY_POLICY = POLICY.replace(  # the answering model is checked against the allowlist like any API model
    'allow_digests: ["', 'allow_digests: ["api:azure-foundry:gpt-4.1-2025-04-14", "') + f"""foundry:
  endpoint: {ENDPOINT}
  agent_name: case-agent
  agent_id: {FOUNDRY_AGENT}
  registered_by: local:{"b" * 64}
  token_env: SIJIL_TEST_FOUNDRY_TOKEN
"""
PACK = f"""rulepack_id: moi-foundry-pack
version: 0.1.0
rules:
  - id: no-case-delete
    on: tool_call
    match: {{tool: ["mcp:case-mcp:delete_case"]}}
    action: block
  - id: case-closure-needs-approval
    on: tool_call
    match: {{tool: ["mcp:case-mcp:close_case"]}}
    action: confirm
hitl:
  channel: entra
  entra: {{issuer_id: entra-moi, audience: "api://sijil-approvals"}}
  routes:
    - id: case-closure
      rules: ["case-closure-*"]
      approvers: {{role: {CLOSER}}}
      min_assurance: high
"""
CASE_ARGS = json.dumps({"caseId": "MOI-2026-004211"})
FIRST = {"id": "resp_01", "object": "response", "model": "gpt-4.1-2025-04-14", "status": "completed",
         "agent": {"name": "case-agent", "version": "3"}, "usage": {"input_tokens": 900, "output_tokens": 40},
         "output": [
             {"type": "web_search_call", "id": "ws_01", "status": "completed",
              "action": {"type": "search", "query": "MOI salary certificate rules"}},
             {"type": "mcp_call", "id": "mcp_kb_01", "server_label": "policy-kb", "name": "search",
              "arguments": json.dumps({"q": "closure"}), "output": "Closure needs a supervisor.", "status": "completed"},
             {"type": "mcp_approval_request", "id": "mcpr_01", "server_label": "case-mcp", "name": "get_case",
              "arguments": CASE_ARGS},
             {"type": "mcp_approval_request", "id": "mcpr_02", "server_label": "case-mcp", "name": "delete_case",
              "arguments": CASE_ARGS}]}
SECOND = {"id": "resp_02", "object": "response", "model": "gpt-4.1-2025-04-14", "status": "completed",
          "usage": {"input_tokens": 1200, "output_tokens": 30},
          "output": [
              {"type": "mcp_call", "id": "mcp_01", "approval_request_id": "mcpr_01", "server_label": "case-mcp",
               "name": "get_case", "arguments": CASE_ARGS, "output": json.dumps({"status": "open"})},
              {"type": "message", "id": "msg_01", "role": "assistant",
               "content": [{"type": "output_text", "text": "The case is open. I did not delete it."}]}]}
CLOSE_ASK = {"id": "resp_10", "object": "response", "model": "gpt-4.1-2025-04-14", "status": "completed",
             "output": [{"type": "mcp_approval_request", "id": "mcpr_10", "server_label": "case-mcp",
                         "name": "close_case", "arguments": CASE_ARGS}]}
CLOSED = {"id": "resp_11", "object": "response", "model": "gpt-4.1-2025-04-14", "status": "completed",
          "output": [{"type": "mcp_call", "id": "mcp_10", "approval_request_id": "mcpr_10", "server_label": "case-mcp",
                      "name": "close_case", "arguments": CASE_ARGS, "output": "closed"},
                     {"type": "message", "id": "msg_10", "role": "assistant",
                      "content": [{"type": "output_text", "text": "Closed."}]}]}


class Foundry:
    """The Foundry project: answers the transcript by previous_response_id and keeps what it was sent."""

    def __init__(self):
        self.seen = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.seen.append((dict(request.headers), body))
        reply = {None: CLOSE_ASK if "close" in json.dumps(body.get("input")) else FIRST, "resp_01": SECOND,
                 "resp_10": CLOSED}[body.get("previous_response_id")]
        return httpx.Response(200, json=reply)


@pytest.fixture
def relay(tmp_path, monkeypatch):
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    foundry = Foundry()
    client, s, _ = gov_node(tmp_path, pack=PACK, handler=foundry, policy=FOUNDRY_POLICY)
    with client:
        yield client, s, foundry


def portal(client, text="What is the status of case MOI-2026-004211? Then delete it.", token=None, conversation="conv_abc"):
    return client.post("/v1/responses", headers={"X-Sijil-Principal-Token": token or officer()},
                       json={"agent": {"name": "case-agent", "type": "agent_reference"}, "conversation": conversation,
                             "input": text})


def test_the_gate_answers_foundry_and_the_portal_sees_only_the_final_answer(relay, tmp_path):
    client, s, foundry = relay
    r = portal(client)
    assert r.status_code == 200 and r.json() == SECOND
    headers, follow_up = foundry.seen[1]
    assert headers["authorization"] == "Bearer ledger-entra-token" and not any(h.startswith("x-sijil") for h in headers)
    assert follow_up["previous_response_id"] == "resp_01" and "conversation" not in follow_up
    assert follow_up["input"] == [
        {"type": "mcp_approval_response", "approve": True, "approval_request_id": "mcpr_01"},
        {"type": "mcp_approval_response", "approve": False, "approval_request_id": "mcpr_02"}]
    reg = rows(s.db_path, "type = 'agent_register'")[0]
    assert json.loads(reg["ext"])["relay_binding"] == {"platform": "foundry", "agent_name": "case-agent",
                                                      "endpoint_host": "moi-pilot.services.ai.azure.com"}
    start = rows(s.db_path, "type = 'task_start'")[0]
    assert (start["agent_id"], start["principal"], json.loads(start["ext"])["agent_auth"]) == \
        (FOUNDRY_AGENT, human(OFFICER), "relay")
    first, second = rows(s.db_path, "type = 'inference'")
    x = json.loads(first["ext"])
    assert (first["model_digest"], x["api"], x["foundry"]["items"]) == (
        "api:azure-foundry:gpt-4.1-2025-04-14", "foundry_responses",
        {"web_search_call": 1, "mcp_call": 1, "mcp_approval_request": 2})
    assert [u["id"] for u in x["tool_uses"]] == ["ws_01", "mcp_kb_01", "mcpr_01", "mcpr_02"]
    calls = {json.loads(c["ext"])["foundry_item_id"]: c for c in rows(s.db_path, "type = 'tool_call'")}
    assert {k: (c["decision"], json.loads(c["ext"]).get("after_the_fact", False)) for k, c in calls.items()} == {
        "ws_01": ("allow", True), "mcp_kb_01": ("allow", True), "mcpr_01": ("allow", False), "mcpr_02": ("block", False)}
    assert json.loads(calls["mcpr_02"]["rule_hits"]) == ["no-case-delete"]
    results = {r["parent_seq"]: r for r in rows(s.db_path, "type = 'tool_result'")}
    assert results[str(calls["mcpr_01"]["seq"])]["source_label"] == "mcp:case-mcp"
    assert results[str(calls["ws_01"]["seq"])]["source_label"] == "web"
    assert json.loads(second["ext"])["foundry"]["previous_response_id"] == "resp_01"
    assert portal(client, "And now?").status_code == 200                    # the same conversation, the same task
    assert len(rows(s.db_path, "type = 'task_start'")) == 1
    code, line = verify(s.db_path, s.pubkey_path)
    assert code == 0 and "relay:1" in line and line.endswith(" after_the_fact=4"), line


def test_a_confirm_rule_at_the_gate_goes_to_a_named_approver(relay):
    client, s, foundry = relay
    out = []
    worker = threading.Thread(target=lambda: out.append(portal(client, "close the case")))
    worker.start()
    for _ in range(250):
        if rows(s.db_path, "type = 'approval'"):
            break
        time.sleep(0.02)
    aid = json.loads(rows(s.db_path, "type = 'approval'")[0]["ext"])["approval_id"]
    assert client.post(f"/api/approval/{aid}/decide", json={"decision": "grant", "token": supervisor()}).status_code == 200
    worker.join(10)
    assert out[0].status_code == 200 and out[0].json() == CLOSED
    assert foundry.seen[1][1]["input"][0]["approve"] is True
    call = rows(s.db_path, "type = 'tool_call'")[0]
    assert (call["decision"], json.loads(call["ext"])["confirmation"]) == ("flag", "granted")
    code, line = verify(s.db_path, s.pubkey_path)
    assert code == 0 and " approvals=granted:1," in line, line


def test_without_a_valid_user_token_nothing_reaches_foundry(relay):
    client, s, foundry = relay
    r = client.post("/v1/responses", json={"conversation": "conv_abc", "input": "hello"})
    assert r.status_code == 401 and r.json()["sijill"]["rule_hits"] == ["principal-missing"]
    assert portal(client, conversation="").status_code == 400
    assert foundry.seen == []
    refusal = rows(s.db_path, "type = 'inference'")[0]
    assert (refusal["decision"], refusal["task_seq"], refusal["agent_id"]) == ("block", "", FOUNDRY_AGENT)
    # §17.4.3: model_id is the agent name until Foundry reports one, and model_digest follows it
    assert (refusal["model_id"], refusal["model_digest"]) == ("case-agent", "api:azure-foundry:case-agent")
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_a_policy_foundry_block_is_checked(tmp_path):
    from sijill import policy
    (tmp_path / "p.yaml").write_text(FOUNDRY_POLICY.replace(f"agent_id: {FOUNDRY_AGENT}", "agent_id: case-agent"))
    with pytest.raises(ValueError, match="foundry"):
        policy.load(tmp_path / "p.yaml")
    (tmp_path / "p.yaml").write_text(FOUNDRY_POLICY.replace("principals:", "principals_off:"))
    with pytest.raises(ValueError, match="principals"):
        policy.load(tmp_path / "p.yaml")


PRICED = PACK + """pricing:
  - {id: foundry-gpt, model: "api:azure-foundry:gpt-4.1*", input_per_mtok_micro: 1000000, output_per_mtok_micro: 2000000,
     missing_usage_cost_micro: 777}
"""


def test_relay_inferences_are_priced_and_the_chain_verifies_with_the_rulepack(tmp_path, monkeypatch):
    """Task 7's rule on the relay: a forwarded, priced inference seals price_rule and an int cost_micro; no usage or
    a failed upstream is charged missing_usage_cost_micro."""
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    foundry = Foundry()
    state = {"fail": False}

    def handler(request):
        if state["fail"]:
            return httpx.Response(500, json={"error": "down"})
        resp = foundry(request)
        if json.loads(request.content).get("previous_response_id") == "resp_01":
            data = {k: v for k, v in resp.json().items() if k != "usage"}      # no usage reported
            return httpx.Response(200, json=data)
        return resp
    client, s, _ = gov_node(tmp_path, pack=PRICED, handler=handler, policy=FOUNDRY_POLICY)
    with client:
        assert portal(client).status_code == 200
        state["fail"] = True
        assert portal(client, "again").status_code == 502
    first, second, failed = (json.loads(r["ext"]) for r in rows(s.db_path, "type = 'inference'"))
    assert (first["price_rule"], first["cost_micro"], first["usage"]) == ("foundry-gpt", 980, {"input_tokens": 900, "output_tokens": 40})
    assert (second["price_rule"], second["cost_micro"], "usage" in second) == ("foundry-gpt", 777, False)
    assert "cost_micro" not in failed            # the answering model is unknown: not priced
    for flags in ((), ("--rulepack", str(tmp_path / "starter.yaml"))):
        code, line = verify(s.db_path, s.pubkey_path, *flags)
        assert code == 0, line


def test_a_failed_upstream_is_priced_under_the_agent_name_and_the_chain_verifies(tmp_path, monkeypatch):
    """§17.4.3: model_digest is api:azure-foundry:<model_id>, and model_id falls back to the agent name, so an
    upstream_error priced for that digest carries it too."""
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    pack = PACK + """pricing:
  - {id: foundry-any, model: "api:azure-foundry:*", input_per_mtok_micro: 1, output_per_mtok_micro: 1,
     missing_usage_cost_micro: 555}
"""
    client, s, _ = gov_node(tmp_path, pack=pack, handler=lambda r: httpx.Response(500, json={"error": "down"}),
                            policy=FOUNDRY_POLICY)
    with client:
        assert portal(client).status_code == 502
    failed = rows(s.db_path, "type = 'inference'")[-1]
    assert (failed["model_id"], failed["model_digest"]) == ("case-agent", "api:azure-foundry:case-agent")
    assert (json.loads(failed["ext"])["price_rule"], json.loads(failed["ext"])["cost_micro"]) == ("foundry-any", 555)
    for flags in ((), ("--rulepack", str(tmp_path / "starter.yaml"))):
        code, line = verify(s.db_path, s.pubkey_path, *flags)
        assert code == 0, line


def test_a_refused_approval_at_the_gate_is_denied_and_the_chain_verifies(relay):
    client, s, foundry = relay
    out = []
    worker = threading.Thread(target=lambda: out.append(portal(client, "close the case")))
    worker.start()
    for _ in range(250):
        if rows(s.db_path, "type = 'approval'"):
            break
        time.sleep(0.02)
    aid = json.loads(rows(s.db_path, "type = 'approval'")[0]["ext"])["approval_id"]
    client.post(f"/api/approval/{aid}/decide", json={"decision": "refuse", "token": supervisor()})
    worker.join(10)
    assert foundry.seen[1][1]["input"][0]["approve"] is False
    call = rows(s.db_path, "type = 'tool_call'")[0]
    x = json.loads(call["ext"])
    assert (call["decision"], x["confirmation"], "approval_seq" in x) == ("block", "denied", True)
    for flags in ((), ("--rulepack", str(s.rulepack_path))):
        code, line = verify(s.db_path, s.pubkey_path, *flags)
        assert code == 0, line


@pytest.mark.parametrize("extra", [
    {"tools": [{"type": "mcp", "server_label": "x", "require_approval": "never"}]},
    {"agent": {"name": "other-agent", "type": "agent_reference"}},
    {"model": "gpt-5"},
    {"input": [{"type": "mcp_approval_response", "approve": True, "approval_request_id": "mcpr_02"}]},
    {"input": {"type": "mcp_approval_response", "approve": True, "approval_request_id": "mcpr_02"}},
    {"input": [{"type": "MCP_Approval_Response", "approve": True, "approval_request_id": "mcpr_02"}]},
    {"input": [{"type": " mcp_approval_response", "approve": True, "approval_request_id": "mcpr_02"}]},
    {"input": [{"type": "Message", "role": "user", "content": "hi"}]},
    {"input": [{"role": "user", "content": "hi"}]},
    {"input": [[{"type": "message", "role": "user", "content": "hi"}]]},
    {"input": [{"type": "unknown_item"}]},
    {"input": 5}, {"input": None}, {"input": [5]}, {"input": [None]},
    {"previous_response_id": "resp_01", "input": [{"type": "mcp_approval_response", "approve": True,
                                                   "approval_request_id": "mcpr_02"}]}])
def test_the_client_cannot_add_tools_pick_an_agent_or_answer_approvals(relay, extra):
    client, s, foundry = relay
    body = {"agent": {"name": "case-agent", "type": "agent_reference"}, "conversation": "conv_abc", "input": "hi", **extra}
    r = client.post("/v1/responses", headers={"X-Sijill-Principal-Token": officer()}, json=body)
    assert r.status_code == 400 and foundry.seen == []
    assert rows(s.db_path, "type = 'task_start'") == []


def test_the_round_limit_denies_what_is_pending_and_never_relays_it(tmp_path, monkeypatch):
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    calls = []

    def endless(request):
        calls.append(1)
        return httpx.Response(200, json={"id": f"resp_{len(calls)}", "object": "response", "model": "gpt-4.1-2025-04-14",
                                         "status": "completed", "output": [
                                             {"type": "mcp_approval_request", "id": f"mcpr_{len(calls)}",
                                              "server_label": "case-mcp", "name": "get_case", "arguments": CASE_ARGS}]})
    client, s, _ = gov_node(tmp_path, pack=PACK, handler=endless, policy=FOUNDRY_POLICY)
    with client:
        r = portal(client)
    assert r.status_code == 502 and r.json()["error"]["type"] == "round_limit" and "mcpr_8" not in r.text
    assert len(calls) == 8
    last = rows(s.db_path, "type = 'tool_call'")[-1]
    assert (json.loads(last["ext"])["foundry_item_id"], last["decision"]) == ("mcpr_8", "block")
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_an_unrecognised_item_is_denied_sealed_block_and_never_relayed(tmp_path, monkeypatch):
    """Fail closed: an item type the relay does not know may be a renamed approval request waiting for an answer,
    so the turn is sealed block with foundry-item-unknown and nothing reaches the portal."""
    from sijill import policy
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    reply = {"id": "resp_u", "object": "response", "model": "gpt-4.1-2025-04-14", "status": "completed",
             "output": [{"type": "reasoning", "id": "rs_01", "summary": []},
                        {"type": "mcp_approval_request_v2", "id": "mcpr_x", "server_label": "case-mcp",
                         "name": "delete_case", "arguments": CASE_ARGS},
                        {"type": "message", "id": "msg_u", "role": "assistant",
                         "content": [{"type": "output_text", "text": "Waiting for approval."}]}]}
    client, s, _ = gov_node(tmp_path, pack=PACK, handler=lambda r: httpx.Response(200, json=reply), policy=FOUNDRY_POLICY)
    with client:
        r = portal(client)
    assert r.status_code == 403 and r.json()["error"]["type"] == "policy_block" and "mcpr_x" not in r.text
    rec = rows(s.db_path, "type = 'inference'")[-1]
    assert (rec["decision"], rec["mode"], rec["output_hash"]) == ("block", "enforce", "")
    assert "foundry-item-unknown" in json.loads(rec["rule_hits"])
    assert "foundry-item-unknown" in policy.RESERVED_IDS
    for flags in ((), ("--rulepack", str(s.rulepack_path))):
        code, line = verify(s.db_path, s.pubkey_path, *flags)
        assert code == 0, line


COMPUTER = {"type": "computer_call", "id": "cu_01", "call_id": "call_cu", "status": "completed",
            "action": {"type": "click", "x": 10, "y": 20}, "pending_safety_checks": []}
UNKNOWN = {"type": "mcp_approval_request_v2", "id": "mcpr_x", "server_label": "case-mcp", "name": "delete_case",
           "arguments": CASE_ARGS}
FUNCTION = {"type": "function_call", "id": "fc_01", "call_id": "call_fc", "name": "lookup", "arguments": "{}"}
ASK = {"type": "mcp_approval_request", "id": "mcpr_r1", "server_label": "case-mcp", "name": "get_case",
       "arguments": CASE_ARGS}


@pytest.mark.parametrize("rounds,leak", [
    ([[COMPUTER]], "cu_01"),                               # a client-executed call: the portal would run it
    ([[{**COMPUTER, "type": "local_shell_call"}]], "cu_01"),
    ([[FUNCTION, UNKNOWN]], "mcpr_x"),                     # next to a function_call the portal would answer
    ([[ASK], [UNKNOWN]], "mcpr_x"),                        # in a later round trip
    ([[ASK], [COMPUTER]], "cu_01"),
    ([["not an item", FUNCTION]], "call_fc"),              # a non-object entry
])
def test_unrecognised_and_client_executed_items_fail_closed(tmp_path, monkeypatch, rounds, leak):
    """§12 item 42: a pending item the relay cannot answer, or one the client would execute, is never relayed and
    never sealed as a call Foundry ran: the round trip is sealed block with foundry-item-unknown."""
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json={"id": f"resp_{len(calls)}", "object": "response", "model": "gpt-4.1-2025-04-14",
                                         "status": "completed", "output": rounds[len(calls) - 1]})
    client, s, _ = gov_node(tmp_path, pack=PACK, handler=handler, policy=FOUNDRY_POLICY)
    with client:
        r = portal(client)
    assert r.status_code == 403 and r.json()["error"]["type"] == "policy_block" and leak not in r.text
    assert len(calls) == len(rounds)
    rec = rows(s.db_path, "type = 'inference'")[-1]
    assert (rec["decision"], rec["mode"], rec["output_hash"]) == ("block", "enforce", "")
    assert "foundry-item-unknown" in json.loads(rec["rule_hits"])
    assert not any(json.loads(c["ext"]).get("after_the_fact") for c in rows(s.db_path, "type = 'tool_call'"))
    for flags in ((), ("--rulepack", str(s.rulepack_path))):
        code, line = verify(s.db_path, s.pubkey_path, *flags)
        assert code == 0, line


def test_informational_items_still_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    reply = {"id": "resp_i", "object": "response", "model": "gpt-4.1-2025-04-14", "status": "completed",
             "output": [{"type": "mcp_list_tools", "id": "mcpl_01", "server_label": "case-mcp", "tools": []},
                        {"type": "reasoning", "id": "rs_01", "summary": []},
                        {"type": "message", "id": "msg_i", "role": "assistant",
                         "content": [{"type": "output_text", "text": "Hello."}]}]}
    client, s, _ = gov_node(tmp_path, pack=PACK, handler=lambda r: httpx.Response(200, json=reply), policy=FOUNDRY_POLICY)
    with client:
        r = portal(client)
    assert r.status_code == 200 and r.json() == reply
    assert rows(s.db_path, "type = 'inference'")[-1]["decision"] == "allow"


UNHASHABLE = [                             # (output items, answer text) Foundry may send back
    ([{"type": "mcp_approval_request", "id": "mcpr_s", "server_label": "case-mcp", "name": "get_case",
       "arguments": '{"caseId": "\\ud800"}'}], ""),                       # gated arguments escaping a lone surrogate
    ([{"type": "mcp_approval_request", "id": "mcpr_s", "server_label": "case-mcp", "name": "get_case",
       "arguments": '{"caseId": NaN}'}], ""),                              # or carrying NaN
    ([{"type": "function_call", "call_id": "call_s", "name": "lookup", "arguments": "{bad \udc00"}], ""),
    ([], "lone \udfff"),                                                    # the answer text
]
SPEND = """pricing:
  - {id: foundry-any, model: "api:azure-foundry:*", input_per_mtok_micro: 1000000000, output_per_mtok_micro: 0,
     missing_usage_cost_micro: 555}
budgets:
  - id: relay
    match: {harness: [foundry]}
    limits: {model_spend_micro: 1500000}
    currency: AED
    on_exceed: block
"""


@pytest.mark.parametrize("items,text", UNHASHABLE)
def test_an_unhashable_answer_is_sealed_priced_and_counts_toward_the_budget(tmp_path, monkeypatch, items, text):
    """§2.2: the ledger cannot hash NaN or a lone surrogate, but Foundry answered and billed: the round trip is sealed
    as a priced upstream_error with the raw bytes hashed, nothing is gated, and the spend counts (§17.6.2)."""
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    seen = []
    message = [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]}]
    reply = json.dumps({"id": "resp_s", "object": "response", "model": "gpt-4.1-2025-04-14", "status": "completed",
                        "usage": {"input_tokens": 1000, "output_tokens": 7}, "output": items + message}).encode()

    def handler(r):
        seen.append(r)
        return httpx.Response(200, content=reply, headers={"content-type": "application/json"})
    client, s, _ = gov_node(tmp_path, pack=PACK + SPEND, handler=handler, policy=FOUNDRY_POLICY)
    with client:
        for _ in range(2):
            r = portal(client)
            assert r.status_code == 502 and r.json()["error"]["type"] == "upstream_error" and "mcpr_s" not in r.text
        r = portal(client)
        assert r.status_code == 403 and r.json()["sijill"]["rule_hits"] == ["budget:relay:model_spend_micro"]
    assert len(seen) == 2 and rows(s.db_path, "type = 'tool_call'") == []
    first, second, third = rows(s.db_path, "type = 'inference'")
    for rec in (first, second):
        x = json.loads(rec["ext"])
        assert (rec["model_digest"], rec["output_hash"], json.loads(rec["rule_hits"])) == \
            ("api:azure-foundry:case-agent", "", ["upstream_error"])
        assert (x["usage"], x["cost_micro"], x["response_hash"]) == \
            ({"input_tokens": 1000, "output_tokens": 7}, 1000000, record.sha256_hex(reply))
    assert third["decision"] == "block"
    for flags in ((), ("--rulepack", str(tmp_path / "starter.yaml"))):
        code, line = verify(s.db_path, s.pubkey_path, *flags)
        assert code == 0, line


def test_a_lone_surrogate_in_the_conversation_id_is_400(relay):
    client, s, foundry = relay
    r = client.post("/v1/responses", headers={"X-Sijil-Principal-Token": officer(), "Content-Type": "application/json"},
                    content=json.dumps({"conversation": "conv_\ud800", "input": "hello"}))
    assert r.status_code == 400 and foundry.seen == []


@pytest.mark.parametrize("given", ['"hello \\ud800"', '[{"type": "message", "role": "user", "content": NaN}]'])
@pytest.mark.parametrize("token", [officer, lambda: "not-a-token"])
def test_input_no_record_can_hash_is_400_before_any_task_or_refusal(relay, given, token):
    """§2.2: input is hashed once, right after the shape check: no session, no task_start, no principal refusal."""
    client, s, foundry = relay
    r = client.post("/v1/responses", headers={"X-Sijil-Principal-Token": token(), "Content-Type": "application/json"},
                    content='{"conversation": "conv_nan", "input": %s}' % given)
    assert r.status_code == 400 and "not canonical" in r.json()["detail"] and foundry.seen == []
    assert rows(s.db_path, "type IN ('task_start', 'inference')") == []
    assert client.app.state.node.store.session("fr_" + record.sha256_hex(b"conv_nan")[:32]) is None


def test_a_function_call_is_correlated_by_its_call_id(tmp_path, monkeypatch):
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    reply = {"id": "resp_f", "object": "response", "model": "gpt-4.1-2025-04-14", "status": "completed",
             "output": [{"type": "function_call", "id": "fc_item", "call_id": "call_xyz", "name": "lookup",
                         "arguments": "{}"}]}
    client, s, _ = gov_node(tmp_path, pack=PACK, handler=lambda r: httpx.Response(200, json=reply), policy=FOUNDRY_POLICY)
    with client:
        assert portal(client).status_code == 200
    assert [u["id"] for u in json.loads(rows(s.db_path, "type = 'inference'")[0]["ext"])["tool_uses"]] == ["call_xyz"]


def test_a_foreign_approved_call_is_recorded_after_the_fact_and_listed(tmp_path, monkeypatch):
    """A client previous_response_id can bring an mcp_call whose approval was never gated here."""
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    reply = {"id": "resp_g", "object": "response", "model": "gpt-4.1-2025-04-14", "status": "completed",
             "output": [{"type": "mcp_call", "id": "mcp_x", "approval_request_id": "mcpr_foreign", "server_label": "case-mcp",
                         "name": "get_case", "arguments": CASE_ARGS, "output": "ok"}]}
    client, s, _ = gov_node(tmp_path, pack=PACK, handler=lambda r: httpx.Response(200, json=reply), policy=FOUNDRY_POLICY)
    with client:
        r = portal(client, "hi")
        assert r.status_code == 200, r.text
    call = rows(s.db_path, "type = 'tool_call'")[0]
    assert json.loads(call["ext"])["after_the_fact"] is True
    for flags in ((), ("--rulepack", str(s.rulepack_path))):
        code, line = verify(s.db_path, s.pubkey_path, *flags)
        assert code == 0, line


def test_an_upstream_auth_failure_is_a_502_not_the_users_status(tmp_path, monkeypatch):
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "expired")
    client, s, _ = gov_node(tmp_path, pack=PACK, handler=lambda r: httpx.Response(401, json={}), policy=FOUNDRY_POLICY)
    with client:
        assert portal(client).status_code == 502


def test_concurrent_first_requests_make_one_session_and_one_task(relay, monkeypatch):
    from sijill import proxy
    client, s, foundry = relay
    human = proxy.Node.human

    async def slow(self, *a, **k):               # both requests are past the session check before either writes
        await asyncio.sleep(0.2)
        return await human(self, *a, **k)
    monkeypatch.setattr(proxy.Node, "human", slow)
    out = []
    workers = [threading.Thread(target=lambda: out.append(portal(client, "hello"))) for _ in range(6)]
    [w.start() for w in workers]
    [w.join(20) for w in workers]
    assert sorted(r.status_code for r in out) == [200] * 6
    assert len(rows(s.db_path, "type = 'task_start'")) == 1
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_a_list_of_supported_items_is_forwarded(relay):
    client, s, foundry = relay
    given = [{"type": "message", "role": "user", "content": "hi"}]
    assert portal(client, given).status_code == 200
    assert foundry.seen[0][1]["input"] == given


def test_the_relay_verdict_blocks_a_command_over_the_cap_unparsed(tmp_path):
    from types import SimpleNamespace

    from conftest import ROOT
    from guard import rules
    from sijill import foundry
    path = str(ROOT / "rulepacks" / "starter.yaml")
    n = SimpleNamespace(rulepack=SimpleNamespace(path=path, hash=rules.load(path).hash),
                        store=SimpleNamespace(in_task=lambda seq: []))
    over = foundry.verdict(n, {"seq": 1}, "mcp:shell:run_command", {"command": "ls " + "a" * rules.MAX_COMMAND}, 9)
    assert (over.hits, over.action) == (["command-too-long"], "block")
    assert foundry.verdict(n, {"seq": 1}, "mcp:shell:run_command", {"command": "ls"}, 9).action == "allow"


def test_the_gate_stops_waiting_when_no_decision_comes(tmp_path, monkeypatch):
    from sijill import approvals, foundry as relay_module
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    monkeypatch.setattr(approvals, "schedule", lambda n, p: None)       # the timer has died
    monkeypatch.setattr(relay_module, "GRACE_S", 0.2)
    foundry = Foundry()
    client, s, _ = gov_node(tmp_path, pack=PACK.replace("min_assurance: high", "min_assurance: high\n      timeout_seconds: 1"),
                            handler=foundry, policy=FOUNDRY_POLICY)
    with client:
        started = time.monotonic()
        r = portal(client, "close the case")
        assert r.status_code == 200 and time.monotonic() - started < 10      # deadline + grace, not forever
    assert foundry.seen[1][1]["input"][0]["approve"] is False
    call = rows(s.db_path, "type = 'tool_call'")[0]
    x = json.loads(call["ext"])
    assert (call["decision"], x["confirmation"], "approval_seq" in x) == ("block", "unavailable", False)
    for flags in ((), ("--rulepack", str(s.rulepack_path))):
        assert verify(s.db_path, s.pubkey_path, *flags)[0] == 0


def test_the_relay_verdict_blocks_64_kb_of_letters_before_any_scan(tmp_path):
    from types import SimpleNamespace

    from conftest import ROOT
    from guard import rules
    from sijill import foundry
    path = str(ROOT / "rulepacks" / "starter.yaml")
    n = SimpleNamespace(rulepack=SimpleNamespace(path=path, hash=rules.load(path).hash),
                        store=SimpleNamespace(in_task=lambda seq: []))
    foundry.verdict(n, {"seq": 1}, "mcp:srv:any_tool", {}, 9)           # loads the pack outside the timing
    for tool, key in (("mcp:shell:run_command", "command"), ("mcp:srv:any_tool", "note")):
        start = time.perf_counter()
        v = foundry.verdict(n, {"seq": 1}, tool, {key: "a" * 65536}, 9)
        assert time.perf_counter() - start < 0.05 and (v.hits, v.action) == (["command-too-long"], "block")


def test_a_confirm_rule_call_foundry_ran_unasked_is_flagged_and_verifies_with_the_rulepack(tmp_path, monkeypatch):
    monkeypatch.setenv("SIJIL_TEST_FOUNDRY_TOKEN", "ledger-entra-token")
    reply = {"id": "resp_g", "object": "response", "model": "gpt-4.1-2025-04-14", "status": "completed",
             "output": [{"type": "mcp_call", "id": "mcp_x", "approval_request_id": "mcpr_foreign", "server_label": "case-mcp",
                         "name": "close_case", "arguments": CASE_ARGS, "output": "closed"}]}
    client, s, _ = gov_node(tmp_path, pack=PACK, handler=lambda r: httpx.Response(200, json=reply), policy=FOUNDRY_POLICY)
    with client:
        assert portal(client, "hi").status_code == 200
    call = rows(s.db_path, "type = 'tool_call'")[0]
    x = json.loads(call["ext"])
    assert (call["decision"], json.loads(call["rule_hits"]), x["after_the_fact"], x["observed_by"]) == \
        ("flag", ["case-closure-needs-approval"], True, "foundry_relay")
    for flags in ((), ("--rulepack", str(s.rulepack_path))):
        code, line = verify(s.db_path, s.pubkey_path, *flags)
        assert code == 0, line
