"""Row 3g and spec §3 on /v1/chat/completions: tool_uses (§17.1.1), tool_use_index, attestation: api."""

import json

import httpx
import pytest

from conftest import MODEL, make_node, rows, sqlite, verify
from sijill import record

NOTE = {"caseId": "MOI-2026-004211", "note": "Applicant uploaded the missing salary certificate."}
NOTE_HASH = record.sha256_hex(record.canonical_json(NOTE))
DATED = "gpt-4.1-2025-04-14"
API_POLICY = """policy_id: gov-assistant
approval_ref: "APR-0147"
attestation: api
node: {id: auh-node-01, region: AE-AZ}
rules:
  - {id: residency, type: region_allowlist, allow: [AE-AZ], mode: enforce}
  - {id: approved_models, type: model_allowlist, allow_digests: ["api:azure-openai:gpt-4.1-2025-04-14"], mode: enforce}
  - {id: sensitive_terms, type: keyword_flag, terms: [passport number], mode: enforce}
"""
API = dict(upstream_provider="azure-openai")


def answer(model: str = DATED, tool_calls=None, content=None):
    def handler(request: httpx.Request) -> httpx.Response:
        message = {"role": "assistant", "content": content}
        if tool_calls is not None:
            message["tool_calls"] = tool_calls
        return httpx.Response(200, headers={"x-request-id": "req-7Qm"}, json={
            "id": "chatcmpl-1", "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "finish_reason": "tool_calls" if tool_calls else "stop", "message": message}]})
    return handler


CALLS = [{"id": "call_N1aB", "type": "function", "function": {"name": "addCaseNote", "arguments": json.dumps(NOTE)}},
         {"id": "call_C6kL", "type": "function", "function": {"name": "closeCase", "arguments": "{not json"}}]


def chunk(model=DATED, finish=None, **delta) -> str:
    return "data: " + json.dumps({"model": model, "choices": [{"index": 0, "delta": delta,
                                                               "finish_reason": finish}]}) + "\n\n"


def streamed(*chunks: str, done: bool = True):
    def handler(request):
        return httpx.Response(200, content=("".join(chunks) + ("data: [DONE]\n\n" if done else "")).encode(),
                              headers={"content-type": "text/event-stream"})
    return handler


def ask(client, model=MODEL, stream=False, content="Add a note to the case"):
    return client.post("/v1/chat/completions", json={
        "model": model, "stream": stream, "messages": [{"role": "user", "content": content}]})


def ext(rec) -> dict:
    return json.loads(rec["ext"]) if rec["ext"] else {}


def test_tool_calls_become_tool_uses_and_are_indexed(tmp_path):
    client, s = make_node(tmp_path, answer(tool_calls=CALLS))
    with client:
        assert ask(client).status_code == 200
    [rec] = rows(s.db_path)
    x = ext(rec)
    assert x == {"api": "openai_chat", "stop_reason": "tool_calls", "tool_uses": [
        {"id": "call_N1aB", "name": "addCaseNote", "args_hash": NOTE_HASH},
        {"id": "call_C6kL", "name": "closeCase", "args_hash": record.sha256_hex(b"{not json"), "args_raw": True}]}
    assert rec["model_digest"].startswith("sha256:")          # weights mode: the M1 digest, unchanged
    assert sqlite(s.db_path, "SELECT tool_use_id, seq, name FROM tool_use_index ORDER BY tool_use_id") == \
        "call_C6kL|1|closeCase\ncall_N1aB|1|addCaseNote"
    assert verify(s.db_path, s.pubkey_path)[1].startswith("PASS records=1 ")


def test_weights_mode_plain_answer_keeps_m1_shape(tmp_path):
    client, s = make_node(tmp_path, answer(content="Opening hours are 7:30 to 14:30."))
    with client:
        assert ask(client).status_code == 200
    [rec] = rows(s.db_path)
    assert rec["ext"] == "" and rec["output_hash"] == record.output_hash("Opening hours are 7:30 to 14:30.")


def test_streamed_fragments_are_joined_per_index(tmp_path):
    args = json.dumps(NOTE)
    client, s = make_node(tmp_path, streamed(
        chunk(role="assistant", content=None),
        chunk(tool_calls=[{"index": 0, "id": "call_N1aB", "type": "function",
                           "function": {"name": "addCaseNote", "arguments": args[:10]}}]),
        chunk(tool_calls=[{"index": 1, "id": "call_X9", "type": "function",
                           "function": {"name": "lookupCase", "arguments": ""}}]),
        chunk(tool_calls=[{"index": 0, "function": {"arguments": args[10:]}}]),
        chunk(tool_calls=[{"index": 1, "function": {"arguments": '{"caseId": "MOI-1"}'}}]),
        chunk(finish="tool_calls")))
    with client, client.stream("POST", "/v1/chat/completions", json={
            "model": MODEL, "stream": True, "messages": [{"role": "user", "content": "go"}]}) as r:
        assert r.status_code == 200 and [l for l in r.iter_lines() if l][-1] == "data: [DONE]"
    [rec] = rows(s.db_path)
    assert ext(rec)["tool_uses"] == [
        {"id": "call_N1aB", "name": "addCaseNote", "args_hash": NOTE_HASH},
        {"id": "call_X9", "name": "lookupCase", "args_hash": record.sha256_hex(record.canonical_json({"caseId": "MOI-1"}))}]
    assert ext(rec)["stop_reason"] == "tool_calls"
    assert sqlite(s.db_path, "SELECT count(*) FROM tool_use_index") == "2"
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_api_mode_digest_names_the_model_that_answered(tmp_path):
    handler = answer(tool_calls=CALLS[:1])
    client, s = make_node(tmp_path, handler, API_POLICY, **API)
    with client:
        r = ask(client, model="gpt-4.1")                      # an alias; the provider answers with the snapshot
        assert r.status_code == 200
    [rec] = rows(s.db_path)
    assert rec["model_id"] == "gpt-4.1" and rec["model_digest"] == "api:azure-openai:gpt-4.1-2025-04-14"
    x = ext(rec)
    request = {"model": "gpt-4.1", "stream": False, "messages": [{"role": "user", "content": "Add a note to the case"}]}
    assert x == {"api": "openai_chat", "attestation": "api",
                 "request_hash": record.sha256_hex(record.canonical_json(request)), "system_hash": "",
                 "response_hash": record.sha256_hex(handler(None).content), "provider_request_id": "req-7Qm",
                 "stop_reason": "tool_calls", "tool_uses": [{"id": "call_N1aB", "name": "addCaseNote",
                                                             "args_hash": NOTE_HASH}], "session_id": ""}
    code, line = verify(s.db_path, s.pubkey_path)
    assert code == 0 and "attestation=weights:0,api:1,api+tee:0,none:0" in line


def test_api_mode_unapproved_answering_model_is_withheld(tmp_path):
    client, s = make_node(tmp_path, answer(model="gpt-4.1-2025-09-30", content="secret answer"), API_POLICY, **API)
    with client:
        r = ask(client, model="gpt-4.1")
    assert r.status_code == 403 and r.json()["sijill"]["rule_hits"] == ["approved_models"]
    assert "secret answer" not in r.text
    [rec] = rows(s.db_path)
    assert (rec["decision"], rec["mode"], rec["output_hash"]) == ("block", "enforce", "")
    assert rec["model_digest"] == "api:azure-openai:gpt-4.1-2025-09-30"
    assert sqlite(s.db_path, "SELECT count(*) FROM tool_use_index") == "0"
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_api_mode_preflight_block_names_the_requested_model(tmp_path):
    client, s = make_node(tmp_path, answer(content="never"), API_POLICY, **API)
    with client:
        r = ask(client, model="gpt-4.1", content="my passport number is X")
    assert r.status_code == 403
    [rec] = rows(s.db_path)
    assert rec["model_digest"] == "api:azure-openai:gpt-4.1" and rec["decision"] == "block"
    assert ext(rec)["tool_uses"] == [] and ext(rec)["response_hash"] == ""
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_api_mode_answer_without_model_is_upstream_error(tmp_path):
    def no_model(request):
        return httpx.Response(200, json={"choices": [{"index": 0, "message": {"role": "assistant", "content": "x"}}]})
    client, s = make_node(tmp_path, no_model, API_POLICY, **API)
    with client:
        assert ask(client, model="gpt-4.1").status_code == 502
    assert json.loads(rows(s.db_path)[0]["rule_hits"]) == ["upstream_error"]


def test_api_mode_stream_refuses_before_relaying_an_unapproved_model(tmp_path):
    client, s = make_node(tmp_path, streamed(chunk(model="gpt-5", content="hidden")), API_POLICY, **API)
    with client, client.stream("POST", "/v1/chat/completions", json={
            "model": "gpt-4.1", "stream": True, "messages": [{"role": "user", "content": "hi"}]}) as r:
        body = "".join(r.iter_text())
    assert "hidden" not in body and "decision=block" in body
    [rec] = rows(s.db_path)
    assert rec["model_digest"] == "api:azure-openai:gpt-5"
    assert (rec["decision"], rec["output_hash"]) == ("block", "")
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_api_mode_stream_seals_response_model_and_hash(tmp_path):
    chunks = (chunk(role="assistant", content="Hello"), chunk(content=" there", finish="stop"))
    client, s = make_node(tmp_path, streamed(*chunks), API_POLICY, **API)
    with client, client.stream("POST", "/v1/chat/completions", json={
            "model": "gpt-4.1", "stream": True, "messages": [{"role": "user", "content": "hi"}]}) as r:
        assert [l for l in r.iter_lines() if l][-1] == "data: [DONE]"
    [rec] = rows(s.db_path)
    relayed = "".join(chunks)       # aiter_lines() strips endings; each line is hashed and relayed + "\n"
    assert rec["model_digest"] == "api:azure-openai:" + DATED and rec["output_hash"] == record.output_hash("Hello there")
    assert ext(rec)["response_hash"] == record.sha256_hex(relayed.encode()) and ext(rec)["stop_reason"] == "stop"


def test_api_mode_needs_the_route_provider(tmp_path):
    client, _ = make_node(tmp_path, answer(), API_POLICY)
    with pytest.raises(ValueError, match="SIJILL_UPSTREAM_PROVIDER"):
        with client:
            pass


def test_switching_to_api_mode_is_a_sealed_policy_change(tmp_path):
    client, s = make_node(tmp_path, answer(content="ok"), **API)
    with client:
        assert ask(client).status_code == 200
        (tmp_path / "policy.yaml").write_text(API_POLICY)
        assert client.post("/api/admin/policy/reload").json()["seq"] == 2
        assert ask(client, model="gpt-4.1").status_code == 200
    assert [r["type"] for r in rows(s.db_path)] == ["inference", "policy_change", "inference"]
    assert "attestation=weights:1,api:1," in verify(s.db_path, s.pubkey_path)[1]


LEAD = ('data: {"id": "", "model": "", "choices": [], "prompt_filter_results": '
        '[{"prompt_index": 0, "content_filter_results": {}}]}\n\n')


def test_api_mode_stream_leading_empty_model_chunk_does_not_latch(tmp_path):
    chunks = (LEAD, chunk(role="assistant", content="Hello"), chunk(content=" there", finish="stop"))
    client, s = make_node(tmp_path, streamed(*chunks), API_POLICY, **API)
    with client, client.stream("POST", "/v1/chat/completions", json={
            "model": "gpt-4.1", "stream": True, "messages": [{"role": "user", "content": "hi"}]}) as r:
        assert [l for l in r.iter_lines() if l][-1] == "data: [DONE]"
    [rec] = rows(s.db_path)
    assert rec["model_digest"] == "api:azure-openai:" + DATED and rec["decision"] == "allow"
    assert rec["output_hash"] == record.output_hash("Hello there")
    assert ext(rec)["response_hash"] == record.sha256_hex("".join(chunks).encode())
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_api_mode_stream_leading_empty_model_chunk_then_unapproved_model_is_refused(tmp_path):
    client, s = make_node(tmp_path, streamed(LEAD, chunk(model="gpt-5", content="hidden")), API_POLICY, **API)
    with client, client.stream("POST", "/v1/chat/completions", json={
            "model": "gpt-4.1", "stream": True, "messages": [{"role": "user", "content": "hi"}]}) as r:
        body = "".join(r.iter_text())
    assert "hidden" not in body and "decision=block" in body
    [rec] = rows(s.db_path)
    assert rec["model_digest"] == "api:azure-openai:gpt-5" and (rec["decision"], rec["output_hash"]) == ("block", "")
    assert verify(s.db_path, s.pubkey_path)[0] == 0


@pytest.mark.parametrize("arguments,content,model", [
    ('{"note": "\\ud800"}', None, DATED),          # JSON arguments whose string escapes a lone surrogate
    ("{not json \ud800", None, DATED),              # raw arguments carrying one
    ("{}", "lone \udfff", DATED),                   # the answer text carrying one
    ("{}", None, "gpt-4.1\ud800"),                  # the model the provider says answered
])
def test_a_lone_surrogate_from_the_model_is_sealed_as_an_upstream_error(tmp_path, arguments, content, model):
    """§2.2: a record never contains a lone surrogate. The call was forwarded and billed, so it is sealed as an
    upstream_error under the requested model, with the raw answer bytes hashed, and the client gets a 502."""
    calls = [{"id": "call_S", "type": "function", "function": {"name": "addCaseNote", "arguments": arguments}}]
    body = json.dumps({"id": "chatcmpl-1", "object": "chat.completion", "model": model, "choices": [{          # \uXXXX
        "index": 0, "finish_reason": "tool_calls", "message": {"role": "assistant", "content": content, "tool_calls": calls}}]})
    client, s = make_node(tmp_path, lambda request: httpx.Response(200, content=body,
                                                                    headers={"content-type": "application/json"}),
                          API_POLICY, **API)
    with client:
        r = ask(client, model=DATED)
    assert r.status_code == 502 and "call_S" not in r.text
    [rec] = rows(s.db_path)
    x = ext(rec)
    assert (rec["model_digest"], rec["output_hash"], json.loads(rec["rule_hits"])) == \
        ("api:azure-openai:" + DATED, "", ["upstream_error"] if model == DATED else ["approved_models", "upstream_error"])
    assert (x["response_hash"], x["tool_uses"]) == (record.sha256_hex(body.encode()), [])
    assert sqlite(s.db_path, "SELECT count(*) FROM tool_use_index") == "0"
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def raw_answer(model: str, content: str):
    """answer(), but the body escapes lone surrogates as JSON does on the wire."""
    def handler(request):
        return httpx.Response(200, headers={"content-type": "application/json"}, content=json.dumps({
            "id": "chatcmpl-1", "model": model, "choices": [{"index": 0, "finish_reason": "stop",
                                                             "message": {"role": "assistant", "content": content}}]}).encode())
    return handler


@pytest.mark.parametrize("handler,stream", [
    (raw_answer("gpt-4.1-2025-09-30", "lone \udfff"), False),   # unapproved, and the answer cannot be hashed
    (streamed(chunk(model="gpt-5\ud800", content="hidden")), True),
], ids=["content", "streamed-model"])
def test_api_mode_an_unhashable_answer_from_an_unapproved_model_keeps_the_block(tmp_path, handler, stream):
    """The allowlist decided block before the answer proved unhashable: the record keeps that evidence."""
    client, s = make_node(tmp_path, handler, API_POLICY, **API)
    with client:
        r = client.post("/v1/chat/completions", json={"model": "gpt-4.1", "messages": [{"role": "user", "content": "hi"}],
                                                      "stream": stream})
    [rec] = rows(s.db_path)
    assert (rec["decision"], rec["mode"], json.loads(rec["rule_hits"])) == \
        ("block", "enforce", ["approved_models", "upstream_error"])
    assert rec["model_digest"] == "api:azure-openai:gpt-4.1" and rec["output_hash"] == ""
    assert verify(s.db_path, s.pubkey_path)[0] == 0
