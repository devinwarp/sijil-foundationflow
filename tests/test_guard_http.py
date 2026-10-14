"""Row 8b: the HTTP tool adapter in front of a REST case API, sealing through a real ledger (spec §17.3)."""

import asyncio
import dataclasses
import json

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from agentkit import chat
from conftest import ADMIN, rows, verify
from guard import config, http, identity, serve, task
from guardkit import guard_yaml, ledger_node, ledger_of
from sijill import record

NOTE = {"caseId": "MOI-2026-004211", "note": "Applicant uploaded the missing salary certificate."}
CALLS = {"note": ("addCaseNote", NOTE), "close": ("closeCase", {"caseId": "MOI-2026-004211"}),
         "export": ("exportCases", {}), "delete": ("DELETE /cases/{caseId}", {"caseId": "MOI-2026-004211"}),
         "list": ("listCases", {"limit": 10, "open": True}), "get": ("getCase", {"caseId": "MOI-2026-004211"})}
SPEC = {"openapi": "3.1.0", "info": {"title": "case-api", "version": "2"}, "paths": {
    "/cases": {"get": {"operationId": "listCases", "parameters": [
        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
        {"name": "open", "in": "query", "schema": {"type": "boolean"}}]}},
    "/cases/{caseId}": {"parameters": [{"$ref": "#/components/parameters/caseId"}],
                        "get": {"operationId": "getCase"}, "delete": {}},
    "/cases/{caseId}/notes": {"post": {"operationId": "addCaseNote", "parameters": [{"$ref": "#/components/parameters/caseId"}],
                                       "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}}},
    "/cases/{caseId}/close": {"post": {"operationId": "closeCase", "parameters": [{"$ref": "#/components/parameters/caseId"}]}}},
    "components": {"parameters": {"caseId": {"name": "caseId", "in": "path", "required": True, "schema": {"type": "string"}}}}}
SAVED = json.dumps({"noteId": "n-1", "text": "saved\u200b"}).encode()      # the escape hides U+200B in raw bytes
GOV_PACK = """rulepack_id: moi-case-pack
version: 0.1.0
rules:
  - id: case-closure-needs-approval
    description: Closing a case is a consequential action and needs a named approver
    on: tool_call
    match: { tool: ["http:case-api:closeCase"] }
    action: confirm
"""


def model(request: httpx.Request) -> httpx.Response:
    prompt = json.loads(request.content)["messages"][-1]["content"]
    word = next((w for w in CALLS if w in prompt), None)
    message = {"role": "assistant", "content": "Done."}
    if word:
        name, args = CALLS[word]
        message = {"role": "assistant", "content": None, "tool_calls": [{
            "id": "call_" + record.sha256_hex(prompt.encode())[:12], "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}]}
    return httpx.Response(200, json={"id": "c", "model": "m", "choices": [{"index": 0, "message": message,
                                                                           "finish_reason": "stop"}]})


class CaseApi:
    """The real upstream: records what reached it."""

    def __init__(self):
        self.seen, self.down, self.big, self.last, self.extra = [], False, None, None, {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("refused")
        self.seen.append((request.method, request.url.path, request.url.query.decode(), dict(request.headers)))
        self.last = request
        if self.big:
            content, ctype, status = self.big
            return httpx.Response(status, content=content, headers={"content-type": ctype})
        if request.url.path.endswith("/notes"):
            return httpx.Response(201, content=SAVED, headers={"content-type": "application/json"})
        return httpx.Response(200, json={"ok": True}, headers=self.extra)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SIJIL_TOOLS_TOKEN", "tools-secret")
    (tmp_path / "case-api.json").write_text(json.dumps(SPEC))
    client, s = ledger_node(tmp_path, model)
    with client:
        cfg = config.load(str(guard_yaml(tmp_path, f"""rulepack: {tmp_path}/starter.yaml
repo: {tmp_path}/repo
http_tools:
  listen: 127.0.0.1:8090
  inbound_auth: {{mode: bearer_env}}
  servers:
    - name: case-api
      upstream: https://case.moi.internal/api/v2
      spec: {tmp_path}/case-api.json
      forward_headers: [Authorization]
      operations: {{allow: [getCase, listCases, addCaseNote, closeCase, exportCases], deny: ["*"]}}
""")))
        identity.register(ledger_of(client), cfg.agent_id, identity.create_key(cfg.key_path, cfg.repo),
                          cfg.registered_by)
        api = CaseApi()
        adapter = http.Adapter(cfg, ledger_of(client), httpx.AsyncClient(transport=httpx.MockTransport(api)))
        with TestClient(http.app(adapter), headers={"X-Sijil-Tools-Token": "tools-secret"}) as tools:
            tools.adapter = adapter
            yield client, s, cfg, tools, api


def start(tools, intent="Case MOI-2026-004211") -> dict:
    r = tools.post("/_sijil/task/start", json={"intent": intent, "session_id": "conv-1", "harness": "foundry"})
    assert r.status_code == 200, r.text
    return r.json()


def think(client, t, prompt) -> str:
    """The agent's model call, bound to the task; returns the tool call id the model chose."""
    hdr = {"X-Sijil-Agent-Session": t["agent_session"], "X-Sijil-Task-Seq": str(t["task_seq"])}
    r = chat(client, None, prompt, **hdr)
    assert r.status_code == 200
    return r.json()["choices"][0]["message"]["tool_calls"][0]["id"]


def test_case_note_round_trip_seals_call_egress_and_result(env):
    client, s, cfg, tools, api = env
    t = start(tools)
    cid = think(client, t, "add the note")
    r = tools.post("/case-api/cases/MOI-2026-004211/notes", json={"note": NOTE["note"]},
                   headers={"Authorization": "Bearer case-pat", "X-Sijil-Tool-Use-Id": cid,
                            "X-Sijil-Task-Seq": str(t["task_seq"]), "X-Sijil-Harness": "foundry"})
    assert r.status_code == 201 and r.json() == {"noteId": "n-1", "text": "saved"}        # stripped
    method, path, query, headers = api.seen[0]
    assert (method, path) == ("POST", "/api/v2/cases/MOI-2026-004211/notes")
    assert headers["authorization"] == "Bearer case-pat" and not any(h.startswith("x-sijil") for h in headers)
    call, egress, result = rows(s.db_path)[-3:]
    x = json.loads(call["ext"])
    assert (call["type"], call["input_hash"], x["correlation"], x["tool_use_id"]) == \
        ("tool_call", record.sha256_hex(record.canonical_json(NOTE)), "tool_use_id", cid)
    assert (x["observed_by"], x["harness"], x["qualified"], x["tool"], x["server"]) == \
        ("http_adapter", "foundry", "http:case-api:addCaseNote", "addCaseNote", "case-api")
    assert x["summary"] == {"method": "POST", "host": "case.moi.internal", "path_template": "/cases/{caseId}/notes",
                            "arg_keys": ["caseId", "note"]}
    assert (egress["type"], egress["parent_seq"]) == ("egress", str(call["seq"]))
    assert json.loads(egress["ext"]) == {"host": "case.moi.internal", "port": 443, "proto": "https",
                                         "observed_by": "http_adapter", "allowed_by": "rulepack", "method": "POST",
                                         "pin_source": cfg.path}
    y = json.loads(result["ext"])
    assert (result["source_label"], y["http_status"], y["status"], y["content_types"]) == \
        ("http:case-api", 201, "ok", ["application/json"])
    assert y["invisible_unicode"]["action"] == "stripped" and r.headers["x-sijil-seq"] == str(result["seq"])
    assert result["output_hash"] == record.sha256_hex(SAVED) and y["bytes"] == len(SAVED)
    assert tools.post("/_sijil/task/end", json={"task_seq": t["task_seq"]}).json()["egress"] == 1
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_args_hash_correlation_with_typed_query_parameters(env):
    client, s, cfg, tools, api = env
    t = start(tools)
    think(client, t, "list the open cases")
    r = tools.get("/case-api/cases?limit=10&open=true", headers={"X-Sijil-Task-Seq": str(t["task_seq"])})
    assert r.status_code == 200 and api.seen[0][2] == "limit=10&open=true"
    x = json.loads(rows(s.db_path, "type = 'tool_call'")[0]["ext"])
    assert x["correlation"] == "args_hash" and x["summary"]["path_template"] == "/cases"
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_unknown_and_filtered_operations_are_sealed_blocks(env):
    client, s, cfg, tools, api = env
    t = start(tools)
    h = {"X-Sijil-Task-Seq": str(t["task_seq"])}
    cid = think(client, t, "export everything")
    r = tools.get("/case-api/admin/export", headers={**h, "X-Sijil-Tool-Use-Id": cid})
    assert r.status_code == 404 and r.json()["error"]["rule_hits"] == ["http-operation-unknown"]
    cid = think(client, t, "delete the case")
    r = tools.delete("/case-api/cases/MOI-2026-004211", headers={**h, "X-Sijil-Tool-Use-Id": cid})
    assert r.status_code == 404 and r.json()["error"]["rule_hits"] == ["tool-not-allowlisted"]
    assert api.seen == []                                                # the upstream was never called
    unknown, filtered = rows(s.db_path, "type = 'tool_call'")
    assert json.loads(unknown["ext"])["tool"] == "GET (unmatched)" and unknown["decision"] == "block"
    assert json.loads(filtered["ext"])["tool"] == "DELETE /cases/{caseId}"
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_confirm_without_an_approval_channel_blocks(env, tmp_path):
    client, s, cfg, tools, api = env
    (tmp_path / "starter.yaml").write_text(GOV_PACK)
    assert client.post("/api/admin/rulepack/reload", headers=ADMIN).status_code == 200
    t = start(tools)
    cid = think(client, t, "close the case")
    r = tools.post("/case-api/cases/MOI-2026-004211/close", headers={"X-Sijil-Tool-Use-Id": cid,
                                                                     "X-Sijil-Task-Seq": str(t["task_seq"])})
    assert r.status_code == 403 and r.json()["error"]["rule_hits"] == ["case-closure-needs-approval"]
    rec = rows(s.db_path, "type = 'tool_call'")[0]
    assert json.loads(rec["ext"])["confirmation"] == "unavailable" and api.seen == []
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_task_must_be_named_when_two_are_open_and_nothing_is_sealed(env):
    client, s, cfg, tools, api = env
    t1, t2 = start(tools), start(tools, "second conversation")
    think(client, t1, "get the case")
    before = len(rows(s.db_path))
    r = tools.get("/case-api/cases/MOI-2026-004211")
    assert r.status_code == 409 and r.json()["error"]["type"] == "http-task-ambiguous"
    assert len(rows(s.db_path)) == before and api.seen == []
    assert tools.get("/case-api/cases/MOI-2026-004211", headers={"X-Sijil-Task-Seq": str(t1["task_seq"])}).status_code == 200


def test_inbound_auth_upstream_failure_and_unparented_calls(env):
    client, s, cfg, tools, api = env
    before = len(rows(s.db_path))
    assert tools.get("/case-api/cases", headers={"X-Sijil-Tools-Token": "wrong"}).status_code == 401
    assert len(rows(s.db_path)) == before
    t = start(tools)
    r = tools.get("/case-api/cases/MOI-2026-004211", headers={"X-Sijil-Task-Seq": str(t["task_seq"])})
    assert r.status_code == 403 and r.json()["error"]["seq"] is None    # no inference asked for it: not sealed
    think(client, t, "get the case")
    api.down = True
    r = tools.get("/case-api/cases/MOI-2026-004211", headers={"X-Sijil-Task-Seq": str(t["task_seq"])})
    assert r.status_code == 502
    result = rows(s.db_path, "type = 'tool_result'")[0]
    assert json.loads(result["ext"])["status"] == "error" and "http_status" not in json.loads(result["ext"])
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_task_endpoints_refuse_malformed_bodies(env):
    client, s, cfg, tools, api = env
    for path, body in (("/_sijil/task/start", b"{"), ("/_sijil/task/start", b"[]"),
                       ("/_sijil/task/start", b'{"harness": "claude-code"}'), ("/_sijil/task/end", b"nope"),
                       ("/_sijil/task/end", b'{"task_seq": 3, "outcome": "timeout"}')):
        assert tools.post(path, content=body).status_code == 400, (path, body)


def test_spec_matching_prefers_literal_paths(tmp_path):
    (tmp_path / "s.json").write_text(json.dumps({"paths": {"/cases/{id}": {"get": {"operationId": "getCase"}},
                                                           "/cases/open": {"get": {"operationId": "openCases"}}}}))
    ops = http.load_spec(str(tmp_path / "s.json"))
    assert http.match(ops, "GET", "/cases/open")[0].id == "openCases"
    assert http.match(ops, "GET", "/cases/42") == (ops[1], {"id": "42"})
    assert http.match(ops, "POST", "/cases/42") is None and http.match(ops, "GET", "/cases/4/2") is None


@pytest.mark.parametrize("block,message", [
    ("http_tools:\n  listen: 0.0.0.0:8090\n  inbound_auth: {mode: bearer_env}\n", "needs tls"),
    ("http_tools:\n  inbound_auth: {mode: entra}\n", "entra is not built"),
    ("http_tools:\n  inbound_auth: {mode: bearer_env, token_env: GUARD_UNSET_TOKEN}\n", "is not set"),
    ("http_tools:\n  servers: [{name: case-api, upstream: https://x}]\n", "needs a"),
])
def test_http_tools_config_refuses_unsafe_setups(tmp_path, block, message):
    p = guard_yaml(tmp_path, block)
    with pytest.raises(ValueError, match=message):
        config.load(str(p))


def test_dot_segments_never_reach_the_upstream(env):
    client, s, cfg, tools, api = env
    t = start(tools)
    h = {"X-Sijil-Task-Seq": str(t["task_seq"])}
    cid = think(client, t, "export everything")
    r = tools.get("/case-api/cases/%2e%2e/export", headers={**h, "X-Sijil-Tool-Use-Id": cid})
    assert r.status_code == 404 and r.json()["error"]["rule_hits"] == ["http-operation-unknown"] and api.seen == []


def test_oversized_text_is_cut_at_a_character_boundary_and_sealed_truncated(env):
    client, s, cfg, tools, api = env
    limit = cfg.max_result_bytes
    big = b"a" * (limit - 1) + "\u00e9".encode() + b"tail"            # the two-byte character straddles the limit
    api.big = (big, "text/plain", 200)
    t = start(tools)
    think(client, t, "list the open cases")
    r = tools.get("/case-api/cases?limit=10&open=true", headers={"X-Sijil-Task-Seq": str(t["task_seq"])})
    assert r.status_code == 200 and r.content == b"a" * (limit - 1)
    x = json.loads(rows(s.db_path, "type = 'tool_result'")[0]["ext"])
    assert x["truncated"] is True and x["bytes"] == len(big) and x["http_status"] == 200 and "withheld" not in x
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_oversized_json_is_withheld_with_the_upstream_status(env):
    client, s, cfg, tools, api = env
    big = json.dumps({"rows": ["x" * 1000] * 400}).encode()
    api.big = (big, "application/json", 201)
    t = start(tools)
    think(client, t, "list the open cases")
    r = tools.get("/case-api/cases?limit=10&open=true", headers={"X-Sijil-Task-Seq": str(t["task_seq"])})
    assert r.status_code == 201 and r.json() == {"sijil": "result withheld: over max_result_bytes"}
    result = rows(s.db_path, "type = 'tool_result'")[0]
    x = json.loads(result["ext"])
    assert "truncated" not in x and x["bytes"] == len(big) and x["http_status"] == 201 and x["withheld"] is True
    assert result["output_hash"] == record.sha256_hex(big) and r.headers["x-sijil-seq"] == str(result["seq"])
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_an_undecodable_body_is_hashed_as_it_arrived_not_as_the_notice(env):
    """Final review Minor 2: the guard's notice is relayed, the upstream bytes are what output_hash commits to."""
    client, s, cfg, tools, api = env
    deep = b"[" * 100000 + b"]" * 100000
    api.big = (deep, "application/json", 200)
    t = start(tools)
    think(client, t, "list the open cases")
    r = tools.get("/case-api/cases?limit=10&open=true", headers={"X-Sijil-Task-Seq": str(t["task_seq"])})
    assert r.status_code == 502 and r.json() == {"error": "upstream response is not decodable"}
    result = rows(s.db_path, "type = 'tool_result'")[0]
    x = json.loads(result["ext"])
    assert result["output_hash"] == record.sha256_hex(deep) and x["bytes"] == len(deep) and x["status"] == "error"
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_ledger_unreachable_is_503_with_a_generic_message(env):
    client, s, cfg, tools, api = env
    t = start(tools)
    think(client, t, "get the case")

    def down(request):
        raise httpx.ConnectError("secret-host:5432 refused")
    tools.adapter.ledger.http = httpx.Client(base_url="http://ledger", transport=httpx.MockTransport(down))
    r = tools.get("/case-api/cases/MOI-2026-004211", headers={"X-Sijil-Task-Seq": str(t["task_seq"])})
    assert r.status_code == 503 and r.json() == {"error": "Sijil ledger unreachable"} and api.seen == []
    assert tools.post("/_sijil/task/start", json={"intent": "x"}).status_code == 503


def test_missing_token_header_is_401_and_nothing_is_sealed(env):
    client, s, cfg, tools, api = env
    before = len(rows(s.db_path))
    with TestClient(tools.app) as bare:
        assert bare.get("/case-api/cases").status_code == 401
        assert bare.post("/_sijil/task/start", json={"intent": "x"}).status_code == 401
    assert len(rows(s.db_path)) == before and api.seen == []


@pytest.mark.parametrize("url", ["/case-api/cases/a%2fb", "/case-api//cases", "/case-api/cases/", "/case-api/Cases",
                                 "/case-api/cases/x/y/z", "/case-api/admin/export?secret=1", "/case-api"])
def test_evasive_paths_never_reach_the_upstream(env, url):
    client, s, cfg, tools, api = env
    t = start(tools)
    cid = think(client, t, "export everything")
    r = tools.get(url, headers={"X-Sijil-Task-Seq": str(t["task_seq"]), "X-Sijil-Tool-Use-Id": cid})
    assert r.status_code in (403, 404) and api.seen == []


def test_only_listed_headers_reach_the_upstream_and_none_come_back(env):
    client, s, cfg, tools, api = env
    api.extra = {"Set-Cookie": "sid=1", "Location": "http://evil", "WWW-Authenticate": "Basic", "X-Up": "1",
                 "Connection": "close"}
    t = start(tools)
    think(client, t, "get the case")
    h = [("x-sijil-task-seq", str(t["task_seq"])), ("authorization", "Bearer pat"), ("cookie", "a=b"),
         ("proxy-authorization", "x"), ("x-api-key", "k"), ("accept", "a/1"), ("accept", "b/2")]
    r = tools.get("/case-api/cases/MOI-2026-004211", headers=h)
    assert r.status_code == 200
    got = api.last.headers
    assert got["authorization"] == "Bearer pat" and got.get_list("accept") == ["a/1", "b/2"]
    assert not {"cookie", "proxy-authorization", "x-api-key"} & set(got)
    assert not {"set-cookie", "location", "www-authenticate", "x-up"} & set(r.headers)
    # Authorization is forwarded only when the server lists it
    ad = tools.adapter
    server, ops = ad.servers["case-api"]
    ad.servers["case-api"] = (dataclasses.replace(server, forward_headers=()), ops)
    think(client, t, "get the case again")
    assert tools.get("/case-api/cases/MOI-2026-004211", headers=h).status_code == 200
    assert "authorization" not in api.last.headers


def test_body_cap_is_413_by_length_and_when_chunked(env):
    client, s, cfg, tools, api = env
    ad = tools.adapter
    server, ops = ad.servers["case-api"]
    ad.servers["case-api"] = (dataclasses.replace(server, max_body_bytes=10), ops)
    before = len(rows(s.db_path))
    assert tools.post("/case-api/cases/x/notes", content=b"x" * 11).status_code == 413
    chunks = (b"x" * 4 for _ in range(4))
    assert tools.post("/case-api/cases/x/notes", content=chunks).status_code == 413
    assert len(rows(s.db_path)) == before and api.seen == []


def test_task_refusals_are_told_apart_and_stale_pipelines_dropped(env):
    client, s, cfg, tools, api = env
    t = start(tools)
    ad = tools.adapter
    ad.pipelines["stale-session"] = object()
    r = tools.get("/case-api/cases/MOI-2026-004211", headers={"X-Sijil-Task-Seq": "99999"})
    assert r.status_code == 409 and r.json()["error"]["type"] == "http-task-not-open"
    assert "stale-session" not in ad.pipelines
    tools.post("/_sijil/task/end", json={"task_seq": t["task_seq"]})
    r = tools.get("/case-api/cases/MOI-2026-004211")
    assert r.status_code == 409 and r.json()["error"]["type"] in ("http-task-none", "http-task-not-open")


def _cfg(tmp_path, monkeypatch, block):
    monkeypatch.setenv("SIJIL_TOOLS_TOKEN", "t")
    return config.load(str(guard_yaml(tmp_path, block)))


@pytest.mark.parametrize("listen", ["[::1]:8090", "localhost:8090", "127.0.0.2:8090"])
def test_loopback_allowlist_accepts_without_tls_or_auth(tmp_path, monkeypatch, listen):
    assert _cfg(tmp_path, monkeypatch, f"http_tools:\n  listen: '{listen}'\n").http_tools.auth == "none"


@pytest.mark.parametrize("listen", ["0.0.0.0:8090", ":8090", "example.com:8090", "[::]:8090"])
def test_off_loopback_needs_tls_and_auth(tmp_path, monkeypatch, listen):
    with pytest.raises(ValueError, match="needs tls"):
        _cfg(tmp_path, monkeypatch, f"http_tools:\n  listen: '{listen}'\n  inbound_auth: {{mode: bearer_env}}\n")
    block = f"http_tools:\n  listen: '{listen}'\n  tls: {{cert: c.pem, key: k.pem}}\n  inbound_auth: {{mode: bearer_env}}\n"
    assert _cfg(tmp_path, monkeypatch, block).http_tools.auth == "bearer_env"


def test_auth_modes(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="client_ca"):
        _cfg(tmp_path, monkeypatch, "http_tools:\n  tls: {cert: c, key: k}\n  inbound_auth: {mode: mtls}\n")
    ok = _cfg(tmp_path, monkeypatch, "http_tools:\n  tls: {cert: c, key: k}\n  inbound_auth: {mode: mtls, client_ca: ca}\n")
    assert ok.http_tools.auth == "mtls" and ok.http_tools.client_ca.endswith("/ca")
    with pytest.raises(ValueError, match="must be paths"):
        _cfg(tmp_path, monkeypatch, "http_tools:\n  tls: {cert: [1], key: k}\n")
    with pytest.raises(ValueError, match="not supported|only"):
        _cfg(tmp_path, monkeypatch, "http_tools:\n  inbound_auth: {mode: none, bogus: 1}\n")


@pytest.mark.parametrize("server,message", [
    ("{name: a, upstream: 'https://x', spec: s, forward_headers: [X-Sijil-Task-Seq]}", "forward_headers"),
    ("{name: a, upstream: 'https://x', spec: s, forward_headers: [Host]}", "forward_headers"),
    ("{name: a, upstream: 'https://x', spec: s, forward_headers: [Proxy-Authorization]}", "forward_headers"),
    ("{name: _sijil, upstream: 'https://x', spec: s}", "needs a"),
    ("{name: a, upstream: 'https://x:99999', spec: s}", "port"),
    ("{name: a, upstream: 'ftp://x', spec: s}", "http"),
])
def test_http_server_config_refusals(tmp_path, monkeypatch, server, message):
    with pytest.raises(ValueError, match=message):
        _cfg(tmp_path, monkeypatch, f"http_tools:\n  servers: [{server}]\n")


def test_adapter_and_a_stdio_guard_of_one_agent_share_one_task(env):
    """Final review Important 3 (d): a task opened through the adapter is the state file's task, so a stdio MCP
    guard of the same agent joins it and the adapter's calls without X-Sijil-Task-Seq still find one task."""
    from test_guard_serve import INIT, SERVERS, Harness
    client, s, cfg, tools, api = env
    t = start(tools)
    both = dataclasses.replace(cfg, servers=config._servers(yaml.safe_load(SERVERS), cfg.path, cfg.repo))

    async def go():
        g = serve.Guard(both, both.servers[1], ledger_of(client))
        await g.start()
        a = await g.new_session(Harness(), {})
        meta = (await a.handle("initialize", INIT))["_meta"]["sijil"]
        await g.aclose()
        return meta
    assert asyncio.run(go()) == {"agent_session": t["agent_session"], "task_seq": t["task_seq"]}
    assert len(rows(s.db_path, "type = 'task_start'")) == 1 and rows(s.db_path, "type = 'task_end'") == []
    think(client, t, "get the case")
    assert tools.get("/case-api/cases/MOI-2026-004211").status_code == 200
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_adapter_task_routes_use_the_shared_state_file_and_renew_a_lost_session(env):
    """(e): conversations sit side by side on the state file's stack, an end takes its own off, and a session the
    ledger no longer knows (401) is renewed as `sijil-guard task start` renews it."""
    client, s, cfg, tools, api = env
    path = task.state_path(cfg)
    t1, t2 = start(tools), start(tools, "second conversation")
    assert task.load(path, cfg.agent_id).tasks == [t1["task_seq"], t2["task_seq"]]
    assert tools.post("/_sijil/task/end", json={"task_seq": str(t1["task_seq"])}).status_code == 200
    assert task.load(path, cfg.agent_id).tasks == [t2["task_seq"]]
    st = task.load(path, cfg.agent_id)
    st.agent_session = "as_" + "0" * 32
    task.save(st, path)
    t3 = start(tools, "third conversation")
    st = task.load(path, cfg.agent_id)
    assert t3["agent_session"] == st.agent_session != "as_" + "0" * 32 and st.tasks == [t3["task_seq"]]


def test_the_task_is_resolved_once_per_request(env, monkeypatch):
    """Final review Minor 8: without X-Sijil-Task-Seq the tool_call's task is the one the egress and the result
    are sealed into, though another task opens while the upstream runs."""
    client, s, cfg, tools, api = env
    t = start(tools)
    think(client, t, "get the case")
    ad, fetch = tools.adapter, tools.adapter.fetch

    async def racing(*a):
        await asyncio.to_thread(task.start_task, ad.ledger, t["agent_session"], "another conversation", "foundry")
        return await fetch(*a)
    monkeypatch.setattr(ad, "fetch", racing)
    assert tools.get("/case-api/cases/MOI-2026-004211").status_code == 200
    sealed = rows(s.db_path, "type IN ('tool_call', 'egress', 'tool_result')")
    assert [r["task_seq"] for r in sealed] == [str(t["task_seq"])] * 3
    assert verify(s.db_path, s.pubkey_path)[0] == 0


@pytest.mark.parametrize("value,kind,typed", [
    ("5", "integer", 5), ("-0", "integer", 0), ("-12", "number", -12), ("1.5", "number", 1.5),
    ("1e3", "number", 1000.0), ("-0.25E-2", "number", -0.0025), ("true", "boolean", True),
    # not strict JSON numbers: they stay strings (§17.3.3)
    (" 5", "integer", " 5"), ("5_000", "integer", "5_000"), ("+5", "integer", "+5"), ("05", "integer", "05"),
    ("1.5", "integer", "1.5"), ("٥", "integer", "٥"), ("nan", "number", "nan"), ("inf", "number", "inf"),
    ("Infinity", "number", "Infinity"), ("1e400", "number", "1e400"), (".5", "number", ".5"), ("5.", "number", "5."),
    ("+1.5", "number", "+1.5"), ("1_0.5", "number", "1_0.5"), ("5\n", "integer", "5\n"), ("True", "boolean", "True"),
    ("9" * 5000, "integer", "9" * 5000),                     # past Python's int-from-string digit limit
])
def test_typed_parameters_accept_only_strict_json_numbers(value, kind, typed):
    got = http._typed(value, kind)
    assert got == typed and type(got) is type(typed)


def test_the_health_endpoint_needs_no_token_and_tells_nothing(env):
    """GET /_sijil/healthz for the sidecar's probe: no token, no ledger call, only {"ok": true}."""
    client, s, cfg, tools, api = env
    before = rows(s.db_path)
    bare = TestClient(tools.app)
    r = bare.get("/_sijil/healthz")
    assert (r.status_code, r.json()) == (200, {"ok": True})
    assert bare.post("/_sijil/healthz").status_code == 401           # only the probe is open
    assert bare.get("/case-api/cases/x").status_code == 401
    assert rows(s.db_path) == before and api.seen == []
