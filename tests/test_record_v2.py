"""record.py v2 (spec §2.1-2.4, §17.1): field set, omit-if-empty hashing, and the writer's _validate rules."""

import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sijill import policy, record
from sijill.store import Store

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
AGENT = "spiffe://acme.example/agent/ci-fixer"
PRINCIPAL = "email:" + "0" * 64
HUMAN = "human:entra-moi:" + "1" * 64


def cj(obj) -> str:
    return record.canonical_json(obj).decode()


BASE = dict(ts="2026-10-01T08:00:00.000Z", model_id="", model_digest="", node_id="auh-node-01",
            node_region="AE-AZ", policy_id="moi-case-agent", policy_hash="a" * 64, approval_ref="APR-0311",
            mode="record", decision="allow", rule_hits="[]", input_hash="", output_hash="",
            parent_seq="", source_label="", rulepack_hash="b" * 64, ext="", agent_id="", principal="", task_seq="")
TOOL_CALL = {**BASE, "type": "tool_call", "input_hash": "c" * 64, "parent_seq": "5", "task_seq": "4",
             "agent_id": AGENT, "principal": PRINCIPAL,
             "ext": cj({"harness": "http-agent", "session_id": "s1", "tool": "addCaseNote", "server": "case-api",
                        "qualified": "http:case-api:addCaseNote", "correlation": "tool_use_id",
                        "observed_by": "http_adapter"})}
CLAIMS = {"issuer_id": "entra-moi", "profile": "entra", "validation": "userinfo", "iss": "https://id.example",
          "aud": "", "tenant": "", "assurance": "high", "assurance_rule": 0, "delegated": True,
          "token_hash": "d" * 64}
REQUEST = {"phase": "request", "approval_id": "ap_" + "0" * 26, "tool": "closeCase", "server": "case-api",
           "qualified": "http:case-api:closeCase", "correlation": "tool_use_id", "route_id": "case-closure",
           "approver_set": {"role": "Sijil.Approver.CaseClosure"}, "min_assurance": "high",
           "timeout_ms": 900000, "on_timeout": "deny", "sod": True}


TASK_START_EXT = {"intent_hash": "f" * 64, "harness": "http-agent", "session_id": "s", "repo": "", "commit": "",
                  "lockfile_hash": "", "delegated_from": "", "agent_auth": "key", "principal_auth": "oidc",
                  "agent_session": "as_1"}


def seal(body, seq=10):
    return record.seal(body, seq, record.GENESIS_HASH, KEY)


def test_fields_and_types_are_the_v2_4_set():
    assert len(record.FIELDS) == 25 and record.FIELDS[-3:] == ("prev_hash", "record_hash", "signature")
    assert len(record.TYPES) == 16 and record.TYPES[-2:] == ("agent_identity_update", "approval")
    assert record.AGENT_AUTH == ("key", "mtls", "oidc", "relay", "none")


def test_empty_ext_fields_are_left_out_of_the_hash():
    rec = seal(TOOL_CALL)
    obj = {k: v for k, v in rec.items() if k not in ("record_hash", "signature", "source_label")}
    assert rec["record_hash"] == record.sha256_hex(record.canonical_json(obj))
    assert rec["record_hash"] != record.sha256_hex(record.canonical_json({**obj, "source_label": ""}))


def test_accepts_v2_4_shapes():
    seal(TOOL_CALL)
    seal({**TOOL_CALL, "principal": HUMAN})
    seal({**BASE, "type": "tool_result", "parent_seq": "6", "task_seq": "4", "source_label": "http:case-api",
          "agent_id": AGENT, "principal": HUMAN, "output_hash": "e" * 64,
          "ext": cj({"tool": "addCaseNote", "server": "case-api", "status": "ok", "bytes": 3,
                     "content_types": ["application/json"], "http_status": 201,
                     "invisible_unicode": {"found": False, "count": 0, "action": "none"}})})
    seal({**BASE, "type": "approval", "parent_seq": "5", "task_seq": "4", "agent_id": AGENT, "principal": HUMAN,
          "mode": "record", "decision": "flag", "ext": cj(REQUEST)})
    seal({**BASE, "type": "approval", "parent_seq": "7", "task_seq": "4", "agent_id": AGENT, "principal": HUMAN,
          "ext": cj({"phase": "decision", "approval_id": REQUEST["approval_id"], "outcome": "granted",
                     "approver": "human:entra-moi:" + "2" * 64,
                     "approver_claims": {**CLAIMS, "roles_matched": ["Sijil.Approver.CaseClosure"]}})})
    seal({**BASE, "type": "agent_register", "agent_id": "f2c1e7a0-0000-4000-8000-000000000001",
          "principal": PRINCIPAL,
          "ext": cj({"auth": "relay", "registered_by": PRINCIPAL, "principal_auth": "oidc", "id_form": "aip",
                     "relay_binding": {"platform": "foundry", "endpoint_host": "moi.services.ai.azure.com",
                                       "agent_name": "case-agent"}})})


def ext_with(**kw):
    return cj({**json.loads(TOOL_CALL["ext"]), **kw})


@pytest.mark.parametrize("change", [
    {"parent_seq": "05"},                                    # leading zero
    {"parent_seq": "10"},                                    # not earlier than seq 10
    {"task_seq": "abc"},
    {"task_seq": ""},                                        # tool_call outside a task (H2)
    {"source_label": "mcp:sentry"},                          # source_label only on tool_result
    {"principal": "human:Entra:" + "1" * 64},                # issuer_id is lower-case
    {"principal": "email:dev@acme.example"},                 # humans are hashed
    {"agent_id": "spiffe://acme.example/agent/ci fixer"},    # whitespace
    {"rulepack_hash": "B" * 64},
    {"ext": '{"tool": "x"}'},                                # not canonical
    {"ext": "[]"},                                           # not an object
    {"ext": ext_with(summary=None)},                         # null
    {"ext": ext_with(colour="red")},                         # unknown key
    {"ext": ext_with(harness="vscode")},                     # harness enum
    {"ext": ext_with(observed_by="static")},                 # static is egress-only
    {"ext": ext_with(approval_seq="76")},                    # typed key
    {"ext": ext_with(after_the_fact=1)},
    {"type": "inference"},                                   # parent_seq not allowed on inference
])
def test_rejects_malformed_tool_call(change):
    with pytest.raises((ValueError, TypeError)):
        seal({**TOOL_CALL, **change})


@pytest.mark.parametrize("word", ["NaN", "Infinity", "-Infinity"])
def test_rejects_nan_in_ext(word):
    ext = TOOL_CALL["ext"].replace('"tool":', f'"summary":{{"n":{word}}},"tool":')    # sorted: before tool
    with pytest.raises(ValueError):
        seal({**TOOL_CALL, "ext": ext})
    with pytest.raises(ValueError):
        record.canonical_json({"x": float(word.lower().replace("infinity", "inf"))})


def test_tool_call_without_parent_needs_correlation_none():
    with pytest.raises(ValueError, match="requires parent_seq"):
        seal({**TOOL_CALL, "parent_seq": ""})
    seal({**TOOL_CALL, "parent_seq": "", "ext": ext_with(correlation="none")})


@pytest.mark.parametrize("type_,ext,match", [
    ("task_start", {**TASK_START_EXT, "agent_auth": "magic"}, "agent_auth"),
    ("task_start", {**TASK_START_EXT, "principal_claims": {**CLAIMS, "assurance": "medium"}}, "enums"),
    ("task_start", {**TASK_START_EXT, "principal_claims": {**CLAIMS, "validation": "jwt"}}, "missing"),
    ("agent_register", {"auth": "relay", "registered_by": PRINCIPAL, "principal_auth": "oidc", "id_form": "aip"},
     "relay_binding"),
    ("agent_register", {"auth": "key", "registered_by": PRINCIPAL, "principal_auth": "none", "id_form": "spiffe",
                        "agent_pubkey": "0" * 64, "nonce": "1" * 64, "self_proof": "2" * 128,
                        "relay_binding": {"platform": "foundry", "endpoint_host": "h", "agent_name": "a"}},
     "relay_binding"),
])
def test_rejects_bad_identity_payloads(type_, ext, match):
    with pytest.raises(ValueError, match=match):
        seal({**BASE, "type": type_, "agent_id": AGENT, "principal": PRINCIPAL, "ext": cj(ext)})


RESULT = {**BASE, "type": "tool_result", "parent_seq": "6", "task_seq": "4", "source_label": "http:case-api",
          "agent_id": AGENT, "principal": HUMAN, "output_hash": "e" * 64}
RESULT_EXT = {"tool": "listCases", "server": "case-api", "status": "ok", "bytes": 3,
              "content_types": ["application/json"], "http_status": 200,
              "invisible_unicode": {"found": False, "count": 0, "action": "none"}}


def test_withheld_is_an_optional_true_only_tool_result_key():
    """§2.4.2, §17.1: the HTTP adapter marks a withheld JSON or binary body; absent otherwise."""
    seal({**RESULT, "ext": cj({**RESULT_EXT, "withheld": True})})
    for bad in (False, 1, "true"):
        with pytest.raises(ValueError, match="withheld"):
            seal({**RESULT, "ext": cj({**RESULT_EXT, "withheld": bad})})


@pytest.mark.parametrize("ext", [
    {**REQUEST, "approval_id": "ap_123"},
    {**REQUEST, "on_timeout": "allow"},
    {k: v for k, v in REQUEST.items() if k != "route_id"},
    {"phase": "decision", "approval_id": REQUEST["approval_id"], "outcome": "granted"},          # no approver
    {"phase": "decision", "approval_id": REQUEST["approval_id"], "outcome": "timeout",
     "approver": HUMAN, "approver_claims": CLAIMS},                                                # timeout is unnamed
    {"phase": "decision", "approval_id": REQUEST["approval_id"], "outcome": "granted",
     "approver": PRINCIPAL, "approver_claims": CLAIMS},                                            # approver not human:
])
def test_rejects_bad_approvals(ext):
    with pytest.raises(ValueError):
        seal({**BASE, "type": "approval", "parent_seq": "5", "task_seq": "4", "agent_id": AGENT,
              "principal": HUMAN, "ext": cj(ext)})


@pytest.mark.parametrize("type_", ["task_start", "agent_register", "agent_identity_update", "rulepack_change"])
def test_task_seq_forbidden_on_task_start_agent_and_ledger_types(type_):
    with pytest.raises(ValueError, match="task_seq not allowed"):
        seal({**BASE, "type": type_, "task_seq": "4", "ext": ""})


def test_ledger_types_carry_no_identity():
    with pytest.raises(ValueError, match="ledger-originated"):
        seal({**BASE, "type": "policy_change", "agent_id": AGENT, "principal": PRINCIPAL})


def test_reserved_rule_ids(tmp_path):
    for rid in ("principal-missing", "approval-timeout", "http-task-ambiguous", "budget:case-agent:tool_calls"):
        p = tmp_path / "policy.yaml"
        p.write_text("policy_id: p\napproval_ref: A\nnode: {id: n, region: AE-AZ}\n"
                     f"rules:\n  - {{id: '{rid}', type: keyword_flag, terms: [x], mode: record}}\n")
        with pytest.raises(ValueError, match="reserved"):
            policy.load(p)


def test_store_refuses_a_v1_table(tmp_path):
    db = tmp_path / "v1.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE records (seq INTEGER PRIMARY KEY, type TEXT, ts TEXT, model_id TEXT, "
                 "model_digest TEXT, node_id TEXT, node_region TEXT, policy_id TEXT, policy_hash TEXT, "
                 "approval_ref TEXT, mode TEXT, decision TEXT, rule_hits TEXT, input_hash TEXT, "
                 "output_hash TEXT, prev_hash TEXT, record_hash TEXT, signature TEXT)")
    conn.close()
    with pytest.raises(RuntimeError, match="migrate_v2.py"):
        Store(str(db))


def test_store_creates_side_tables_and_indexes(tmp_path):
    Store(str(tmp_path / "s.db")).close()
    conn = sqlite3.connect(tmp_path / "s.db")
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    conn.close()
    assert {"records", "tool_use_index", "principal_index", "agent_sessions",
            "idx_records_task", "idx_records_agent"} <= names
