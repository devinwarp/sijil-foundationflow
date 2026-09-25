"""Acceptance tests 5-7 and proxy behaviour, against a stub model runtime."""

import json
import statistics
from pathlib import Path

import httpx

from conftest import ask, rows, stub_model, tamper, verify
from sijill import policy, record
from sijill.policy import UPSTREAM_ERROR_HIT
from sijill.proxy import UPSTREAM_ERROR_TYPE


def test_allow_forwards_and_seals(node):
    client, s = node
    r = ask(client, "What are the opening hours of the service centre?")
    assert r.status_code == 200
    assert r.json()["choices"][0]["message"]["content"].startswith("Stub answer")
    assert r.headers["x-sijill-decision"] == "allow" and r.headers["x-sijill-seq"] == "1"
    [rec] = rows(s.db_path)
    assert (rec["decision"], rec["mode"], rec["rule_hits"], rec["type"]) == ("allow", "record", "[]", "inference")
    assert len(rec["output_hash"]) == 64 and rec["node_region"] == "AE-AZ"
    assert UPSTREAM_ERROR_HIT not in rec["rule_hits"]


def test_sensitive_term_in_record_mode_is_flagged_and_forwarded(node):
    client, s = node
    r = ask(client, "How do I renew my EMIRATES ID?")
    assert r.status_code == 200 and r.headers["x-sijill-decision"] == "flag"
    [rec] = rows(s.db_path)
    assert (rec["decision"], rec["mode"], json.loads(rec["rule_hits"])) == ("flag", "record", ["sensitive_terms"])


def test_unapproved_model_is_blocked(node):
    client, s = node
    r = ask(client, "hello", model="some-other-model")
    assert r.status_code == 403
    rec = rows(s.db_path)[0]
    assert rec["rule_hits"] == '["approved_models"]'
    assert UPSTREAM_ERROR_HIT not in rec["rule_hits"]


def test_streaming_rejected_and_not_recorded(node):
    client, s = node
    r = client.post("/v1/chat/completions", json={"model": "x", "stream": True, "messages": []})
    assert r.status_code == 400 and rows(s.db_path) == []


def test_seed_50_through_proxy_then_tamper_demo(node):
    """Test 1-4 again, on a chain written by the real proxy."""
    client, s = node
    for i in range(50):
        assert ask(client, f"question {i}" + (" passport number" if i % 7 == 0 else "")).status_code == 200
    db, pub = s.db_path, s.pubkey_path
    assert verify(db, pub)[1].startswith("PASS records=50")
    tamper(db, "backup")
    tamper(db, "alter", "17")
    assert verify(db, pub) == (1, "FAIL seq=17 content altered")
    tamper(db, "restore")
    tamper(db, "forge", "17")
    assert verify(db, pub) == (1, "FAIL seq=17 signature invalid")
    tamper(db, "restore")
    assert verify(db, pub)[0] == 0
    # The proxy keeps sealing onto the restored chain.
    assert ask(client, "after restore").status_code == 200
    assert verify(db, pub)[1].startswith("PASS records=51")


def test_5_disallowed_region_blocks_with_403_and_chain_passes(node):
    client, s = node
    ask(client, "before")
    r = client.post("/api/admin/node/region", json={"region": "US-VA"})
    assert r.json() == {"region": "US-VA", "region_allowed": False, "seq": 2}
    r = ask(client, "Where is my application?")
    assert r.status_code == 403
    body = r.json()
    assert body["sijill"]["seq"] == 3 and body["sijill"]["rule_hits"] == ["residency"]
    change, block = rows(s.db_path, "seq >= 2")
    assert (change["type"], change["node_region"]) == ("policy_change", "US-VA")
    assert (block["decision"], block["mode"], block["output_hash"]) == ("block", "enforce", "")
    assert client.get("/api/policy").json()["region_allowed"] is False
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_6_mode_change_reload_writes_policy_change(node):
    client, s = node
    ask(client, "my emirates id is 784-...")
    assert client.post("/api/admin/policy/reload").json()["changed"] == []  # no change, no record
    p = Path(s.policy_path)
    p.write_text(p.read_text().replace(
        'terms: ["emirates id", "passport number"]\n    mode: record',
        'terms: ["emirates id", "passport number"]\n    mode: enforce'))
    r = client.post("/api/admin/policy/reload").json()
    assert r["changed"] == ["sensitive_terms"] and r["seq"] == 2
    change = rows(s.db_path, "seq = 2")[0]
    assert change["type"] == "policy_change" and change["rule_hits"] == '["sensitive_terms"]'
    assert change["model_id"] == change["input_hash"] == change["output_hash"] == ""
    assert change["policy_hash"] != rows(s.db_path, "seq = 1")[0]["policy_hash"]
    assert ask(client, "my emirates id is 784-...").status_code == 403
    assert verify(s.db_path, s.pubkey_path)[1].startswith("PASS records=3")


def test_7_proxy_overhead_p95_under_50ms(node):
    client, _ = node
    overheads = [float(ask(client, f"q{i}").headers["x-sijill-overhead-ms"]) for i in range(100)]
    p50 = statistics.median(overheads)
    p95 = statistics.quantiles(overheads, n=100)[94]
    print(f"\nproxy overhead (stub model): p50={p50:.2f}ms p95={p95:.2f}ms")
    assert p95 < 50


def test_api_records_policy_verify(node):
    client, _ = node
    for i in range(5):
        ask(client, f"q{i}")
    r = client.get("/api/records", params={"since": 3}).json()
    assert r["total"] == 5 and [x["seq"] for x in r["records"]] == [4, 5]
    pol = client.get("/api/policy").json()
    assert pol["node_id"] == "auh-node-01" and [x["mode"] for x in pol["rules"]] == ["enforce", "enforce", "record"]
    v = client.get("/api/verify").json()
    assert v["ok"] and v["output"].startswith("PASS records=5")


def test_tail_deletion_while_running_is_detected(node):
    """The writer trusts its own head, so deleting the newest record leaves a visible gap."""
    client, s = node
    for i in range(3):
        ask(client, f"q{i}")
    from conftest import sqlite
    sqlite(s.db_path, "DELETE FROM records WHERE seq = 3;")
    ask(client, "next")
    assert verify(s.db_path, s.pubkey_path) == (1, "FAIL seq=4 gap")


def test_transport_error_seals_marked_record(node_with):
    def down(request):
        raise httpx.ConnectError("connection refused", request=request)

    client, s = node_with(down)
    with client:
        r = ask(client, "hello")
        assert r.status_code == 502 and r.headers["x-sijill-seq"] == "1"
    [rec] = rows(s.db_path)
    assert json.loads(rec["rule_hits"]) == [UPSTREAM_ERROR_HIT]
    assert rec["decision"] == "allow" and rec["output_hash"] == ""


def test_non_200_passthrough_seals_marked_record(node_with):
    def missing(request):
        return httpx.Response(404, json={"error": {"message": "model not found"}})

    client, s = node_with(missing)
    with client:
        r = ask(client, "hello")
        assert r.status_code == 404 and r.json()["error"]["message"] == "model not found"
    [rec] = rows(s.db_path)
    assert json.loads(rec["rule_hits"]) == [UPSTREAM_ERROR_HIT]


def test_bad_200_is_upstream_failure_and_chain_verifies(node_with):
    def empty_choices(request):
        body = json.loads(request.content)
        if "list" in body["messages"][-1]["content"]:
            return httpx.Response(200, json={"choices": "nope"})
        return httpx.Response(200, json={"choices": []})

    client, s = node_with(empty_choices)
    with client:
        r = ask(client, "hello")
        assert r.status_code == 502 and r.json()["error"]["type"] == UPSTREAM_ERROR_TYPE
        r = ask(client, "choices must be a list")
        assert r.status_code == 502
    recs = rows(s.db_path)
    assert len(recs) == 2
    assert all(json.loads(x["rule_hits"]) == [UPSTREAM_ERROR_HIT] for x in recs)
    assert all(x["output_hash"] == "" for x in recs)

    def not_json(request):
        return httpx.Response(200, content=b"<html>runtime gone</html>")

    client2, _ = node_with(not_json)
    with client2:
        r = ask(client2, "hello")
        assert r.status_code == 502
        recs = rows(s.db_path)
        assert len(recs) == 3  # restart wrote no extra record: policy hash unchanged
        assert all(json.loads(x["rule_hits"]) == [UPSTREAM_ERROR_HIT] for x in recs)
        assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_flagged_prompt_plus_transport_error(node_with):
    def down(request):
        raise httpx.ConnectError("connection refused", request=request)

    client, s = node_with(down)
    with client:
        r = ask(client, "can I give you my emirates id?")
        assert r.status_code == 502 and r.headers["x-sijill-decision"] == "flag"
    [rec] = rows(s.db_path)
    assert json.loads(rec["rule_hits"]) == ["sensitive_terms", UPSTREAM_ERROR_HIT]
    assert rec["decision"] == "flag"


def test_startup_policy_drift(node_with):
    client, s = node_with(stub_model)
    with client:
        assert rows(s.db_path) == []  # fresh store: no startup policy_change
        for i in range(3):
            assert ask(client, f"q{i}").status_code == 200

    p = Path(s.policy_path)
    p.write_text(p.read_text().replace('"emirates id"', '"national id"'))
    client2, _ = node_with(stub_model)
    with client2:
        changes = rows(s.db_path, "type = 'policy_change'")
        assert len(changes) == 1
        assert changes[0]["seq"] == 4 and changes[0]["rule_hits"] == "[]"
        assert changes[0]["policy_hash"] == policy.load(s.policy_path).hash
        assert verify(s.db_path, s.pubkey_path)[0] == 0

    client3, _ = node_with(stub_model)
    with client3:
        assert len(rows(s.db_path)) == 4  # restart with no edit: no record


def test_reload_records_any_policy_change(node):
    client, s = node
    ask(client, "hello")
    p = Path(s.policy_path)

    # A term edit moves the hash but no mode: record written, changed == [].
    p.write_text(p.read_text().replace('"emirates id"', '"national id"'))
    r = client.post("/api/admin/policy/reload").json()
    assert r["changed"] == [] and r["seq"] == 2
    rec = rows(s.db_path, "seq = 2")[0]
    assert rec["type"] == "policy_change" and rec["rule_hits"] == "[]"
    assert rec["policy_hash"] == r["policy_hash"]

    # A mode flip: changed names the rule.
    p.write_text(p.read_text().replace("mode: record", "mode: enforce"))
    r = client.post("/api/admin/policy/reload").json()
    assert r["changed"] == ["sensitive_terms"] and r["seq"] == 3
    assert json.loads(rows(s.db_path, "seq = 3")[0]["rule_hits"]) == ["sensitive_terms"]

    # No file change: no record.
    r = client.post("/api/admin/policy/reload").json()
    assert r["changed"] == [] and r["seq"] is None
    assert len(rows(s.db_path)) == 3
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_null_content_is_valid_and_hashed_empty(node_with):
    """Tool-call replies carry content: null; that is a valid 200, not a failure."""

    def tool_call(request):
        return httpx.Response(200, json={
            "id": "chatcmpl-stub", "object": "chat.completion",
            "choices": [{"index": 0, "finish_reason": "tool_calls",
                         "message": {"role": "assistant", "content": None,
                                     "tool_calls": [{"id": "call_1", "type": "function"}]}}]})

    client, s = node_with(tool_call)
    with client:
        r = ask(client, "hello")
        assert r.status_code == 200
        assert r.json()["choices"][0]["message"]["tool_calls"]
    [rec] = rows(s.db_path)
    assert rec["output_hash"] == record.output_hash("")
    assert UPSTREAM_ERROR_HIT not in rec["rule_hits"]
