"""Verifier v2 (spec §4): column fallback, §2.2 hashing, checks 5-7 and A-G, --json. Numbers in
brackets are the §4.4 test list. Chains come from tests/v2chain.py; a broken chain is written by a
writer holding the node key (Chain.write(validate=False)), because an outsider's edit always stops
at `signature invalid` before these checks run."""

import importlib.util
import json
import subprocess
import sys

import pytest

import v2chain
import vectors_v2
from conftest import ROOT, make_chain, sqlite, verify, verify_json
from sijill import keys, record

spec = importlib.util.spec_from_file_location("sijill_verify", ROOT / "verifier" / "sijill_verify.py")
sv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sv)
V1_COLUMNS = ", ".join(f for f in record.FIELDS if f not in record.EXT_FIELDS)


def run(c, tmp_path, *flags, validate=False):
    return verify(*c.write(tmp_path, validate=validate), *flags)


def test_demo_chain_passes(tmp_path):
    code, line = run(v2chain.demo(), tmp_path, validate=True)
    assert code == 0, line
    assert line.startswith("PASS records=15 first=2026-10-01T08:00:00.000Z last=2026-10-01T08:00:14.000Z ")
    assert " attestation=weights:0,api:2,api+tee:0,none:0 " in line


def test_1_tool_call_pointing_at_a_tool_result(tmp_path):
    c = v2chain.demo()
    c[9]["parent_seq"] = "7"
    assert run(c, tmp_path) == (1, "FAIL seq=9 parent type tool_result expected inference")


def test_2_tool_call_pointing_at_the_rulepack_change(tmp_path):
    c = v2chain.demo()
    c[6]["parent_seq"] = "1"
    assert run(c, tmp_path) == (1, "FAIL seq=6 parent type rulepack_change expected inference")


def test_3_args_not_requested_by_parent(tmp_path):
    c = v2chain.demo()
    c[6]["input_hash"] = "f" * 64
    assert run(c, tmp_path) == (1, "FAIL seq=6 tool_call args not requested by parent")


def test_3b_tool_use_id_must_match_the_same_entry(tmp_path):
    c = v2chain.demo()
    c.ext(10, tool_use_id="toolu_02")              # npm args, but the id of the npx entry
    assert run(c, tmp_path) == (1, "FAIL seq=10 tool_call args not requested by parent")


def test_4_orphan_tool_call_fails_then_passes_with_flag(tmp_path):
    c = v2chain.demo()
    c[10]["parent_seq"] = ""
    c.ext(10, correlation="none", tool_use_id=None)
    assert run(c, tmp_path) == (1, "FAIL seq=10 tool_call without parent inference")
    code, line = run(c, tmp_path, "--allow-orphan-tool-calls")
    assert code == 0 and line.endswith(" orphans=1")


def test_4b_orphan_without_correlation_none_fails_even_with_flag(tmp_path):
    c = v2chain.demo()
    c[10]["parent_seq"] = ""
    assert run(c, tmp_path, "--allow-orphan-tool-calls") == (1, "FAIL seq=10 tool_call without parent inference")


def test_5_rulepack_changed_without_rulepack_change(tmp_path):
    c = v2chain.demo()
    c[8]["rulepack_hash"] = "1" * 64
    assert run(c, tmp_path) == (1, "FAIL seq=8 rulepack changed without rulepack_change")


def test_5b_rulepack_change_must_name_before_and_after(tmp_path):
    c = v2chain.demo()
    c.ext(1, after="2" * 64)
    assert run(c, tmp_path) == (1, "FAIL seq=1 rulepack_change before/after mismatch")
    c = v2chain.demo()
    v2chain.rulepack_change(c, before="9" * 64, after="5" * 64)
    assert run(c, tmp_path) == (1, "FAIL seq=16 rulepack_change before/after mismatch")
    c = v2chain.demo()
    v2chain.rulepack_change(c, before=v2chain.RP, after="5" * 64)
    assert run(c, tmp_path)[0] == 0


def test_6_schema_downgrade(tmp_path):
    c = v2chain.demo()
    c[15]["rulepack_hash"] = ""
    assert run(c, tmp_path) == (1, "FAIL seq=15 schema downgrade")


def test_7_v1_database_passes_before_and_after_migration(tmp_path):
    key = keys.generate(tmp_path / "node.key", tmp_path / "node.pub")
    db = tmp_path / "sijill.db"
    make_chain(db, key, n=20)
    sqlite(db, f"CREATE TABLE v1 AS SELECT {V1_COLUMNS} FROM records; DROP TABLE records; "
               "ALTER TABLE v1 RENAME TO records;")
    assert len(sqlite(db, "PRAGMA table_info(records);").splitlines()) == 18
    before = verify(db, tmp_path / "node.pub")
    assert before[0] == 0 and before[1].startswith("PASS records=20 ")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "migrate_v2.py"), str(db)], check=True,
                   capture_output=True)
    assert verify(db, tmp_path / "node.pub") == before


@pytest.mark.parametrize("seq", sorted(vectors_v2.out))
def test_8_known_answer_vectors(seq):
    """The verifier's own canonicalisation reproduces every §2.6/§17.8 record hash and signature."""
    rec = vectors_v2.out[seq]
    node = sv.ed25519.Ed25519PublicKey.from_public_bytes(vectors_v2.NODE_KEY.public_key().public_bytes_raw())
    assert sv.record_hash(rec) == rec["record_hash"]
    assert sv.signature_valid(node, rec["record_hash"], rec["signature"])
    assert sv.parse_ext(rec["ext"]) == (json.loads(rec["ext"]) if rec["ext"] else {})   # check 6
    if rec["type"] == "inference":                                                     # check G
        assert sv.attestation(rec["model_digest"], json.loads(rec["ext"])) in sv.ATTESTATION


def test_ext_not_canonical(tmp_path):
    c = v2chain.demo()
    c[3]["ext"] = c[3]["ext"].replace(',"files"', ', "files"')
    assert run(c, tmp_path) == (1, "FAIL seq=3 ext not canonical")


@pytest.mark.parametrize("word", ["NaN", "Infinity", "-Infinity"])
def test_nan_in_ext_is_a_fail_line_not_an_exception(tmp_path, word):
    """§2.2: NaN and infinities are not JSON; the reference parser reads them, so check 6 must refuse them."""
    c = v2chain.demo()
    c[3]["ext"] = c[3]["ext"][:-1] + f',"zz":{word}}}'
    assert run(c, tmp_path) == (1, "FAIL seq=3 ext not canonical")


@pytest.mark.parametrize("value,line", [
    ("05", "FAIL seq=6 parent_seq malformed"),
    ("x", "FAIL seq=6 parent_seq malformed"),
    ("8", "FAIL seq=6 parent not earlier"),
])
def test_parent_seq_shape_and_order(tmp_path, value, line):
    c = v2chain.demo()
    c[6]["parent_seq"] = value
    assert run(c, tmp_path) == (1, line)


def test_drift_without_baseline_is_parent_missing(tmp_path):
    c = v2chain.demo()
    c[13]["parent_seq"] = ""
    assert run(c, tmp_path) == (1, "FAIL seq=13 parent missing")


def test_duplicate_tool_result(tmp_path):
    c = v2chain.demo()
    c[12]["parent_seq"] = "6"
    assert run(c, tmp_path) == (1, "FAIL seq=12 duplicate tool_result for parent 6")


def test_drift_baseline_mismatch(tmp_path):
    c = v2chain.demo()
    c[13]["input_hash"] = "9" * 64
    assert run(c, tmp_path) == (1, "FAIL seq=13 drift baseline mismatch")


@pytest.mark.parametrize("seq,label", [(12, "mcp:Sentry"), (12, ""), (6, "repo"), (7, "http:case_api!")])
def test_source_label_invalid(tmp_path, seq, label):
    c = v2chain.demo()
    c[seq]["source_label"] = label
    assert run(c, tmp_path) == (1, f"FAIL seq={seq} source_label invalid")


def test_http_source_label_accepted(tmp_path):
    c = v2chain.demo()
    c[12]["source_label"] = "http:case-api"
    assert run(c, tmp_path)[0] == 0


@pytest.mark.parametrize("digest,attestation", [
    ("sha256:" + "0" * 64, "api"), ("api:anthropic:claude", "weights"), ("", "api"), ("sha1:abc", None)])
def test_attestation_mismatch(tmp_path, digest, attestation):
    c = v2chain.demo()
    c[5]["model_digest"] = digest
    c.ext(5, attestation=attestation)
    assert run(c, tmp_path) == (1, "FAIL seq=5 attestation mismatch")


def test_attestation_counts_and_hyphenated_provider(tmp_path):
    c = v2chain.demo()
    c[5]["model_digest"] = "api:azure-openai:gpt-4.1-2025-04-14"
    c.ext(5, attestation="api+tee")
    c[8]["model_digest"] = "sha256:" + "0" * 64
    c.ext(8, attestation=None)
    code, line = run(c, tmp_path)
    assert code == 0 and " attestation=weights:1,api:0,api+tee:1,none:0 " in line


def test_unknown_type(tmp_path):
    c = v2chain.demo()
    c[3]["type"] = "integrity_check"
    assert run(c, tmp_path) == (1, "FAIL seq=3 unknown type integrity_check")


def test_outsider_forge_stops_at_signature(tmp_path):
    """scripts/tamper.sh forge builds v2 canonical bytes, so the verifier reports the missing key."""
    from conftest import tamper
    db, pub = v2chain.demo().write(tmp_path)
    tamper(db, "forge", "7")
    assert verify(db, pub) == (1, "FAIL seq=7 signature invalid")


def test_json_output(tmp_path):
    c = v2chain.demo()
    db, pub = c.write(tmp_path)
    code, res = verify_json(db, pub)
    assert code == 0 and res["ok"] and res["records"] == 15 and res["code"] is None and res["seq"] is None
    assert res["attestation"] == {"weights": 0, "api": 2, "api+tee": 0, "none": 0}
    assert set(res) == {"ok", "line", "seq", "code", "records", "attestation", "agent_auth", "orphans",
                        "unauthenticated", "agents", "principals", "principal_tokens", "approvals", "budget_hits",
                        "after_the_fact", "rulepack_matched"}
    c[9]["parent_seq"] = "7"
    code, res = verify_json(*c.write(tmp_path, validate=False))
    assert (code, res["ok"], res["seq"], res["code"]) == (1, False, 9, "parent_type")
    assert res["line"] == "FAIL seq=9 parent type tool_result expected inference"
    code, res = verify_json(tmp_path / "nope.db", pub)
    assert (code, res["code"], res["seq"]) == (1, "database_not_found", None)


def test_7b_v2_0_database_with_four_new_columns_passes(tmp_path):
    """A v2.0 store has parent_seq, source_label, rulepack_hash, ext but not the identity columns."""
    key = keys.generate(tmp_path / "node.key", tmp_path / "node.pub")
    db = tmp_path / "sijill.db"
    make_chain(db, key, n=5)
    cols = V1_COLUMNS.replace("output_hash", "output_hash, parent_seq, source_label, rulepack_hash, ext")
    sqlite(db, f"CREATE TABLE v20 AS SELECT {cols} FROM records; DROP TABLE records; "
               "ALTER TABLE v20 RENAME TO records;")
    assert len(sqlite(db, "PRAGMA table_info(records);").splitlines()) == 22
    assert verify(db, tmp_path / "node.pub")[1].startswith("PASS records=5 ")


def test_database_without_records_table(tmp_path):
    _, pub = v2chain.demo().write(tmp_path)
    sqlite(tmp_path / "other.db", "CREATE TABLE t (x INTEGER);")
    code, res = verify_json(tmp_path / "other.db", pub)
    assert (code, res["code"], res["seq"]) == (1, "database_unreadable", None)
