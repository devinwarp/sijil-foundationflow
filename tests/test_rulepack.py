"""Row 4: rule pack loading, rulepack_change at startup and reload, rulepack_hash on every record (spec §2.4.6)."""

import json

import pytest

from conftest import ask, make_node, rows, stub_model, verify
from sijill import record, rulepack

PACK = """rulepack_id: moi-case-pack
version: 0.1.0
rules:
  - id: case-closure-needs-approval
    on: tool_call
    match: {tool: ["http:case-api:closeCase"]}
    action: confirm
  - id: no-write-after-citizen-upload
    on: tool_call
    match: {http_method: [POST], context_labels_any: ["http:document-intake"]}
    action: block
"""


def pack_node(tmp_path, text=PACK):
    (tmp_path / "pack.yaml").write_text(text)
    return make_node(tmp_path, stub_model, rulepack_path=str(tmp_path / "pack.yaml"))


def test_first_adoption_is_sealed_before_anything_else(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        assert ask(client, "hello").status_code == 200
    change, inference = rows(s.db_path)
    h = record.sha256_hex(PACK.encode())
    assert (change["type"], change["agent_id"], change["principal"], change["rulepack_hash"]) == \
        ("rulepack_change", "", "", h)
    ids = ["case-closure-needs-approval", "no-write-after-citizen-upload"]
    assert json.loads(change["rule_hits"]) == ids
    assert json.loads(change["ext"]) == {"rulepack_id": "moi-case-pack", "version": "0.1.0",
                                         "path": str(tmp_path / "pack.yaml"), "before": "", "after": h,
                                         "rules_changed": ids, "trigger": "startup"}
    assert inference["rulepack_hash"] == h
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_restart_with_the_same_pack_seals_nothing(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        pass
    client, s = pack_node(tmp_path)
    with client:
        pass
    assert len(rows(s.db_path)) == 1


def test_reload_seals_only_changed_actions(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        assert client.post("/api/admin/rulepack/reload").json()["seq"] is None
        (tmp_path / "pack.yaml").write_text(PACK.replace("action: block", "action: record"))
        r = client.post("/api/admin/rulepack/reload").json()
        assert r["changed"] == ["no-write-after-citizen-upload"] and r["seq"] == 2
        assert ask(client, "after").status_code == 200
    first, second, inference = rows(s.db_path)
    x = json.loads(second["ext"])
    assert (x["before"], x["after"], x["trigger"]) == (first["rulepack_hash"], second["rulepack_hash"], "reload")
    assert inference["rulepack_hash"] == second["rulepack_hash"]
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_pack_edited_while_down_is_sealed_at_startup(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        pass
    client, s = pack_node(tmp_path, PACK.replace("0.1.0", "0.2.0"))
    with client:
        pass
    _, change = rows(s.db_path)
    x = json.loads(change["ext"])
    assert (x["version"], x["rules_changed"], x["trigger"]) == ("0.2.0", [], "startup")
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_m1_chain_adopts_a_pack_without_a_downgrade(tmp_path):
    client, s = make_node(tmp_path, stub_model)
    with client:
        ask(client, "before any pack")
    client, s = pack_node(tmp_path)
    with client:
        ask(client, "after")
    assert [r["rulepack_hash"] != "" for r in rows(s.db_path)] == [False, True, True]
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_dropping_the_pack_from_config_refuses_to_start(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        pass
    client, s = make_node(tmp_path, stub_model)
    with pytest.raises(RuntimeError, match="SIJILL_RULEPACK_PATH"):
        with client:
            pass


def test_reload_needs_the_admin_token(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        assert client.post("/api/admin/rulepack/reload", headers={"Authorization": "Bearer no"}).status_code == 401


@pytest.mark.parametrize("text, match", [
    ("version: 1\nrules: []\n", "rulepack_id"),
    (PACK.replace("case-closure-needs-approval", "Case_Closure"), "kebab-case"),
    (PACK.replace("case-closure-needs-approval", "principal-missing"), "reserved"),
    (PACK.replace("no-write-after-citizen-upload", "case-closure-needs-approval"), "duplicate"),
    (PACK.replace("action: confirm", "action: maybe"), "action"),
    (PACK.replace("on: tool_call", "on: inference", 1), "on in"),
])
def test_loader_refuses_bad_packs(tmp_path, text, match):
    (tmp_path / "p.yaml").write_text(text)
    with pytest.raises(ValueError, match=match):
        rulepack.load(str(tmp_path / "p.yaml"))
