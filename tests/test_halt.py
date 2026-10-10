# tests/test_halt.py
"""Operator halt: every call refused and sealed until resumed; the state survives a restart."""

import json

import pytest

from conftest import ROOT, ask, rows, stub_model, verify
from sijill import policy


def test_halt_blocks_and_seals_then_resume(node):
    client, s = node
    assert ask(client, "before").status_code == 200
    assert client.post("/api/admin/halt", json={"halted": True}).json() == {"halted": True, "seq": 2}
    r = ask(client, "during")
    assert r.status_code == 403 and r.json()["sijill"]["rule_hits"] == ["halted"]
    assert client.post("/api/admin/halt", json={"halted": False}).json()["seq"] == 4
    assert ask(client, "after").status_code == 200
    change, block, resume = rows(s.db_path, "seq BETWEEN 2 AND 4")
    assert (change["type"], json.loads(change["rule_hits"])) == ("policy_change", ["halted"])
    assert (block["decision"], json.loads(block["rule_hits"])) == ("block", ["halted"])
    assert (resume["type"], json.loads(resume["rule_hits"])) == ("policy_change", ["resumed"])
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_halt_is_idempotent(node):
    client, _ = node
    client.post("/api/admin/halt", json={"halted": True})
    assert client.post("/api/admin/halt", json={"halted": True}).json() == {"halted": True, "seq": None}


def test_halt_survives_restart(node_with):
    client, s = node_with(stub_model)
    with client:
        client.post("/api/admin/halt", json={"halted": True})
    client, s = node_with(stub_model)
    with client:
        assert ask(client, "after restart").status_code == 403


def test_halt_needs_admin_token(node):
    client, _ = node
    r = client.post("/api/admin/halt", json={"halted": True}, headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_reserved_ids_rejected_in_policy(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text((ROOT / "policy.yaml").read_text().replace("id: residency", "id: halted"))
    with pytest.raises(ValueError, match="reserved"):
        policy.load(p)
