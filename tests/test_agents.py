"""Row 5b, identity half: challenge-response sessions, register / rotate / revoke (spec §5.8.2, §2.4.7-2.4.9)."""

import asyncio
import json

import pytest

from agentkit import (AGENT, AGENT_KEY, HDR, NEW_KEY, NODE_ID, OPS, agent_node, nonce, proof, pub, register,
                      session)
from conftest import rows, sqlite, verify
from sijill import agents


def test_register_then_session_and_the_chain_passes(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        r = register(client, display_name="Case agent (MOI pilot)")
        assert r.status_code == 200 and r.json()["seq"] == 1
        sess = session(client)
    assert (sess["agent_auth"], sess["principal"], sess["principal_auth"]) == ("key", OPS, "none")
    [rec] = rows(s.db_path)
    x = json.loads(rec["ext"])
    assert (rec["type"], rec["agent_id"], rec["principal"]) == ("agent_register", AGENT, OPS)
    assert (x["auth"], x["agent_pubkey"], x["principal_auth"], x["id_form"]) == ("key", pub(AGENT_KEY), "none", "spiffe")
    assert sqlite(s.db_path, "SELECT agent_id, remote_addr FROM agent_sessions") == f"{AGENT}|testclient"
    code, line = verify(s.db_path, s.pubkey_path)
    assert code == 0 and line.startswith("PASS records=1 ")


@pytest.mark.parametrize("agent_id", ["moi.gov.ae/2f1c7e9a-0000-4000-8000-000000000001",   # AIP form, undeclared
                                      "spiffe://moi.gov.ae/workload/case-agent",            # not /agent/
                                      "spiffe://MOI.gov.ae/agent/case-agent"])
def test_ids_the_verifier_would_refuse_are_never_sealed(tmp_path, agent_id):
    client, s = agent_node(tmp_path)
    with client:
        r = client.post("/api/agent/challenge", json={"agent_id": agent_id, "purpose": "register"}, headers=HDR)
        assert r.status_code == 422
        msg = {"agent_id": agent_id, "agent_pubkey": pub(AGENT_KEY), "nonce": "0" * 64, "registered_by": OPS}
        r = client.post("/api/agent/register", json={**msg, "self_proof": proof(AGENT_KEY, msg)}, headers=HDR)
        assert r.status_code == 422
    assert rows(s.db_path) == []


def test_bad_self_proof_and_reused_nonce_are_refused(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        n = nonce(client, purpose="register")
        msg = {"agent_id": AGENT, "agent_pubkey": pub(AGENT_KEY), "nonce": n, "registered_by": OPS}
        bad = client.post("/api/agent/register", json={**msg, "self_proof": proof(NEW_KEY, msg)}, headers=HDR)
        assert bad.status_code == 401 and bad.json()["detail"] == "proof invalid"
        again = client.post("/api/agent/register", json={**msg, "self_proof": proof(AGENT_KEY, msg)}, headers=HDR)
        assert again.status_code == 401 and again.json()["detail"] == "nonce invalid"
    assert rows(s.db_path) == []


def test_session_proof_is_bound_to_this_node(tmp_path):
    client, _ = agent_node(tmp_path)
    with client:
        register(client)
        n = nonce(client)
        msg = {"agent_id": AGENT, "node_id": "other-node", "nonce": n, "purpose": "session"}
        r = client.post("/api/agent/session", json={"agent_id": AGENT, "nonce": n, "proof": proof(AGENT_KEY, msg)},
                        headers=HDR)
        assert r.status_code == 401 and r.json()["detail"] == "proof invalid"


def test_expired_nonce_is_refused(tmp_path, monkeypatch):
    client, _ = agent_node(tmp_path)
    with client:
        register(client)
        n = nonce(client)
        later = agents.clock() + agents.NONCE_TTL_S + 1
        monkeypatch.setattr(agents, "clock", lambda: later)
        msg = {"agent_id": AGENT, "node_id": NODE_ID, "nonce": n, "purpose": "session"}
        r = client.post("/api/agent/session", json={"agent_id": AGENT, "nonce": n, "proof": proof(AGENT_KEY, msg)},
                        headers=HDR)
        assert r.status_code == 401 and r.json()["detail"] == "nonce expired"


def test_rotate_then_revoke_seal_and_verify(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        register(client)
        n = nonce(client, purpose="rotate")
        msg = {"agent_id": AGENT, "new_pubkey": pub(NEW_KEY), "nonce": n, "old_pubkey": pub(AGENT_KEY)}
        r = client.post("/api/agent/rotate", headers=HDR, json={
            "agent_id": AGENT, "new_pubkey": pub(NEW_KEY), "nonce": n, "rotated_by": OPS,
            "proof_old": proof(AGENT_KEY, msg), "proof_new": proof(NEW_KEY, msg)})
        assert r.status_code == 200
        assert session(client, key=NEW_KEY)["agent_auth"] == "key"
        assert client.post("/api/agent/revoke", json={"agent_id": AGENT, "revoked_by": OPS,
                                                      "reason": "pilot ended"}).status_code == 200
        n = nonce(client)
        msg = {"agent_id": AGENT, "node_id": NODE_ID, "nonce": n, "purpose": "session"}
        r = client.post("/api/agent/session", json={"agent_id": AGENT, "nonce": n, "proof": proof(NEW_KEY, msg)},
                        headers=HDR)
        assert r.status_code == 401 and r.json()["detail"] == "agent revoked"
    reg, rot, rev = rows(s.db_path)
    assert (rev["type"], rev["mode"], rev["decision"]) == ("agent_revoke", "enforce", "block")
    assert json.loads(rev["ext"]) == {"pubkey": pub(NEW_KEY), "revoked_by": OPS, "principal_auth": "key",
                                      "reason": "pilot ended"}
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_registry_is_rebuilt_from_the_chain_after_restart(tmp_path):
    client, _ = agent_node(tmp_path)
    with client:
        register(client)
    client, _ = agent_node(tmp_path)
    with client:
        assert register(client).status_code == 409
        assert session(client)["agent_auth"] == "key"


def test_revoke_needs_the_admin_token(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        register(client)
        r = client.post("/api/agent/revoke", json={"agent_id": AGENT, "revoked_by": OPS},
                        headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401
    assert len(rows(s.db_path)) == 1


def test_closed_register_policy_needs_the_admin_token(tmp_path):
    client, s = agent_node(tmp_path, policy_text=None)          # repo policy.yaml: no agents block -> closed
    with client:
        r = client.post("/api/agent/register", headers={**HDR, "Authorization": "Bearer nope"}, json={})
        assert r.status_code == 401
        assert register(client).status_code == 200              # the test client carries the admin token
    assert json.loads(rows(s.db_path)[0]["ext"])["principal_auth"] == "key"


def test_agent_endpoints_are_disabled_without_a_token(tmp_path):
    client, _ = agent_node(tmp_path, agent_token="")
    with client:
        r = client.post("/api/agent/challenge", json={"agent_id": AGENT}, headers=HDR)
        assert r.status_code == 503


def test_wrong_agent_token_is_401(tmp_path):
    client, _ = agent_node(tmp_path)
    with client:
        r = client.post("/api/agent/challenge", json={"agent_id": AGENT}, headers={"X-Sijil-Token": "nope"})
        assert r.status_code == 401


def test_concurrent_registrations_of_one_id_seal_once(tmp_path):
    """The registry check runs under the seal lock, so a race cannot seal two registrations (check K)."""
    client, s = agent_node(tmp_path)
    with client:
        n = client.app.state.node
        x = {"auth": "key", "agent_pubkey": pub(AGENT_KEY), "nonce": "0" * 64, "registered_by": OPS,
             "self_proof": "00", "principal_auth": "none", "id_form": "spiffe"}

        async def both():
            async with n.lock:          # another seal is in progress: both registrations queue on the lock
                tasks = [asyncio.create_task(agents.seal_agent(n, "agent_register", AGENT, OPS, "", x,
                                                               check=lambda: n.agents.unregistered(AGENT)))
                         for _ in range(2)]
                await asyncio.sleep(0)
            return await asyncio.gather(*tasks, return_exceptions=True)
        results = client.portal.call(both)
    assert sorted(type(r).__name__ for r in results) == ["HTTPException", "dict"]
    assert len(rows(s.db_path)) == 1
