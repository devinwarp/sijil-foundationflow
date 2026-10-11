"""An agent's side of the ledger protocol (spec §5.8.2), for the /api/agent/* tests."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import ROOT, make_node, stub_model
from sijill import record

AGENT_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
NEW_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
AGENT = "spiffe://moi.gov.ae/agent/case-agent"
TOKEN = "agent-token"
HDR = {"X-Sijil-Token": TOKEN}
OPS = "local:" + record.sha256_hex(b"ops@auh-node-01")
NODE_ID = "auh-node-01"
OPEN_POLICY = (ROOT / "policy.yaml").read_text() + "agents:\n  register_policy: open\n  session_ttl_s: 3600\n"


def pub(key) -> str:
    return key.public_key().public_bytes_raw().hex()


def proof(key, msg: dict) -> str:
    return key.sign(bytes.fromhex(record.sha256_hex(record.canonical_json(msg)))).hex()


def agent_node(tmp_path, handler=stub_model, policy_text=OPEN_POLICY, **overrides):
    return make_node(tmp_path, handler, policy_text, **{"agent_token": TOKEN, **overrides})


def nonce(client, agent_id=AGENT, purpose="session") -> str:
    r = client.post("/api/agent/challenge", json={"agent_id": agent_id, "purpose": purpose}, headers=HDR)
    assert r.status_code == 200, r.text
    return r.json()["nonce"]


def register(client, agent_id=AGENT, key=AGENT_KEY, registered_by=OPS, **extra):
    n = nonce(client, agent_id, "register")
    msg = {"agent_id": agent_id, "agent_pubkey": pub(key), "nonce": n, "registered_by": registered_by}
    return client.post("/api/agent/register", json={**msg, "self_proof": proof(key, msg), **extra}, headers=HDR)


def session(client, agent_id=AGENT, key=AGENT_KEY) -> dict:
    n = nonce(client, agent_id)
    msg = {"agent_id": agent_id, "node_id": NODE_ID, "nonce": n, "purpose": "session"}
    r = client.post("/api/agent/session", json={"agent_id": agent_id, "nonce": n, "proof": proof(key, msg)},
                    headers=HDR)
    assert r.status_code == 200, r.text
    return r.json()
