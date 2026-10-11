"""Agent identity on the ledger (spec §5.8, §2.4.7-2.4.9): challenge-response sessions, the agent registry
rebuilt from sealed records, and register / rotate / revoke. BSL.

The registry lives in process memory like the chain head (one worker); it is rebuilt from the chain at
startup, so it is never evidence of its own.
"""

import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException, Request

from . import record

SPIFFE = re.compile(r"spiffe://[a-z0-9.-]+/agent/[a-z0-9._-]+")      # verifier check I2
ID_SYNTAX = {"spiffe": r"spiffe://[a-z0-9.-]+/\S+", "wimse": r"wimse://[a-z0-9.-]+/\S+", "did": r"did:[a-z0-9]+:\S+",
             "entra": r"[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}", "cloud-native": r"\S{1,512}", "other": r"\S{1,512}"}
PUBKEY = re.compile(r"[0-9a-f]{64}")
NONCE_TTL_S = 60
PURPOSES = ("session", "register", "rotate")


def clock() -> float:
    return time.time()


def ts_at(epoch: float) -> str:
    """record.now_ts() form for any instant."""
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def cj(obj) -> str:
    return record.canonical_json(obj).decode()


def digest(msg: dict) -> str:
    return record.sha256_hex(record.canonical_json(msg))


def proof_ok(pubkey_hex: str, signature_hex, msg: dict) -> bool:
    """Ed25519 over the 32 raw bytes of sha256(canonical_json(msg)) (spec §2.4.7, §5.8.2)."""
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).verify(
            bytes.fromhex(signature_hex), bytes.fromhex(digest(msg)))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


@dataclass
class Agent:
    auth: str
    pubkey: str
    registered_by: str
    revoked: bool = False
    oidc_binding: dict = field(default_factory=dict)


class Registry:
    """agent_id -> Agent, and the runtime identities declared on the chain (check I2)."""

    def __init__(self, store):
        self.agents: dict[str, Agent] = {}
        self.declared: set[str] = set()
        self.nonces: dict[str, tuple[str, str, float]] = {}       # nonce -> (agent_id, purpose, expires)
        for rec in store.of_types("agent_register", "agent_rotate", "agent_revoke", "agent_identity_update"):
            self.apply(rec)

    def apply(self, rec: dict) -> None:
        """Fold one sealed agent_* record into the registry (the verifier's state machine, K-K3)."""
        x, aid = (json.loads(rec["ext"]) if rec["ext"] else {}), rec["agent_id"]
        if rec["type"] == "agent_register":
            self.agents[aid] = Agent(x["auth"], x.get("agent_pubkey", ""), x["registered_by"],
                                     oidc_binding=x.get("oidc_binding", {}))
            for identity in x.get("runtime_identities", []):
                self.declare(identity)
        elif rec["type"] == "agent_rotate":
            self.agents[aid].pubkey = x["new_pubkey"]
        elif rec["type"] == "agent_revoke":
            self.agents[aid].revoked = True
        elif x.get("action") == "add":
            self.declare(x.get("runtime_identity"))

    def declare(self, identity) -> None:
        if isinstance(identity, dict) and isinstance(identity.get("identifier"), str):
            syntax = ID_SYNTAX.get(identity.get("scheme"))
            if syntax and re.fullmatch(syntax, identity["identifier"]):
                self.declared.add(identity["identifier"])

    def id_ok(self, agent_id) -> bool:
        """The writer is stateless and the chain append-only: an id the verifier's I2 would refuse must
        never be sealed, or the ledger fails verification for good (M2a final review)."""
        return isinstance(agent_id, str) and bool(SPIFFE.fullmatch(agent_id) or agent_id in self.declared)

    def unregistered(self, agent_id: str) -> None:
        if agent_id in self.agents:
            raise HTTPException(409, "agent already registered")

    def current(self, agent_id: str, pubkey: str) -> None:
        """409 unless the agent is still unrevoked under `pubkey` (a concurrent rotate or revoke won)."""
        a = self.agents[agent_id]
        if a.revoked:
            raise HTTPException(409, "agent already revoked")
        if a.pubkey != pubkey:
            raise HTTPException(409, "agent key changed; retry")

    def active(self, agent_id: str) -> Agent:
        a = self.agents.get(agent_id)
        if a is None:
            raise HTTPException(401, "agent not registered")
        if a.revoked:
            raise HTTPException(401, "agent revoked")
        return a

    def challenge(self, agent_id: str, purpose: str) -> dict:
        now = clock()
        self.nonces = {k: v for k, v in self.nonces.items() if v[2] > now}
        nonce = secrets.token_hex(32)
        self.nonces[nonce] = (agent_id, purpose, now + NONCE_TTL_S)
        return {"nonce": nonce, "expires_at": ts_at(now + NONCE_TTL_S)}

    def burn(self, nonce, agent_id: str, purpose: str) -> None:
        """Single use: the nonce is removed whether or not it matches."""
        entry = self.nonces.pop(nonce, None) if isinstance(nonce, str) else None
        if entry is None or entry[:2] != (agent_id, purpose):
            raise HTTPException(401, "nonce invalid")
        if entry[2] <= clock():
            raise HTTPException(401, "nonce expired")


async def body_of(request: Request) -> dict:
    try:
        b = await request.json()
    except ValueError:
        b = None
    if not isinstance(b, dict):
        raise HTTPException(400, "body must be a JSON object")
    return b


def router(require_admin) -> APIRouter:
    r = APIRouter()

    def node(request: Request):
        return request.app.state.node

    def require_token(request: Request) -> None:
        """X-Sijil-Token (spec §5.6). Unset means disabled, never open (pilot secure defaults)."""
        want = node(request).settings.agent_token
        if not want:
            raise HTTPException(503, "agent endpoints disabled: set SIJILL_TOKEN")
        if not hmac.compare_digest(request.headers.get("x-sijil-token", "").encode(), want.encode()):
            raise HTTPException(401, "X-Sijil-Token required")

    def registrar(request: Request) -> str:
        """principal_auth for register: open -> none; closed -> the admin bearer token, an operator key."""
        if node(request).policy.agents.register_policy == "closed":
            require_admin(request)
            return "key"
        return "none"

    def principal_arg(b: dict, key: str) -> str:
        p = b.get(key)
        if not isinstance(p, str) or not record._PRINCIPAL.fullmatch(p):
            raise HTTPException(400, f"{key} must be a principal (oidc:, email:, local: or human:)")
        return p

    @r.post("/api/agent/challenge", dependencies=[Depends(require_token)])
    async def challenge(request: Request):
        b = await body_of(request)
        n, purpose = node(request), b.get("purpose", "session")
        if purpose not in PURPOSES:
            raise HTTPException(400, f"purpose must be one of {PURPOSES}")
        if not n.agents.id_ok(b.get("agent_id")):
            raise HTTPException(422, "agent_id must be spiffe://<trust-domain>/agent/<name> or declared on the chain")
        return n.agents.challenge(b["agent_id"], purpose)

    @r.post("/api/agent/session", dependencies=[Depends(require_token)])
    async def session(request: Request):
        b = await body_of(request)
        n, aid = node(request), b.get("agent_id")
        n.agents.burn(b.get("nonce"), aid, "session")
        a = n.agents.active(aid)
        if a.auth != "key":
            raise HTTPException(401, "agent is not registered with a key")
        msg = {"agent_id": aid, "node_id": n.policy.node_id, "nonce": b["nonce"], "purpose": "session"}
        if not proof_ok(a.pubkey, b.get("proof"), msg):
            raise HTTPException(401, "proof invalid")
        return open_session(n, request, aid, a.registered_by, "key", "none")

    @r.post("/api/agent/register", dependencies=[Depends(require_token)])
    async def register(request: Request):
        b = await body_of(request)
        n, aid = node(request), b.get("agent_id")
        principal_auth = registrar(request)
        if not n.agents.id_ok(aid):
            raise HTTPException(422, "agent_id must be spiffe://<trust-domain>/agent/<name> or declared on the chain")
        n.agents.unregistered(aid)
        registered_by = principal_arg(b, "registered_by")
        pub = b.get("agent_pubkey")
        if not isinstance(pub, str) or not PUBKEY.fullmatch(pub):
            raise HTTPException(400, "agent_pubkey must be 32 bytes, lower-case hex")
        n.agents.burn(b.get("nonce"), aid, "register")
        msg = {"agent_id": aid, "agent_pubkey": pub, "nonce": b["nonce"], "registered_by": registered_by}
        if not proof_ok(pub, b.get("self_proof"), msg):
            raise HTTPException(401, "proof invalid")
        x = {"auth": "key", "agent_pubkey": pub, "nonce": b["nonce"], "registered_by": registered_by,
             "self_proof": b["self_proof"], "principal_auth": principal_auth, "id_form": "spiffe"}
        if isinstance(b.get("display_name"), str) and b["display_name"]:
            x["display_name"] = b["display_name"][:64]
        return await seal_agent(n, "agent_register", aid, registered_by, digest(msg), x,
                                check=lambda: n.agents.unregistered(aid))

    @r.post("/api/agent/rotate", dependencies=[Depends(require_token)])
    async def rotate(request: Request):
        b = await body_of(request)
        n, aid = node(request), b.get("agent_id")
        a = n.agents.active(aid)
        if a.auth != "key":
            raise HTTPException(409, "only a key agent rotates")
        rotated_by, new = principal_arg(b, "rotated_by"), b.get("new_pubkey")
        if not isinstance(new, str) or not PUBKEY.fullmatch(new):
            raise HTTPException(400, "new_pubkey must be 32 bytes, lower-case hex")
        n.agents.burn(b.get("nonce"), aid, "rotate")
        msg = {"agent_id": aid, "new_pubkey": new, "nonce": b["nonce"], "old_pubkey": a.pubkey}
        if not (proof_ok(a.pubkey, b.get("proof_old"), msg) and proof_ok(new, b.get("proof_new"), msg)):
            raise HTTPException(401, "proof invalid")
        x = {"old_pubkey": a.pubkey, "new_pubkey": new, "nonce": b["nonce"], "proof_old": b["proof_old"],
             "proof_new": b["proof_new"], "rotated_by": rotated_by, "principal_auth": "none"}
        return await seal_agent(n, "agent_rotate", aid, rotated_by, digest(msg), x,
                                check=lambda: n.agents.current(aid, a.pubkey))

    @r.post("/api/agent/revoke", dependencies=[Depends(require_admin)])
    async def revoke(request: Request):
        b = await body_of(request)
        n, aid = node(request), b.get("agent_id")
        a = n.agents.agents.get(aid)
        if a is None:
            raise HTTPException(404, "agent not registered")
        n.agents.current(aid, a.pubkey)
        revoked_by = principal_arg(b, "revoked_by")
        x = {"pubkey": a.pubkey, "revoked_by": revoked_by, "principal_auth": "key"}
        if isinstance(b.get("reason"), str) and b["reason"]:
            x["reason"] = b["reason"][:128]
        return await seal_agent(n, "agent_revoke", aid, revoked_by, "", x, mode="enforce", decision="block",
                                check=lambda: n.agents.current(aid, a.pubkey))

    return r


def open_session(n, request: Request, agent_id: str, principal: str, agent_auth: str, principal_auth: str,
                 jti: str = "") -> dict:
    """agent_sessions row bound to the caller's address; the ledger, not the caller, sets both auth stamps."""
    row = {"agent_session": "as_" + secrets.token_hex(16), "agent_id": agent_id, "principal": principal,
           "agent_auth": agent_auth, "principal_auth": principal_auth, "remote_addr": request.client.host,
           "expires_at": ts_at(clock() + n.policy.agents.session_ttl_s), "jti": jti}
    n.store.add_session(row)
    return {k: row[k] for k in ("agent_session", "agent_auth", "principal", "principal_auth", "expires_at")}


async def seal_agent(n, type_: str, agent_id: str, principal: str, input_hash: str, x: dict,
                     mode: str = "record", decision: str = "allow", check=lambda: None) -> dict:
    def build() -> dict:   # under the seal lock: the registry cannot change between the check and the seal
        check()
        return n.body(n.policy, type_, agent_id=agent_id, principal=principal, input_hash=input_hash,
                      mode=mode, decision=decision, ext=cj(x))
    rec = await n.seal(build)
    n.agents.apply(rec)           # no await between the seal and this: no other seal sees a stale registry
    return {"seq": rec["seq"], "record_hash": rec["record_hash"]}
