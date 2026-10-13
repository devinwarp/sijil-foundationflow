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
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException, Request

from . import oidc, policy, record, rulepack
from .oidc import ts_at

SPIFFE = re.compile(r"spiffe://[a-z0-9.-]+/agent/[a-z0-9._-]+")      # verifier check I2
ID_SYNTAX = {"spiffe": r"spiffe://[a-z0-9.-]+/\S+", "wimse": r"wimse://[a-z0-9.-]+/\S+", "did": r"did:[a-z0-9]+:\S+",
             "entra": r"[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}", "cloud-native": r"\S{1,512}", "other": r"\S{1,512}"}
PUBKEY = HEX64 = re.compile(r"[0-9a-f]{64}")
DECIMAL = re.compile(r"[1-9][0-9]{0,17}")      # fits SQLite INTEGER
OUTCOMES = ("completed", "aborted", "blocked", "error", "timeout")
SEALABLE = ("tool_call", "tool_result", "egress", "integrity_baseline", "integrity_drift")   # row 5; approval: 18g
PARENT_TYPE = {"tool_call": "inference", "tool_result": "tool_call", "egress": "tool_call",
               "integrity_drift": "integrity_baseline"}
COUNTS = ("inference", "tool_calls", "blocked", "confirmed", "denied", "flagged", "egress")
NONCE_TTL_S = 60
PURPOSES = ("session", "register", "rotate")


def clock() -> float:
    return time.time()


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

    def by_binding(self, issuer: str, sub: str) -> str | None:
        """The oidc agent whose binding matches (exact sub_pattern, or a prefix ending in *); first registered wins."""
        for aid, a in self.agents.items():
            p = a.oidc_binding.get("sub_pattern", "")
            if (a.auth == "oidc" and not a.revoked and a.oidc_binding.get("issuer") == issuer
                    and (sub.startswith(p[:-1]) if p.endswith("*") else sub == p)):
                return aid
        return None

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


def session_of(n, request: Request) -> dict | None:
    """The agent session named by X-Sijil-Agent-Session; None when the header is absent, 401 when it is bad."""
    sid = request.headers.get("x-sijil-agent-session")
    if sid is None:
        return None
    sess = n.store.session(sid)
    if sess is None or sess["expires_at"] <= ts_at(clock()):
        raise HTTPException(401, "agent session unknown or expired")
    if sess["remote_addr"] != request.client.host:
        raise HTTPException(401, "agent session bound to another address")
    n.agents.active(sess["agent_id"])
    return sess


def task_for(n, sess: dict, task_seq) -> dict | None:
    """The open task a call belongs to: the named one, which must be this session's, or else the session's
    only open task, or None when it has none. Several open tasks and no name: 409 (spec §17.3.3)."""
    if type(task_seq) is int:
        task_seq = str(task_seq)
    if task_seq not in (None, ""):
        start = n.store.get(int(task_seq)) if isinstance(task_seq, str) and DECIMAL.fullmatch(task_seq) else None
        if (start is None or start["type"] != "task_start" or n.store.task_ended(start["seq"])
                or json.loads(start["ext"])["agent_session"] != sess["agent_session"]):
            raise HTTPException(409, "task not open in this agent session")
        return start
    open_ = n.store.open_tasks(sess["agent_session"])
    if len(open_) > 1:
        raise HTTPException(409, "task ambiguous: send X-Sijil-Task-Seq")
    return open_[0] if open_ else None


def identity(sess: dict | None, task: dict | None) -> dict:
    """Identity columns: a record inside a task carries the task's agent_id and principal (check I)."""
    if task is not None:
        return {"agent_id": task["agent_id"], "principal": task["principal"], "task_seq": str(task["seq"])}
    if sess is not None:
        return {"agent_id": sess["agent_id"], "principal": sess["principal"], "task_seq": ""}
    return {"agent_id": "", "principal": "", "task_seq": ""}


def check_parent(store, body: dict, ext: dict) -> None:
    """What the verifier's A, A2, B2, B3, C and H3 would refuse later, refused before sealing."""
    t, p = body["type"], body["parent_seq"]
    if not p:
        return                                     # record.py decides whether "" is allowed (correlation none)
    parent = store.get(int(p)) if isinstance(p, str) and DECIMAL.fullmatch(p) else None
    if t not in PARENT_TYPE:
        raise HTTPException(400, f"{t} takes no parent_seq")
    if parent is None or parent["type"] != PARENT_TYPE[t]:
        raise HTTPException(400, f"parent_seq must be the seq of an earlier {PARENT_TYPE[t]}")
    if t != "integrity_drift" and parent["task_seq"] != body["task_seq"]:
        raise HTTPException(400, "parent in a different task")
    if t == "tool_call":
        uses = json.loads(parent["ext"]).get("tool_uses", []) if parent["ext"] else []
        fits = [u for u in uses if isinstance(u, dict) and u.get("args_hash") == body["input_hash"]
                and ext.get("tool_use_id", u.get("id")) == u.get("id")]
        if not fits:
            raise HTTPException(400, "tool_call args not requested by parent")
        # one requested tool_use authorizes one tool_call: each earlier child consumed an entry (by its id, else
        # by its args_hash); under the seal lock, so two concurrent calls cannot both take the last one
        used = [(json.loads(c["ext"]).get("tool_use_id", "") if c["ext"] else "", c["input_hash"])
                for c in store.children("tool_call", p)]
        free = [u for u in fits if u.get("id") not in {i for i, _ in used if i}]
        free = free[:max(0, len(free) - sum(1 for i, h in used if not i and h == body["input_hash"]))]
        if not free:
            raise HTTPException(409, "parent already consumed")
    if t == "tool_result" and store.has_child("tool_result", p):
        raise HTTPException(409, f"duplicate tool_result for parent {p}")
    if t == "integrity_drift" and body["input_hash"] != parent["input_hash"]:
        raise HTTPException(400, "drift baseline mismatch")


def task_counts(store, task_seq: int) -> dict:
    """task_end counts, as ints, with the verifier's L2 meanings; last_seq is the task_start when empty."""
    c, last = dict.fromkeys(COUNTS, 0), task_seq
    for r in store.in_task(task_seq):
        if r["type"] == "task_end":
            continue
        conf = json.loads(r["ext"]).get("confirmation") if r["type"] == "tool_call" and r["ext"] else None
        c["inference"] += int(r["type"] == "inference")
        c["tool_calls"] += int(r["type"] == "tool_call")
        c["egress"] += int(r["type"] == "egress")
        c["blocked"] += int(r["decision"] == "block")
        c["flagged"] += int(r["decision"] == "flag")
        c["confirmed"] += int(conf == "granted")
        c["denied"] += int(conf in ("denied", "unavailable"))
        last = r["seq"]
    return {**c, "last_seq": last}


async def end_task(n, start: dict, outcome: str) -> dict:
    def build() -> dict:   # under the seal lock: no record of the task can land between count and seal
        if n.store.task_ended(start["seq"]):
            raise HTTPException(409, "task already ended")
        x = {"outcome": outcome, **task_counts(n.store, start["seq"])}
        return n.body(n.policy, "task_end", agent_id=start["agent_id"], principal=start["principal"],
                      task_seq=str(start["seq"]), ext=cj(x))
    return await n.seal(build)


async def close_expired(n) -> None:
    """Seal outcome=timeout for open tasks whose agent session expired or is unknown (spec §5.9).
    ponytail: scans every open task per call; index by expiry if open tasks reach the thousands."""
    now = ts_at(clock())
    for start in n.store.open_tasks():
        sess = n.store.session(json.loads(start["ext"])["agent_session"])
        if sess is None or sess["expires_at"] <= now:
            try:
                await end_task(n, start, "timeout")
            except HTTPException:
                pass


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

    async def require_session(request: Request) -> dict:
        n = node(request)
        await close_expired(n)
        sess = session_of(n, request)
        if sess is None:
            raise HTTPException(401, "X-Sijil-Agent-Session required")
        return sess

    async def registrar(request: Request) -> tuple[str | None, str]:
        """(registered_by or None to take the body's, principal_auth): open -> none; closed -> the admin
        bearer token, an operator key; principal_oidc -> a validated human principal token (spec §5.6)."""
        n = node(request)
        if n.policy.agents.register_policy == "closed":
            require_admin(request)
            return None, "key"
        if n.policy.agents.register_policy == "principal_oidc":
            h = await principal_or_refuse(n, request, required=True)
            return h["principal"], "oidc"
        return None, "none"

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
        if "oidc_token" in b:
            return await oidc_session(n, request, b["oidc_token"])
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
        if "oidc_binding" in b:
            require_admin(request)        # an operator act, whatever register_policy says (spec §5.8.5)
            return await register_oidc(n, aid, b, principal_arg(b, "registered_by"))
        registered_by, principal_auth = await registrar(request)
        if not n.agents.id_ok(aid):
            raise HTTPException(422, "agent_id must be spiffe://<trust-domain>/agent/<name> or declared on the chain")
        n.agents.unregistered(aid)
        registered_by = registered_by or principal_arg(b, "registered_by")
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
        old = a.pubkey      # a is the registry's live Agent: capture the key the proofs were made for
        if a.auth != "key":
            raise HTTPException(409, "only a key agent rotates")
        rotated_by, new = principal_arg(b, "rotated_by"), b.get("new_pubkey")
        if not isinstance(new, str) or not PUBKEY.fullmatch(new):
            raise HTTPException(400, "new_pubkey must be 32 bytes, lower-case hex")
        n.agents.burn(b.get("nonce"), aid, "rotate")
        msg = {"agent_id": aid, "new_pubkey": new, "nonce": b["nonce"], "old_pubkey": old}
        if not (proof_ok(old, b.get("proof_old"), msg) and proof_ok(new, b.get("proof_new"), msg)):
            raise HTTPException(401, "proof invalid")
        x = {"old_pubkey": old, "new_pubkey": new, "nonce": b["nonce"], "proof_old": b["proof_old"],
             "proof_new": b["proof_new"], "rotated_by": rotated_by, "principal_auth": "none"}
        return await seal_agent(n, "agent_rotate", aid, rotated_by, digest(msg), x,
                                check=lambda: n.agents.current(aid, old))

    @r.post("/api/agent/revoke", dependencies=[Depends(require_admin)])
    async def revoke(request: Request):
        b = await body_of(request)
        n, aid = node(request), b.get("agent_id")
        a = n.agents.agents.get(aid)
        if a is None:
            raise HTTPException(404, "agent not registered")
        old = a.pubkey
        n.agents.current(aid, old)
        revoked_by = principal_arg(b, "revoked_by")
        x = {"pubkey": old, "revoked_by": revoked_by, "principal_auth": "key"}
        if isinstance(b.get("reason"), str) and b["reason"]:
            x["reason"] = b["reason"][:128]
        return await seal_agent(n, "agent_revoke", aid, revoked_by, "", x, mode="enforce", decision="block",
                                check=lambda: n.agents.current(aid, old))

    @r.post("/api/agent/seal")
    async def seal(request: Request, sess: dict = Depends(require_session)):
        b = await body_of(request)
        n, t = node(request), b.get("type")
        if t not in SEALABLE:
            raise HTTPException(400, f"type must be one of {SEALABLE}")
        hits, x = b.get("rule_hits", []), b.get("ext", {})
        if not isinstance(hits, list) or not all(isinstance(h, str) for h in hits) or not isinstance(x, dict):
            raise HTTPException(400, "rule_hits must be a list of strings and ext an object")
        if not isinstance(b.get("rulepack_hash"), str):
            raise HTTPException(400, "rulepack_hash must be a string")
        if any(h in policy.RESERVED_IDS or h.startswith(policy.RESERVED_PREFIXES) for h in hits):
            raise HTTPException(400, "rule_hits may not carry reserved ids; the node adds those itself")
        task = task_for(n, sess, b.get("task_seq"))
        if task is None and t in record.TASK_REQUIRED:
            raise HTTPException(409, "no open task in this agent session")
        fields = {k: b.get(k, d) for k, d in (("parent_seq", ""), ("source_label", ""), ("mode", "record"),
                                              ("decision", "allow"), ("input_hash", ""), ("output_hash", ""))}
        if n.halted and t in ("tool_call", "tool_result", "egress"):   # the operator halt stops agents too
            fields.update(mode="enforce", decision="block")
            hits = [*hits, policy.HALT_HIT]
        if not all(isinstance(v, str) for v in fields.values()):
            raise HTTPException(400, "parent_seq, source_label, mode, decision, input_hash and output_hash must be strings")
        try:
            ext_json = cj(x) if x else ""
        except UnicodeEncodeError:
            raise HTTPException(400, "ext is not valid unicode")
        # agent_id and principal come from the task (or the session), never from the body (check I).
        body = n.body(n.policy, t, rule_hits=policy.rule_hits_json(hits), ext=ext_json,
                      rulepack_hash=b["rulepack_hash"], **fields, **identity(sess, task))

        def build() -> dict:
            if b["rulepack_hash"] != n.rulepack_hash:      # under the lock: a reload cannot slip in after this
                raise HTTPException(409, "rulepack mismatch")
            n.agents.active(sess["agent_id"])
            if task is not None and n.store.task_ended(task["seq"]):
                raise HTTPException(409, "task already ended")
            check_parent(n.store, body, x)
            return body
        try:
            rec = await n.seal(build)
        except rulepack.Mismatch:
            raise HTTPException(409, "rulepack mismatch")
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"seq": rec["seq"], "record_hash": rec["record_hash"], "ts": rec["ts"], "decision": rec["decision"]}

    @r.get("/api/agent/parent")
    async def parent(request: Request, tool_use_id: str = "", name: str = "", args_hash: str = "",
                     sess: dict = Depends(require_session)):
        n = node(request)
        task = task_for(n, sess, request.headers.get("x-sijil-task-seq"))
        if task is None:
            raise HTTPException(409, "no open task in this agent session")
        if not tool_use_id and not (name and args_hash):
            raise HTTPException(400, "tool_use_id, or name and args_hash, required")
        hit = n.store.tool_use(str(task["seq"]), tool_use_id, name, args_hash)
        if hit is None:   # mechanism 3 (window) never yields a parent: B2 would fail it (spec §5.4)
            raise HTTPException(404, {"correlation": "none"})
        return {**hit, "correlation": "tool_use_id" if tool_use_id else "args_hash"}

    @r.get("/api/agent/context")
    async def context(request: Request, before_seq: int, window: str = "session",
                      sess: dict = Depends(require_session)):
        n = node(request)
        task = task_for(n, sess, request.headers.get("x-sijil-task-seq"))
        if task is None:
            raise HTTPException(409, "no open task in this agent session")
        if window not in ("session", "turn"):
            raise HTTPException(400, "window must be session or turn")
        rows = [r for r in n.store.in_task(task["seq"]) if r["seq"] < before_seq]
        since = 0
        if window == "turn":   # after the last inference that requested no tools: the user's previous turn
            since = max((r["seq"] for r in rows if r["type"] == "inference"
                         and not (json.loads(r["ext"]).get("tool_uses") if r["ext"] else None)), default=0)
        results = [r for r in rows if r["type"] == "tool_result" and r["seq"] > since]
        hints = {h for r in results for h in (json.loads(r["ext"]).get("exec_hints", []) if r["ext"] else [])}
        return {"labels": sorted({r["source_label"] for r in results}), "seqs": [r["seq"] for r in results],
                "exec_hints": sorted(hints)}      # for the rules' context_exec_hints (spec §8.1)

    @r.get("/api/agent/baseline")
    async def baseline(request: Request, lockfile_hash: str, sess: dict = Depends(require_session)):
        """The baseline a guard's integrity_drift points at (spec §2.4.5, check C)."""
        seq = node(request).store.baseline(lockfile_hash)
        if seq is None:
            raise HTTPException(404, "no integrity_baseline for that lockfile_hash")
        return {"seq": seq}

    @r.post("/api/agent/task/start")
    async def task_start(request: Request, sess: dict = Depends(require_session)):
        b = await body_of(request)
        n = node(request)
        intent = b.get("intent_hash")
        if not isinstance(intent, str) or not HEX64.fullmatch(intent):
            raise HTTPException(400, "intent_hash must be 64 lower-case hex")
        d = b.get("delegated_from", "")
        parent = n.store.get(int(d)) if isinstance(d, str) and DECIMAL.fullmatch(d) else None
        if d != "" and (parent is None or parent["type"] != "task_start"):
            raise HTTPException(400, "delegated_from must be the seq of an earlier task_start")
        x = {k: b.get(k, "") for k in ("harness", "session_id", "repo", "commit", "lockfile_hash")}
        x.update({k: b[k] for k in ("cwd", "config_digest") if isinstance(b.get(k), str) and b[k]})
        if not all(isinstance(v, str) for v in x.values()):
            raise HTTPException(400, "task fields must be strings")
        # Stamped by the ledger from the session, never taken from the request (spec §5.8.1). A principal
        # token fixes a human principal for the whole task (§17.2.8); its refusal is not sealed (Ruling 12).
        principal, principal_auth = sess["principal"], sess["principal_auth"]
        h = await principal_or_refuse(n, request, required=False)
        if h is not None:
            principal, principal_auth, x["principal_claims"] = h["principal"], "oidc", h["claims"]
        x.update(intent_hash=intent, delegated_from=d, agent_auth=sess["agent_auth"],
                 principal_auth=principal_auth, agent_session=sess["agent_session"])
        def build() -> dict:   # under the seal lock: a revoke cannot land between this check and the seal
            n.agents.active(sess["agent_id"])
            return n.body(n.policy, "task_start", agent_id=sess["agent_id"], principal=principal,
                          input_hash=intent, ext=cj(x))
        try:
            rec = await n.seal(build)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"seq": rec["seq"], "record_hash": rec["record_hash"]}

    @r.post("/api/agent/task/end")
    async def task_end(request: Request, sess: dict = Depends(require_session)):
        b = await body_of(request)
        n = node(request)
        if b.get("outcome") not in OUTCOMES:
            raise HTTPException(400, f"outcome must be one of {OUTCOMES}")
        start = task_for(n, sess, str(b.get("task_seq", "")))
        if start is None:
            raise HTTPException(409, "no open task in this agent session")
        rec = await end_task(n, start, b["outcome"])
        return {"seq": rec["seq"], "record_hash": rec["record_hash"], **{k: v for k, v in json.loads(rec["ext"]).items()
                                                                          if k != "outcome"}}

    return r


async def principal_or_refuse(n, request: Request, required: bool) -> dict | None:
    """Validated human principal from the request's principal token; HTTP refusal (unsealed) otherwise."""
    try:
        h = await n.human(request, None)
        if required and h is None:
            raise oidc.OidcError("missing")
        return h
    except oidc.OidcError as e:
        raise HTTPException(e.status, {"principal_error": e.code, "rule_hits": [oidc.hit(e.code)]})


async def oidc_session(n, request: Request, token) -> dict:
    """Workload token -> session for the registered oidc agent whose binding matches its sub (spec §5.8.5)."""
    issuers = {c["issuer"]: c for c in n.policy.agents.oidc_issuers}
    try:
        v = await oidc.validate(token, issuers, n.jwks, clock())
    except oidc.OidcError as e:
        raise HTTPException(e.status, f"oidc token refused: {e.code}")
    jti, sub = v.claims.get("jti") or v.claims.get("uti"), v.claims.get("sub")
    if not isinstance(jti, str) or not jti:
        raise HTTPException(401, "oidc token refused: no jti or uti")
    if n.store.jti_used(jti):
        raise HTTPException(401, "oidc token refused: replayed")
    if not isinstance(sub, str) or not re.fullmatch(r"\S{1,256}", sub):
        raise HTTPException(401, "oidc token refused: sub")
    aid = n.agents.by_binding(v.cfg["issuer"], sub)
    if aid is None:
        raise HTTPException(401, "no oidc agent registered for this sub")
    principal = f"oidc:{urlsplit(v.cfg['issuer']).hostname}:{sub}"
    return open_session(n, request, aid, principal, "oidc", "oidc", jti)


async def register_oidc(n, aid, b: dict, registered_by: str) -> dict:
    if not n.agents.id_ok(aid):
        raise HTTPException(422, "agent_id must be spiffe://<trust-domain>/agent/<name> or declared on the chain")
    n.agents.unregistered(aid)
    binding = b["oidc_binding"]
    if (not isinstance(binding, dict) or set(binding) != {"issuer", "sub_pattern"}
            or not isinstance(binding["issuer"], str)
            or binding["issuer"] not in {c["issuer"] for c in n.policy.agents.oidc_issuers}
            or not isinstance(binding["sub_pattern"], str) or not binding["sub_pattern"]):
        raise HTTPException(400, "oidc_binding must be {issuer, sub_pattern} for an issuer in agents.oidc_issuers")
    x = {"auth": "oidc", "oidc_binding": binding, "registered_by": registered_by, "principal_auth": "key",
         "id_form": "spiffe"}
    return await seal_agent(n, "agent_register", aid, registered_by, "", x, check=lambda: n.agents.unregistered(aid))


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
