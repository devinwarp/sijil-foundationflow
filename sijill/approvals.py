"""Named human approval on the ledger (spec §17.5): the approval request and decision records, the approver's
Entra token and role, separation of duties, and the deadline, which the ledger owns. BSL.

Pending approvals live in process memory like the agent registry and are rebuilt from the chain at startup. A
deadline that passed while the ledger was down is sealed as a timeout at startup (§17.5.2 step 5).
"""

import asyncio
import json
import os
import re
import secrets
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse

from . import agents, oidc, policy, record

PAGE = Path(__file__).resolve().parent.parent / "dashboard" / "approval.html"
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"          # Crockford base32: ^ap_[0-9A-Z]{26}$
MAX_WAIT_S = 25                                        # one long-poll; the guard asks again
HEX64 = re.compile(r"[0-9a-f]{64}")
_background: set = set()                               # notifications in flight (the loop holds tasks weakly)


def ts_ms(ts: str) -> int:
    return round(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000)


def ms_ts(ms: int) -> str:
    """record.now_ts() form of an integer millisecond instant, without float rounding."""
    t = datetime.fromtimestamp(ms // 1000, timezone.utc).replace(microsecond=ms % 1000 * 1000)
    return t.isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class Pending:
    """One approval request and, once sealed, its decision."""
    request: dict                                      # the sealed request record
    deadline: str                                      # request ts + timeout_ms, in the ts form
    arg_keys: list = field(default_factory=list)       # for the page only, never sealed
    outcome: str = ""                                  # "" while pending
    decision_seq: int | None = None
    event: asyncio.Event = field(default_factory=asyncio.Event)
    timer: asyncio.Task | None = None

    @property
    def x(self) -> dict:
        return json.loads(self.request["ext"])

    def view(self) -> dict:
        return {"approval_id": self.x["approval_id"], "status": self.outcome or "pending", "deadline": self.deadline,
                "request_seq": self.request["seq"], "decision_seq": self.decision_seq}


class Approvals:
    """approval_id -> Pending, folded from the chain's approval records."""

    def __init__(self, store):
        self.items: dict[str, Pending] = {}
        for rec in store.of_types("approval"):
            self.apply(rec)

    def apply(self, rec: dict) -> Pending:
        x = json.loads(rec["ext"])
        if x["phase"] == "request":
            p = Pending(rec, ms_ts(ts_ms(rec["ts"]) + x["timeout_ms"]))
            self.items[x["approval_id"]] = p
        else:
            p = self.items[x["approval_id"]]
            p.outcome, p.decision_seq = x["outcome"], rec["seq"]
            p.event.set()
        return p

    def pending_in(self, task_seq: int) -> bool:
        return any(not p.outcome and p.request["task_seq"] == str(task_seq) for p in self.items.values())


def new_id() -> str:
    return "ap_" + "".join(secrets.choice(ALPHABET) for _ in range(26))


def body_of(n, p: Pending, outcome: str, ts: str, x: dict, output_hash: str = "", hits: list | None = None) -> dict:
    req = p.request
    mode, decision = ("record", "allow") if outcome == "granted" else ("enforce", "block")
    return {**n.body(n.policy, "approval", mode=mode, decision=decision, rule_hits=policy.rule_hits_json(hits or []),
                     input_hash=req["input_hash"], output_hash=output_hash, parent_seq=str(req["seq"]),
                     agent_id=req["agent_id"], principal=req["principal"], task_seq=req["task_seq"],
                     ext=agents.cj({"phase": "decision", "approval_id": p.x["approval_id"], "outcome": outcome, **x})),
            "ts": ts}


async def seal_timeout(n, p: Pending) -> None:
    """The ledger's timer: at the deadline, an unanswered request is sealed outcome timeout (§17.5.2 step 5)."""
    while not p.outcome:
        wait = (ts_ms(p.deadline) - ts_ms(record.now_ts())) / 1000
        if wait > 0:
            await asyncio.sleep(wait)
            continue

        def build() -> dict:
            ts = record.now_ts()
            if p.outcome or ts < p.deadline:
                raise _NotYet
            return body_of(n, p, "timeout", ts, {}, hits=["approval-timeout"])
        try:
            n.approvals.apply(await n.seal(build))
        except _NotYet:
            continue
        except Exception as e:      # a locked store or a signer outage: the timer must outlive it, or the
            print(f"sijill: approval timeout not sealed, retrying: {e!r}", file=sys.stderr)   # request never closes
            await asyncio.sleep(1)


class _NotYet(Exception):
    """Decided meanwhile, or the clock is not yet at the deadline: nothing to seal."""


def schedule(n, p: Pending) -> None:
    if not p.outcome:
        p.timer = asyncio.get_running_loop().create_task(seal_timeout(n, p))


async def start(n) -> None:
    """Startup: every request still pending gets its timer; one already past its deadline is sealed now."""
    if n.rulepack and n.rulepack.hitl and n.rulepack.hitl.channel == "entra" and not n.settings.public_url:
        print("sijill: SIJILL_PUBLIC_URL is empty: approval notifications cannot carry a link and are not sent",
              file=sys.stderr)
    for p in list(n.approvals.items.values()):
        schedule(n, p)


def stop(n) -> None:
    for p in n.approvals.items.values():
        if p.timer:
            p.timer.cancel()


async def notify(n, p: Pending) -> None:
    """Teams incoming webhook: delivery only, never evidence; a failure changes nothing (§17.5.1 notify)."""
    env = n.rulepack.hitl.teams_webhook_env if n.rulepack and n.rulepack.hitl else ""
    url = os.environ.get(env) if env else None
    if not url:
        return
    if not n.settings.public_url:
        print("sijill: approval notification skipped: SIJILL_PUBLIC_URL is empty", file=sys.stderr)
        return
    x = p.x
    link = f"{n.settings.public_url.rstrip('/')}/approval/{x['approval_id']}"
    text = (f"Sijil approval needed: {x['tool']} on {x['server']} (route {x['route_id']}, rules "
            f"{', '.join(json.loads(p.request['rule_hits']))}). Answer before {p.deadline}: {link}")
    try:
        await n.idp.post(url, json={"text": text})
    except Exception as e:          # an invalid URL as much as a network error: delivery only, never fatal
        print(f"sijill: approval notification failed: {e!r}", file=sys.stderr)


async def request_approval(n, sess: dict | None, task: dict, b: dict) -> Pending:
    """Seal an approval request for a tool call whose strictest action is confirm (§17.5.2 step 2). The route is
    the pack's first match over the hits; a route_id the caller names must be that one."""
    pack = n.rulepack
    if pack is None or pack.hitl is None or pack.hitl.channel != "entra":
        raise HTTPException(409, "named approval is not configured (rule pack hitl.channel: entra)")
    hits = b.get("rule_hits")
    if not isinstance(hits, list) or not hits or not all(isinstance(h, str) for h in hits):
        raise HTTPException(400, "rule_hits must be a non-empty list of rule ids")
    if pack.confirm_hits(hits) != hits:
        raise HTTPException(400, "rule_hits must be confirm rules of the pack in force or confirm budgets")
    route = pack.route(hits)
    if route is None:
        raise HTTPException(409, "no hitl route matches these rule_hits")
    if b.get("route_id") not in (None, route.id):
        raise HTTPException(400, f"route_id must be {route.id}, the first route that matches")
    keys = ("tool", "server", "qualified", "correlation", "parent_seq", "input_hash")
    if not all(isinstance(b.get(k), str) for k in keys) or not HEX64.fullmatch(b["input_hash"]):
        raise HTTPException(400, f"{', '.join(keys)} must be strings; input_hash 64 lower-case hex")
    arg_keys = b.get("arg_keys", [])
    if not isinstance(arg_keys, list) or not all(isinstance(k, str) for k in arg_keys):
        raise HTTPException(400, "arg_keys must be a list of strings")
    who = {"role": route.role} if route.role else {"oids_sha256": sorted(record.sha256_hex(o.encode()) for o in route.oids)}
    x = {"phase": "request", "approval_id": new_id(), "tool": b["tool"], "server": b["server"],
         "qualified": b["qualified"], "correlation": b["correlation"], "route_id": route.id, "approver_set": who,
         "min_assurance": route.min_assurance, "timeout_ms": route.timeout_seconds * 1000, "on_timeout": "deny",
         "sod": pack.hitl.separation_of_duties}
    body = n.body(n.policy, "approval", decision="flag", rule_hits=policy.rule_hits_json(hits), parent_seq=b["parent_seq"],
                  input_hash=b["input_hash"], ext=agents.cj(x), agent_id=task["agent_id"], principal=task["principal"],
                  task_seq=str(task["seq"]))

    def build() -> dict:     # under the seal lock: the task cannot end and the parent cannot change meanwhile
        if sess is not None:
            n.agents.active(sess["agent_id"])
        if n.store.task_ended(task["seq"]):
            raise HTTPException(409, "task already ended")
        agents.check_parent(n.store, {**body, "type": "tool_call"}, {})   # the call's parent rules (check V)
        return body
    try:
        rec = await n.seal(build)
    except ValueError as e:
        raise HTTPException(400, str(e))
    p = n.approvals.apply(rec)
    p.arg_keys = sorted(arg_keys)
    schedule(n, p)
    task_ = asyncio.get_running_loop().create_task(notify(n, p))
    _background.add(task_)
    task_.add_done_callback(_background.discard)
    return p


async def long_poll(p: Pending, seconds: float) -> dict:
    if not p.outcome and seconds > 0:
        try:
            await asyncio.wait_for(p.event.wait(), min(seconds, MAX_WAIT_S))
        except asyncio.TimeoutError:
            pass
    return p.view()


async def decide(n, p: Pending, b: dict) -> dict:
    """§17.5.2 step 4: the approver's token, the route's role or object ids, assurance, separation of duties, and
    the deadline, all before anything is sealed. A refusal of the answer is an HTTP error and seals nothing."""
    if b.get("decision") not in ("grant", "refuse"):
        raise HTTPException(400, "decision must be grant or refuse")
    reason = b.get("reason", "")
    if not isinstance(reason, str) or len(reason) > 1024:
        raise HTTPException(400, "reason must be a string of at most 1024 characters")
    if p.outcome:
        raise HTTPException(409, f"already decided: {p.outcome}")
    hitl, pcfg = n.rulepack.hitl if n.rulepack else None, n.policy.principals
    issuer = next((i for i in (pcfg.issuers if pcfg else ()) if hitl and i["id"] == hitl.issuer_id), None)
    if issuer is None:
        raise HTTPException(409, "named approval is not configured")
    approvers = policy.PrincipalsConfig(min_assurance="low", issuers=({**issuer, "audience": hitl.audience},))
    try:
        h = await oidc.human(approvers, n.jwks, b.get("token"), agents.clock())
    except oidc.OidcError as e:
        raise HTTPException(e.status, {"approval_error": e.code})
    req, raw = p.x, h["raw"]
    if "role" in req["approver_set"]:
        roles = raw.get("roles") if isinstance(raw.get("roles"), list) else []
        if req["approver_set"]["role"] not in roles:
            raise HTTPException(403, {"approval_error": "role"})
        matched = [req["approver_set"]["role"]]
    else:
        oid = raw.get("oid")
        if not isinstance(oid, str) or record.sha256_hex(oid.encode()) not in req["approver_set"]["oids_sha256"]:
            raise HTTPException(403, {"approval_error": "approver"})
        matched = []
    levels = record.PRINCIPAL_ASSURANCE
    if levels.index(h["claims"]["assurance"]) < levels.index(req["min_assurance"]):
        raise HTTPException(403, {"approval_error": "assurance"})
    if req["sod"] and h["principal"] == p.request["principal"]:
        raise HTTPException(403, {"approval_error": "separation_of_duties"})
    outcome = "granted" if b["decision"] == "grant" else "refused"
    x = {"approver": h["principal"], "approver_claims": {**h["claims"], "roles_matched": matched}}

    def build() -> dict:
        ts = record.now_ts()          # taken under the lock and sealed as is: the deadline test is the record's
        if p.outcome:
            raise HTTPException(409, f"already decided: {p.outcome}")
        if ts >= p.deadline:
            raise HTTPException(410, "deadline passed")
        return body_of(n, p, outcome, ts, x, record.output_hash(reason) if reason else "")
    rec = await n.seal(build)
    n.approvals.apply(rec)
    if h["display"]:
        n.store.index_principal(h["principal"], h["display"])
    return {"seq": rec["seq"], "outcome": outcome}


def router() -> APIRouter:
    r = APIRouter()

    def node(request: Request):
        return request.app.state.node

    def pending(request: Request, approval_id: str) -> Pending:
        p = node(request).approvals.items.get(approval_id)
        if p is None:
            raise HTTPException(404, "no such approval")
        return p

    @r.post("/api/agent/approval/request")
    async def create(request: Request, sess: dict = Depends(agents.require_session)):
        b = await agents.body_of(request)
        n = node(request)
        task = agents.task_for(n, sess, b.get("task_seq"))
        if task is None:
            raise HTTPException(409, "no open task in this agent session")
        p = await request_approval(n, sess, task, b)
        return {"approval_id": p.x["approval_id"], "seq": p.request["seq"], "deadline": p.deadline}

    @r.get("/api/agent/approval/{approval_id}")
    async def status(request: Request, approval_id: str, wait: float = 0,
                     sess: dict = Depends(agents.require_session)):
        p = pending(request, approval_id)
        if p.request["agent_id"] != sess["agent_id"]:
            raise HTTPException(404, "no such approval")
        return await long_poll(p, wait)

    @r.get("/api/approval/{approval_id}")
    async def page_data(request: Request, approval_id: str):
        """What the approval page shows: names and keys, never argument values (§17.5.2 step 3)."""
        p = pending(request, approval_id)
        x = p.x
        return {**p.view(), **{k: x[k] for k in ("tool", "server", "qualified", "route_id", "min_assurance")},
                "rule_hits": json.loads(p.request["rule_hits"]), "arg_keys": p.arg_keys}

    @r.post("/api/approval/{approval_id}/decide")
    async def answer(request: Request, approval_id: str):
        return await decide(node(request), pending(request, approval_id), await agents.body_of(request))

    @r.get("/approval/{approval_id}")
    async def page(approval_id: str):
        return FileResponse(PAGE)

    return r
