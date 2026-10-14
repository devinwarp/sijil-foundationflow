"""Sijill proxy: evaluate every chat completion against policy, forward or block, seal a record.

Run a single worker (records are sealed under an in-process lock):

    uvicorn sijill.proxy:app --port 8000 --env-file .env.local

Admin endpoints require `Authorization: Bearer $SIJILL_ADMIN_TOKEN`; with no token set they are disabled.
"""

import asyncio
import hashlib
import hmac
import json
import os
import sys
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

import anyio
import httpx
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from . import agents, approvals, budgets, chat, foundry, keys, oidc, policy, record, rulepack
from .digest import DigestResolver
from .store import Store

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "verifier" / "sijill_verify.py"
REPORT = ROOT / "report" / "generate.py"

# Error type used in {"error": {"type": ...}} bodies when the model runtime failed.
UPSTREAM_ERROR_TYPE = "upstream_error"
DASHBOARD = ROOT / "dashboard" / "index.html"


def error_content(raw: bytes):
    """A model runtime's error answer, relayed as it parsed; one that does not parse is relayed as text."""
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        return {"error": {"message": raw.decode(errors="replace")}}


@dataclass
class Settings:
    db_path: str = "sijill.db"
    policy_path: str = "policy.yaml"
    rulepack_path: str = ""            # "" = no rule pack; records keep rulepack_hash "" (M1 behaviour)
    key_path: str = "node.key"
    pubkey_path: str = "node.pub"
    upstream: str = "http://localhost:1234/v1"
    upstream_token: str = ""
    upstream_provider: str = ""        # <provider> in api:<provider>:<model> (spec §3.1: from the route)
    default_model: str = "llama-3.2-3b-instruct"
    upstream_timeout: float = 120.0
    admin_token: str = ""
    agent_token: str = ""              # X-Sijil-Token for /api/agent/*; "" disables those endpoints
    pkcs11_module: str = ""
    pkcs11_token: str = ""
    pkcs11_key: str = ""
    pkcs11_pin: str = ""
    halt_path: str = "sijill.halt"
    digest_cache: str = ".sijill_digests.json"
    jwks_dir: str = "jwks"             # JWKS snapshots by hash (spec §17.2.6); not evidence
    public_url: str = ""               # this ledger's URL as approvers reach it, for approval links (spec §17.5.2)

    @classmethod
    def from_env(cls) -> "Settings":
        e = os.environ.get
        return cls(
            db_path=e("DATABASE_PATH", cls.db_path),
            policy_path=e("POLICY_PATH", cls.policy_path),
            rulepack_path=e("SIJILL_RULEPACK_PATH", ""),
            key_path=e("NODE_KEY_PATH", cls.key_path),
            pubkey_path=e("NODE_PUBKEY_PATH", cls.pubkey_path),
            upstream=e("LMSTUDIO_BASE_URL", cls.upstream),
            upstream_token=e("LM_API_TOKEN", ""),
            upstream_provider=e("SIJILL_UPSTREAM_PROVIDER", ""),
            default_model=e("SIJILL_MODEL", cls.default_model),
            upstream_timeout=float(e("UPSTREAM_TIMEOUT", cls.upstream_timeout)),
            admin_token=e("SIJILL_ADMIN_TOKEN", ""),
            agent_token=e("SIJILL_TOKEN", ""),
            pkcs11_module=e("SIJILL_PKCS11_MODULE", ""),
            pkcs11_token=e("SIJILL_PKCS11_TOKEN", ""),
            pkcs11_key=e("SIJILL_PKCS11_KEY", ""),
            pkcs11_pin=e("SIJILL_PKCS11_PIN", ""),
            halt_path=e("SIJILL_HALT_PATH", cls.halt_path),
            digest_cache=e("SIJILL_DIGEST_CACHE", cls.digest_cache),
            jwks_dir=e("SIJILL_JWKS_DIR", cls.jwks_dir),
            public_url=e("SIJILL_PUBLIC_URL", ""),
        )


class Node:
    """Runtime state: the chain head, the policy and rule pack in force and the node's current region."""

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None,
                 resolver: DigestResolver | None = None, idp_transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.store = Store(settings.db_path)
        if settings.pkcs11_module:
            # No fallback to a key file: a configured HSM that fails is a startup error.
            from .hsm import Pkcs11Signer
            self.key = Pkcs11Signer(settings.pkcs11_module, settings.pkcs11_token,
                                    settings.pkcs11_key, settings.pkcs11_pin)
            pem = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_path = Path(settings.pubkey_path)
            if self.store.last() and pub_path.exists() and pub_path.read_bytes() != pem:
                # Overwriting node.pub would make every earlier record fail verification.
                self.key.close()
                self.store.close()
                raise RuntimeError(f"chain in {settings.db_path} was signed by a different key than the HSM "
                                   f"key; start a new database to rotate to the HSM key")
            pub_path.write_bytes(pem)
        else:
            self.key = keys.load_or_generate(settings.key_path, settings.pubkey_path)
        self.policy = policy.load(settings.policy_path)
        self.check_attestation(self.policy)
        last = self.store.last()
        self.region = last["node_region"] if last else self.policy.node_region
        # The rule pack hash in force on the chain; it moves only when a rulepack_change is sealed.
        self.rulepack_hash = last["rulepack_hash"] if last else ""
        self.rulepack = rulepack.load(settings.rulepack_path) if settings.rulepack_path else None
        if self.rulepack is None and self.rulepack_hash:
            self.store.close()
            raise RuntimeError(f"chain in {settings.db_path} is under rule pack {self.rulepack_hash[:12]}; set "
                               f"SIJILL_RULEPACK_PATH (a record without rulepack_hash fails check E)")
        try:
            rulepack.check_policy(self.rulepack, self.policy)
        except ValueError:
            self.store.close()
            raise
        # The writer trusts its own memory of the head, not the database: a record
        # deleted or edited at the tail while running still shows up as a break.
        self.head = self.store.head()
        self.agents = agents.Registry(self.store)
        self.approvals = approvals.Approvals(self.store)
        self.lock = asyncio.Lock()
        self.halted = Path(settings.halt_path).exists()
        self.resolver = resolver or DigestResolver(cache_path=settings.digest_cache)
        headers = {"Authorization": f"Bearer {settings.upstream_token}"} if settings.upstream_token else {}
        self.client = httpx.AsyncClient(base_url=settings.upstream, headers=headers,
                                        timeout=settings.upstream_timeout, transport=transport)
        # discovery, JWKS and approval notifications (spec §17.5.1 notify); nothing the model sees
        self.idp = httpx.AsyncClient(timeout=10.0, transport=idp_transport)
        f = self.policy.foundry        # the Responses relay's upstream (spec §17.4.2); a change needs a restart
        self.foundry = httpx.AsyncClient(base_url=f.endpoint, timeout=settings.upstream_timeout,
                                         transport=transport) if f else None
        self.jwks = self.keys_for(self.policy)

    def keys_for(self, pol: policy.Policy) -> dict:
        """JWKS caches for every issuer the policy names; a pinned file that fails its sha256 raises."""
        humans = pol.principals.issuers if pol.principals else ()
        return oidc.build_jwks([*pol.agents.oidc_issuers, *humans], self.settings.jwks_dir, self.idp)

    async def human(self, request: Request, task: dict | None, margin: float = 0.0) -> dict | None:
        """The validated human principal of a call (spec §17.2), bound to its task (§17.2.8). None when no
        principals: block is configured, or a token is optional and absent. Raises oidc.OidcError."""
        pcfg = self.policy.principals
        if pcfg is None:
            return None
        token = oidc.token_of(pcfg, request.headers)
        bound = task is not None and task["principal"].startswith("human:")
        if token is None and not pcfg.require and not bound:
            return None
        h = await oidc.human(pcfg, self.jwks, token, agents.clock(), margin)
        if task is not None and h["principal"] != task["principal"]:
            raise oidc.OidcError("task_principal", 409, h["principal"])
        if h["display"]:
            self.store.index_principal(h["principal"], h["display"])
        return h

    def check_attestation(self, pol: policy.Policy) -> None:
        """attestation: api needs the provider of the upstream route; it is never taken from the request."""
        if pol.attestation == "api" and not chat.PROVIDER.fullmatch(self.settings.upstream_provider):
            raise ValueError("attestation: api needs SIJILL_UPSTREAM_PROVIDER ([a-z0-9-]+), the upstream's provider")

    def api_digest(self, model: str) -> str:
        return f"api:{self.settings.upstream_provider}:{model}"

    def body(self, pol: policy.Policy, type_: str, **fields) -> dict:
        base = dict(type=type_, model_id="", model_digest="", node_id=pol.node_id, node_region=self.region,
                    policy_id=pol.policy_id, policy_hash=pol.hash, approval_ref=pol.approval_ref,
                    mode="record", decision="allow", rule_hits="[]", input_hash="", output_hash="",
                    **{f: "" for f in record.EXT_FIELDS})   # v2 columns; set by the rows that use them
        return {**base, **fields}

    async def seal(self, body) -> dict:
        """`body` may be a callable that builds it under the lock, for bodies whose checks read state that a
        concurrent seal could change (agent registry, task_end counts)."""
        async with self.lock:
            if callable(body):
                body = body()
            if body["type"] != "rulepack_change":
                # Stamped under the lock so no record lands between a rulepack_change and its hash (check E).
                if body["rulepack_hash"] not in ("", self.rulepack_hash):
                    raise rulepack.Mismatch(self.rulepack_hash)
                body = {**body, "rulepack_hash": self.rulepack_hash}
            seq, prev = self.head
            # A builder may set ts itself, under this lock, when a check depends on it (an approval deadline).
            rec = record.seal({**body, "ts": body.get("ts") or record.now_ts()}, seq + 1, prev, self.key)
            self.store.append(rec)
            self.head = (rec["seq"], rec["record_hash"])
            if rec["type"] == "rulepack_change":
                self.rulepack_hash = rec["rulepack_hash"]
            return rec

    async def adopt_rulepack(self, new: rulepack.RulePack, trigger: str,
                             old: rulepack.RulePack | None) -> dict | None:
        """Put `new` in force; seal a rulepack_change iff its hash differs from the chain's.
        rules_changed: every rule on first adoption; [] at a restart, where the old pack is unknown."""
        self.rulepack = new
        before = self.rulepack_hash
        if new.hash == before:
            return None
        changed = rulepack.changed(old, new) if old or not before else []
        ext = {"rulepack_id": new.rulepack_id, "version": new.version, "path": new.path, "before": before,
               "after": new.hash, "rules_changed": changed, "trigger": trigger}
        return await self.seal(self.body(self.policy, "rulepack_change", rule_hits=policy.rule_hits_json(changed),
                                         rulepack_hash=new.hash, ext=record.canonical_json(ext).decode()))

    async def adopt_policy(self, new: policy.Policy, old_hash: str,
                           old: policy.Policy | None) -> dict | None:
        """Put `new` in force; seal a policy_change record iff the policy hash moved.

        `old` is the previous Policy object when known (reload), else None (startup,
        where only the previous hash survives), in which case rule_hits is empty.
        """
        self.policy = new
        if new.hash == old_hash:
            return None
        hits = policy.mode_changes(old, new) if old else []
        return await self.seal(self.body(new, "policy_change", rule_hits=policy.rule_hits_json(hits)))

    async def aclose(self) -> None:
        await self.client.aclose()
        await self.idp.aclose()
        if self.foundry:
            await self.foundry.aclose()
        self.store.close()
        close = getattr(self.key, "close", None)  # HSM signer only; file keys have none
        if close:
            close()


def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None,
               resolver: DigestResolver | None = None,
               idp_transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.node = Node(settings, transport, resolver, idp_transport)
        n = app.state.node
        if n.rulepack:   # before any policy_change, so that record already carries the new hash
            await n.adopt_rulepack(n.rulepack, "startup", old=None)
        last = n.store.last()
        if last and last["policy_hash"] != n.policy.hash:
            await n.adopt_policy(n.policy, old_hash=last["policy_hash"], old=None)
        await foundry.register(n)
        await agents.close_expired(n)
        await approvals.start(n)
        yield
        approvals.stop(n)
        await app.state.node.aclose()

    app = FastAPI(title="Sijill", lifespan=lifespan)

    @app.exception_handler(record.NotCanonical)
    @app.exception_handler(UnicodeEncodeError)      # a lone surrogate, which strict UTF-8 cannot encode
    async def not_canonical(request: Request, e: ValueError):
        """Input no record can hash (§2.2) is refused, wherever it surfaces: a request body, an agent's ext. (A model's
        answer is not input: the model doors seal it as an upstream_error.) Any other encoding failure is the
        ledger's fault, and stays a 500."""
        if isinstance(e, UnicodeEncodeError) and e.reason != "surrogates not allowed":
            raise e
        return JSONResponse(status_code=400, content={"detail": f"not canonical JSON: {e}"})

    def node(request: Request) -> Node:
        return request.app.state.node

    def require_admin(request: Request) -> None:
        if not settings.admin_token:
            raise HTTPException(503, "admin endpoints disabled: set SIJILL_ADMIN_TOKEN")
        supplied = request.headers.get("authorization", "").encode()
        if not hmac.compare_digest(supplied, f"Bearer {settings.admin_token}".encode()):
            raise HTTPException(401, "admin token required")

    app.include_router(agents.router(require_admin))
    app.include_router(approvals.router())
    app.include_router(budgets.router())
    app.include_router(foundry.router())

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        t0 = perf_counter()
        n = node(request)
        try:
            payload = await request.json()
        except ValueError:
            raise HTTPException(400, "request body must be JSON")
        if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
            raise HTTPException(400, "`messages` must be a list")
        if not isinstance(payload.get("stream_options") or {}, dict):
            raise HTTPException(400, "`stream_options` must be an object")

        # An agent's call is bound to its session and, when one is open, its task (spec §2.3, §17.2.8).
        sess = agents.session_of(n, request)
        if sess is None and request.headers.get("x-sijil-task-seq"):
            raise HTTPException(401, "X-Sijil-Task-Seq needs X-Sijil-Agent-Session")
        task = agents.task_for(n, sess, request.headers.get("x-sijil-task-seq")) if sess else None
        who = agents.identity(sess, task)
        session_id = json.loads(task["ext"])["session_id"] if task else ""

        model_id = str(payload.get("model") or settings.default_model)
        pol, region = n.policy, n.region
        api = pol.attestation == "api"
        if api:
            if not chat.MODEL.fullmatch(model_id):
                raise HTTPException(400, "`model` must be 1-256 characters without whitespace")
            digest = n.api_digest(model_id)   # until the provider names the model that answered
        else:
            digest = await asyncio.to_thread(n.resolver.resolve, model_id)
        request_hash = record.sha256_hex(record.canonical_json(payload))
        input_hash = record.input_hash(payload["messages"])
        extra = {}

        def ext(**answer) -> str:
            x = chat.ext(pol.attestation, request_hash=request_hash, **{"session_id": session_id, **extra, **answer})
            return record.canonical_json(x).decode() if x else ""

        def headers(rec: dict, upstream_ms: float) -> dict:
            overhead = (perf_counter() - t0) * 1000 - upstream_ms
            return {"X-Sijill-Seq": str(rec["seq"]), "X-Sijill-Decision": rec["decision"],
                    "X-Sijill-Record-Hash": rec["record_hash"], "X-Sijill-Overhead-Ms": f"{overhead:.3f}"}

        try:
            # The record is sealed when the answer is complete: a token must outlive the upstream timeout (U1).
            human = await n.human(request, task, settings.upstream_timeout)
        except oidc.OidcError as e:
            # Sealed like the halt, outside any task so check I holds (spec §17.2.7); nothing is forwarded.
            refused = oidc.hit(e.code)
            rec = await n.seal(n.body(pol, "inference", model_id=model_id, model_digest=digest, mode="enforce",
                                      decision="block", rule_hits=policy.rule_hits_json([refused]),
                                      input_hash=input_hash, ext=ext(principal_error=e.code, session_id=""),
                                      agent_id=who["agent_id"], principal=e.principal))
            return JSONResponse(status_code=e.status, headers=headers(rec, 0.0), content={
                "error": {"message": f"Sijil principal refused: {e.code}", "type": "principal_refused",
                          "code": refused},
                "sijill": {"seq": rec["seq"], "decision": "block", "rule_hits": [refused],
                           "record_hash": rec["record_hash"]}})
        if human is not None:
            if task is None:
                who["principal"] = human["principal"]
                extra["principal_claims"] = human["claims"]
            elif n.store.token_in_force(task["seq"]) != human["claims"]["token_hash"]:
                extra["principal_claims"] = human["claims"]    # a refreshed token in the task (§17.2.8)

        # In api mode the allowlist is checked against the model that answered (spec §3.1), after the call.
        skip = ("model_allowlist",) if api else ()
        decision, mode, hits = policy.evaluate(pol, region, digest, payload["messages"], skip=skip)
        if n.halted:
            decision, mode, hits = "block", "enforce", [policy.HALT_HIT]
        elif task is not None:   # model spend is post-paid: admitted while the task is under budget (§17.6.2)
            exceeded = budgets.evaluate(n.rulepack, n.store, task, "inference")[1]
            if exceeded:
                decision, mode, hits = "block", "enforce", hits + exceeded
        body = n.body(pol, "inference", model_id=model_id, model_digest=digest, mode=mode, decision=decision,
                      rule_hits=policy.rule_hits_json(hits), input_hash=input_hash, ext=ext(), **who)

        def settled(b: dict):
            """Seal-time body: a task that ended while the call was in flight is not written into, so the
            inference is sealed outside it (task_seq and ext.session_id empty), keeping the session identity."""
            def build() -> dict:
                if b["task_seq"] and n.store.task_ended(b["task_seq"]):
                    x = json.loads(b["ext"]) if b["ext"] else {}
                    if "session_id" in x:
                        x["session_id"] = ""
                    # The token was validated in this request: seal the no-task human shape (§17.2.5).
                    if human is not None:
                        x["principal_claims"] = human["claims"]
                    else:
                        x.pop("principal_claims", None)
                    return {**b, "task_seq": "", "agent_id": sess["agent_id"],
                            "principal": human["principal"] if human is not None else sess["principal"],
                            "ext": record.canonical_json(x).decode() if x else ""}
                if b["task_seq"] and policy.HALT_HIT not in json.loads(b["rule_hits"]):
                    return budgets.inference(n, task, b)      # counted under the lock (check W)
                return b
            return build

        def usage(u) -> dict | None:
            """Chat completions usage as {input_tokens, output_tokens} (§17.6.2)."""
            if isinstance(u, dict) and all(type(u.get(k)) is int and u[k] >= 0 for k in ("prompt_tokens", "completion_tokens")):
                return {"input_tokens": u["prompt_tokens"], "output_tokens": u["completion_tokens"]}
            return None

        def answered(model) -> tuple[dict, list[str]] | None:
            """api mode: digest and post-call evaluation for the model the provider says answered."""
            if not (isinstance(model, str) and chat.MODEL.fullmatch(model)):
                return None
            d = n.api_digest(model)
            post_decision, post_mode, post_hits = policy.evaluate(pol, region, d, payload["messages"])
            return {"model_digest": d, "decision": post_decision, "mode": post_mode,
                    "rule_hits": policy.rule_hits_json(post_hits)}, post_hits

        def blocked(rec: dict, block_hits: list[str], upstream_ms: float = 0.0):
            return JSONResponse(status_code=403, headers=headers(rec, upstream_ms), content={
                "error": {"message": f"Blocked by Sijill policy: {', '.join(block_hits)}",
                          "type": "policy_block", "code": "sijill_block"},
                "sijill": {"seq": rec["seq"], "decision": "block", "rule_hits": block_hits,
                           "record_hash": rec["record_hash"]}})

        if decision == "block":
            return blocked(await n.seal(settled(body)), hits)

        async def upstream_failed(status: int, content: dict, upstream_ms: float):
            """Seal the call marked with the reserved upstream-error hit and respond."""
            # Forwarded, so priced like any forwarded request: no usage reported means missing_usage_cost_micro.
            rec = await n.seal(settled({**body, "rule_hits": policy.rule_hits_json(hits + [policy.UPSTREAM_ERROR_HIT]),
                                        "ext": ext(**budgets.cost(n.rulepack, digest, None))}))
            return JSONResponse(status_code=status, headers=headers(rec, upstream_ms), content=content)

        def unhashable(spent, response_hash: str) -> dict:
            """An answer carrying a value no record can hash (§2.2: NaN, an infinity, a lone surrogate) was forwarded
            and billed: sealed as an upstream_error, priced, with only its raw bytes hashed and nothing parsed from it."""
            x = json.loads(ext(**budgets.cost(n.rulepack, digest, spent)) or "{}")   # weights mode drops response_hash
            return {**body, "rule_hits": policy.rule_hits_json(hits + [policy.UPSTREAM_ERROR_HIT]),
                    "ext": record.canonical_json({**x, "response_hash": response_hash}).decode()}

        UNHASHABLE = {"error": {"message": "model runtime returned an answer no record can hash (NaN, an infinity "
                                           "or a lone surrogate)", "type": UPSTREAM_ERROR_TYPE}}

        t1 = perf_counter()
        if payload.get("stream"):
            forward = {**payload, "model": model_id}
            if n.rulepack and n.rulepack.pricing:     # the cost needs the usage the last chunk carries
                forward["stream_options"] = {**(payload.get("stream_options") or {}), "include_usage": True}
            req = n.client.build_request("POST", "/chat/completions", json=forward)
            try:
                resp = await n.client.send(req, stream=True)
            except httpx.HTTPError as e:
                return await upstream_failed(
                    502, {"error": {"message": f"model runtime unreachable: {e!r}",
                                    "type": UPSTREAM_ERROR_TYPE}}, (perf_counter() - t1) * 1000)
            if resp.status_code != 200:
                raw = await resp.aread()
                await resp.aclose()
                return await upstream_failed(resp.status_code, error_content(raw), (perf_counter() - t1) * 1000)

            async def relay():
                parts, calls, relayed = [], chat.StreamCalls(), hashlib.sha256()
                done, errored, refused, post, finish, rec, spent = False, False, False, None, "", None, None
                bad = False
                try:
                    async for line in resp.aiter_lines():
                        if n.halted:  # operator halt lands mid-stream: stop relaying now
                            break
                        if line == "data: [DONE]":
                            done = True
                            break
                        if line.startswith("data: "):
                            try:
                                event = json.loads(line[6:])
                            except (ValueError, RecursionError):
                                event = None
                            if isinstance(event, dict) and "error" in event:
                                errored = True  # in-stream failure (vLLM), even if [DONE] follows
                            if isinstance(event, dict) and event.get("usage"):
                                spent = usage(event["usage"])
                            if api and post is None and isinstance(event, dict) and event.get("model"):
                                # An empty or absent model (Azure's leading prompt-filter chunk) does not latch.
                                post = answered(event["model"])
                                if post is None:
                                    errored = True
                                    break
                                if post[0]["decision"] == "block":   # nothing of the answer is relayed
                                    refused = True
                                    break
                            try:
                                choice = event["choices"][0]
                                delta = choice.get("delta") or {}
                                finish = choice.get("finish_reason") or finish
                            except (KeyError, IndexError, TypeError, AttributeError):
                                delta = {}
                            if api and post is None and isinstance(delta, dict) and (
                                    delta.get("content") or delta.get("tool_calls")):
                                errored = True   # answer content before the answering model is named
                                break
                            if isinstance(delta, dict):
                                if isinstance(delta.get("content"), str):
                                    parts.append(delta["content"])
                                calls.add(delta)
                        relayed.update((line + "\n").encode())
                        yield (line + "\n").encode()
                finally:
                    # Read the halt flag here, with no await before the seal: a halt that has flipped
                    # it has its `halted` record sealed or queued ahead of ours on the lock.
                    halted = n.halted

                    def delivered_cost() -> dict:
                        """The stream was forwarded and ended badly: charged like any forwarded request."""
                        by = post[0]["model_digest"] if post else digest
                        return {"ext": ext(**budgets.cost(n.rulepack, by, spent))}
                    ok = done and not errored and not halted and not (api and post is None)
                    try:
                        uses = calls.tool_uses()
                        if ok:
                            answered_by = post[0]["model_digest"] if post else digest
                            sealed = {**body, "output_hash": record.output_hash("".join(parts)), **(post[0] if post else {}),
                                      "ext": ext(response_hash=relayed.hexdigest(), stop_reason=str(finish),
                                                 tool_uses=uses, **budgets.cost(n.rulepack, answered_by, spent))}
                        elif halted:
                            # The halt is checked before each line is relayed, so `parts` is exactly the content
                            # already delivered. Hash it like a completed stream; nothing delivered keeps "".
                            sealed = {**body, "decision": "block", "mode": "enforce", "rule_hits": policy.rule_hits_json(
                                hits + [policy.HALT_HIT, policy.UPSTREAM_ERROR_HIT]),
                                "output_hash": record.output_hash("".join(parts)) if parts else "",
                                **delivered_cost()}
                        elif refused:     # the provider answered (and billed) with an unapproved model: withheld, priced
                            sealed = {**body, **post[0], **delivered_cost()}
                        else:
                            sealed = {**body, "rule_hits": policy.rule_hits_json(hits + [policy.UPSTREAM_ERROR_HIT]),
                                      **delivered_cost()}
                        record.canonical_json(sealed)      # every field the seal will hash, model_digest included
                    except (record.NotCanonical, UnicodeEncodeError):
                        ok, bad = False, True
                        sealed = unhashable(spent, relayed.hexdigest())
                        if halted:
                            sealed = {**sealed, "decision": "block", "mode": "enforce", "rule_hits":
                                      policy.rule_hits_json(hits + [policy.HALT_HIT, policy.UPSTREAM_ERROR_HIT])}
                    # Shielded: a client hang-up cancels this task (anyio, level-triggered), but the call
                    # must still be sealed. Seal first; closing the upstream may itself yield. The close
                    # runs even if the seal raises, so a signer outage does not leak the connection.
                    with anyio.CancelScope(shield=True):
                        try:
                            rec = await n.seal(settled(sealed))
                            if ok and rec["decision"] != "block":
                                n.store.index_tool_uses(rec["seq"], uses)
                        finally:
                            await resp.aclose()
                if bad:      # relayed already, so the client is told the answer is void
                    yield f"data: {json.dumps(UNHASHABLE)}\n\n".encode()
                yield (f": sijill seq={rec['seq']} decision={rec['decision']} "
                       f"record_hash={rec['record_hash']}\n\n").encode()
                if done and not halted and not bad:
                    yield b"data: [DONE]\n\n"

            return StreamingResponse(relay(), media_type="text/event-stream",
                                     headers={"X-Sijill-Decision": decision, "Cache-Control": "no-cache"})

        try:
            resp = await n.client.post("/chat/completions", json={**payload, "model": model_id})
        except httpx.HTTPError as e:
            return await upstream_failed(
                502, {"error": {"message": f"model runtime unreachable: {e!r}",
                                "type": UPSTREAM_ERROR_TYPE}}, (perf_counter() - t1) * 1000)
        upstream_ms = (perf_counter() - t1) * 1000

        if resp.status_code != 200:
            return await upstream_failed(
                resp.status_code,
                error_content(resp.content) if resp.headers.get("content-type", "").startswith("application/json")
                else {"error": {"message": resp.text}},
                upstream_ms)

        # `content` absent or null is a valid OpenAI shape (tool calls): hash "".
        try:
            data = resp.json()
            choice = data["choices"][0]
            message = choice["message"]
            if not isinstance(message, dict):
                raise TypeError("malformed choice")
            text = message.get("content")
            text = "" if text is None else text
            if not isinstance(text, str):
                raise TypeError("message content is not a string or null")
            post = answered(data.get("model")) if api else None
            if api and post is None:
                raise TypeError("api attestation needs the response's model")
        except (ValueError, KeyError, IndexError, TypeError, AttributeError, RecursionError):
            return await upstream_failed(
                502, {"error": {"message": "model runtime returned a malformed response",
                                "type": UPSTREAM_ERROR_TYPE}}, upstream_ms)

        try:
            uses = chat.tool_uses(message)
            answered_by = post[0]["model_digest"] if post else digest
            sealed = {**body, "output_hash": record.output_hash(text), **(post[0] if post else {}),
                      "ext": ext(response_hash=record.sha256_hex(resp.content),
                                 provider_request_id=resp.headers.get("x-request-id", ""),
                                 stop_reason=str(choice.get("finish_reason") or ""), tool_uses=uses,
                                 **budgets.cost(n.rulepack, answered_by, usage(data.get("usage"))))}
            record.canonical_json(sealed)          # every field the seal will hash, model_digest included
        except (record.NotCanonical, UnicodeEncodeError):
            rec = await n.seal(settled(unhashable(usage(data.get("usage")), record.sha256_hex(resp.content))))
            return JSONResponse(status_code=502, headers=headers(rec, upstream_ms), content=UNHASHABLE)
        if post and post[0]["decision"] == "block":
            # The provider answered, but not with an approved model: the answer is withheld.
            return blocked(await n.seal(settled({**sealed, "output_hash": ""})), post[1], upstream_ms)
        rec = await n.seal(settled(sealed))
        if rec["decision"] == "block":   # a concurrent call of the task spent the budget first: withheld
            return blocked(rec, json.loads(rec["rule_hits"]), upstream_ms)
        n.store.index_tool_uses(rec["seq"], uses)
        return JSONResponse(content=data, headers=headers(rec, upstream_ms))

    @app.get("/api/records")
    async def records(request: Request, since: int = 0, limit: int = 200, after: int | None = None):
        n = node(request)
        limit = max(1, min(limit, 1000))
        page = n.store.after(after, limit) if after is not None else n.store.since(since, limit)
        return {"total": n.store.count(), "records": page}

    @app.get("/api/policy")
    async def current_policy(request: Request):
        n = node(request)
        p = n.policy
        return {"policy_id": p.policy_id, "version_label": p.version_label, "approval_ref": p.approval_ref,
                "policy_hash": p.hash, "node_id": p.node_id, "region": n.region,
                "region_allowed": p.region_allowed(n.region), "model": settings.default_model,
                "rules": [{"id": r["id"], "type": r["type"], "mode": r["mode"]} for r in p.rules],
                "admin_auth": "token" if settings.admin_token else "disabled"}

    @app.get("/api/verify")
    async def verify():
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(VERIFIER), "--db", str(Path(settings.db_path).resolve()),
            "--pubkey", str(Path(settings.pubkey_path).resolve()), "--plain",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await proc.communicate()
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode, "output": out.decode().strip(),
                "checked_at": record.now_ts()}

    @app.post("/api/admin/policy/reload", dependencies=[Depends(require_admin)])
    async def reload_policy(request: Request):
        n = node(request)
        try:
            new = policy.load(settings.policy_path)
            n.check_attestation(new)
            rulepack.check_policy(n.rulepack, new)
            jwks = n.keys_for(new)
        except Exception as e:
            raise HTTPException(400, f"policy not loaded: {e}")
        old = n.policy
        n.jwks = jwks
        rec = await n.adopt_policy(new, old_hash=old.hash, old=old)
        changed = policy.mode_changes(old, new)
        return {"changed": changed, "seq": rec and rec["seq"], "policy_hash": new.hash}

    @app.post("/api/admin/rulepack/reload", dependencies=[Depends(require_admin)])
    async def reload_rulepack(request: Request):
        n = node(request)
        if not settings.rulepack_path:
            raise HTTPException(400, "no rule pack configured: set SIJILL_RULEPACK_PATH")
        try:
            new = rulepack.load(settings.rulepack_path)
            rulepack.check_policy(new, n.policy)
        except Exception as e:
            raise HTTPException(400, f"rule pack not loaded: {e}")
        old = n.rulepack
        rec = await n.adopt_rulepack(new, "reload", old)
        return {"changed": rulepack.changed(old, new), "seq": rec and rec["seq"], "rulepack_hash": new.hash}

    @app.post("/api/admin/node/region", dependencies=[Depends(require_admin)])
    async def set_region(request: Request):
        n = node(request)
        region = (await request.json()).get("region")
        if not isinstance(region, str) or not region.strip() or len(region) > 32:
            raise HTTPException(400, "body must be {\"region\": \"<code>\"}")
        region = region.strip()
        if region == n.region:
            return {"region": region, "seq": None}
        n.region = region
        rec = await n.seal(n.body(n.policy, "policy_change"))
        return {"region": region, "region_allowed": n.policy.region_allowed(region), "seq": rec["seq"]}

    @app.post("/api/admin/halt", dependencies=[Depends(require_admin)])
    async def halt(request: Request):
        n = node(request)
        want = (await request.json()).get("halted")
        if not isinstance(want, bool):
            raise HTTPException(400, 'body must be {"halted": true|false}')
        if want == n.halted:
            return {"halted": want, "seq": None}
        flag = Path(settings.halt_path)
        flag.touch() if want else flag.unlink(missing_ok=True)
        n.halted = want
        hit = policy.HALT_HIT if want else policy.RESUME_HIT
        rec = await n.seal(n.body(n.policy, "policy_change", rule_hits=policy.rule_hits_json([hit])))
        return {"halted": want, "seq": rec["seq"]}

    @app.get("/api/report")
    async def report(request: Request):
        ts_from, ts_to = request.query_params.get("from"), request.query_params.get("to")
        fd, out = tempfile.mkstemp(suffix=".pdf")
        os.close(fd)
        args = [sys.executable, str(REPORT), "--db", str(Path(settings.db_path).resolve()),
                "--pubkey", str(Path(settings.pubkey_path).resolve()), "--out", out]
        args += ["--from", ts_from] if ts_from else []
        args += ["--to", ts_to] if ts_to else []
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.STDOUT)
        log, _ = await proc.communicate()
        if proc.returncode != 0:
            os.unlink(out)
            raise HTTPException(500, f"report generation failed: {log.decode()[-500:]}")
        return FileResponse(out, media_type="application/pdf", filename="sijill-audit-report.pdf",
                            content_disposition_type="inline", background=BackgroundTask(os.unlink, out))

    @app.get("/")
    async def console():
        return FileResponse(DASHBOARD)

    return app


app = create_app()
