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

from . import chat, keys, policy, record
from .digest import DigestResolver
from .store import Store

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "verifier" / "sijill_verify.py"
REPORT = ROOT / "report" / "generate.py"

# Error type used in {"error": {"type": ...}} bodies when the model runtime failed.
UPSTREAM_ERROR_TYPE = "upstream_error"
DASHBOARD = ROOT / "dashboard" / "index.html"


@dataclass
class Settings:
    db_path: str = "sijill.db"
    policy_path: str = "policy.yaml"
    key_path: str = "node.key"
    pubkey_path: str = "node.pub"
    upstream: str = "http://localhost:1234/v1"
    upstream_token: str = ""
    upstream_provider: str = ""        # <provider> in api:<provider>:<model> (spec §3.1: from the route)
    default_model: str = "llama-3.2-3b-instruct"
    upstream_timeout: float = 120.0
    admin_token: str = ""
    pkcs11_module: str = ""
    pkcs11_token: str = ""
    pkcs11_key: str = ""
    pkcs11_pin: str = ""
    halt_path: str = "sijill.halt"
    digest_cache: str = ".sijill_digests.json"

    @classmethod
    def from_env(cls) -> "Settings":
        e = os.environ.get
        return cls(
            db_path=e("DATABASE_PATH", cls.db_path),
            policy_path=e("POLICY_PATH", cls.policy_path),
            key_path=e("NODE_KEY_PATH", cls.key_path),
            pubkey_path=e("NODE_PUBKEY_PATH", cls.pubkey_path),
            upstream=e("LMSTUDIO_BASE_URL", cls.upstream),
            upstream_token=e("LM_API_TOKEN", ""),
            upstream_provider=e("SIJILL_UPSTREAM_PROVIDER", ""),
            default_model=e("SIJILL_MODEL", cls.default_model),
            upstream_timeout=float(e("UPSTREAM_TIMEOUT", cls.upstream_timeout)),
            admin_token=e("SIJILL_ADMIN_TOKEN", ""),
            pkcs11_module=e("SIJILL_PKCS11_MODULE", ""),
            pkcs11_token=e("SIJILL_PKCS11_TOKEN", ""),
            pkcs11_key=e("SIJILL_PKCS11_KEY", ""),
            pkcs11_pin=e("SIJILL_PKCS11_PIN", ""),
            halt_path=e("SIJILL_HALT_PATH", cls.halt_path),
            digest_cache=e("SIJILL_DIGEST_CACHE", cls.digest_cache),
        )


class Node:
    """Runtime state: the chain head, the policy in force and the node's current region."""

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None,
                 resolver: DigestResolver | None = None):
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
        # The writer trusts its own memory of the head, not the database: a record
        # deleted or edited at the tail while running still shows up as a break.
        self.head = self.store.head()
        self.lock = asyncio.Lock()
        self.halted = Path(settings.halt_path).exists()
        self.resolver = resolver or DigestResolver(cache_path=settings.digest_cache)
        headers = {"Authorization": f"Bearer {settings.upstream_token}"} if settings.upstream_token else {}
        self.client = httpx.AsyncClient(base_url=settings.upstream, headers=headers,
                                        timeout=settings.upstream_timeout, transport=transport)

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

    async def seal(self, body: dict) -> dict:
        async with self.lock:
            seq, prev = self.head
            rec = record.seal({**body, "ts": record.now_ts()}, seq + 1, prev, self.key)
            self.store.append(rec)
            self.head = (rec["seq"], rec["record_hash"])
            return rec

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
        self.store.close()
        close = getattr(self.key, "close", None)  # HSM signer only; file keys have none
        if close:
            close()


def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None,
               resolver: DigestResolver | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.node = Node(settings, transport, resolver)
        n = app.state.node
        last = n.store.last()
        if last and last["policy_hash"] != n.policy.hash:
            await n.adopt_policy(n.policy, old_hash=last["policy_hash"], old=None)
        yield
        await app.state.node.aclose()

    app = FastAPI(title="Sijill", lifespan=lifespan)

    def node(request: Request) -> Node:
        return request.app.state.node

    def require_admin(request: Request) -> None:
        if not settings.admin_token:
            raise HTTPException(503, "admin endpoints disabled: set SIJILL_ADMIN_TOKEN")
        supplied = request.headers.get("authorization", "").encode()
        if not hmac.compare_digest(supplied, f"Bearer {settings.admin_token}".encode()):
            raise HTTPException(401, "admin token required")

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

        model_id = str(payload.get("model") or settings.default_model)
        pol, region = n.policy, n.region
        api = pol.attestation == "api"
        if api:
            if not chat.MODEL.fullmatch(model_id):
                raise HTTPException(400, "`model` must be 1-256 characters without whitespace")
            digest = n.api_digest(model_id)   # until the provider names the model that answered
        else:
            digest = await asyncio.to_thread(n.resolver.resolve, model_id)
        # In api mode the allowlist is checked against the model that answered (spec §3.1), after the call.
        skip = ("model_allowlist",) if api else ()
        decision, mode, hits = policy.evaluate(pol, region, digest, payload["messages"], skip=skip)
        if n.halted:
            decision, mode, hits = "block", "enforce", [policy.HALT_HIT]
        request_hash = record.sha256_hex(record.canonical_json(payload))

        def ext(**answer) -> str:
            x = chat.ext(pol.attestation, request_hash=request_hash, **answer)
            return record.canonical_json(x).decode() if x else ""

        body = n.body(pol, "inference", model_id=model_id, model_digest=digest, mode=mode, decision=decision,
                      rule_hits=policy.rule_hits_json(hits), input_hash=record.input_hash(payload["messages"]),
                      ext=ext())

        def answered(model) -> tuple[dict, list[str]] | None:
            """api mode: digest and post-call evaluation for the model the provider says answered."""
            if not (isinstance(model, str) and chat.MODEL.fullmatch(model)):
                return None
            d = n.api_digest(model)
            post_decision, post_mode, post_hits = policy.evaluate(pol, region, d, payload["messages"])
            return {"model_digest": d, "decision": post_decision, "mode": post_mode,
                    "rule_hits": policy.rule_hits_json(post_hits)}, post_hits

        def headers(rec: dict, upstream_ms: float) -> dict:
            overhead = (perf_counter() - t0) * 1000 - upstream_ms
            return {"X-Sijill-Seq": str(rec["seq"]), "X-Sijill-Decision": rec["decision"],
                    "X-Sijill-Record-Hash": rec["record_hash"], "X-Sijill-Overhead-Ms": f"{overhead:.3f}"}

        def blocked(rec: dict, block_hits: list[str], upstream_ms: float = 0.0):
            return JSONResponse(status_code=403, headers=headers(rec, upstream_ms), content={
                "error": {"message": f"Blocked by Sijill policy: {', '.join(block_hits)}",
                          "type": "policy_block", "code": "sijill_block"},
                "sijill": {"seq": rec["seq"], "decision": "block", "rule_hits": block_hits,
                           "record_hash": rec["record_hash"]}})

        if decision == "block":
            return blocked(await n.seal(body), hits)

        async def upstream_failed(status: int, content: dict, upstream_ms: float):
            """Seal the call marked with the reserved upstream-error hit and respond."""
            rec = await n.seal({**body, "rule_hits": policy.rule_hits_json(
                hits + [policy.UPSTREAM_ERROR_HIT])})
            return JSONResponse(status_code=status, headers=headers(rec, upstream_ms), content=content)

        t1 = perf_counter()
        if payload.get("stream"):
            req = n.client.build_request("POST", "/chat/completions", json={**payload, "model": model_id})
            try:
                resp = await n.client.send(req, stream=True)
            except httpx.HTTPError as e:
                return await upstream_failed(
                    502, {"error": {"message": f"model runtime unreachable: {e!r}",
                                    "type": UPSTREAM_ERROR_TYPE}}, (perf_counter() - t1) * 1000)
            if resp.status_code != 200:
                raw = await resp.aread()
                await resp.aclose()
                try:
                    content = json.loads(raw)
                except ValueError:
                    content = {"error": {"message": raw.decode(errors="replace")}}
                return await upstream_failed(resp.status_code, content, (perf_counter() - t1) * 1000)

            async def relay():
                parts, calls, relayed = [], chat.StreamCalls(), hashlib.sha256()
                done, errored, refused, post, finish, rec = False, False, False, None, "", None
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
                            except ValueError:
                                event = None
                            if isinstance(event, dict) and "error" in event:
                                errored = True  # in-stream failure (vLLM), even if [DONE] follows
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
                    uses = calls.tool_uses()
                    ok = done and not errored and not halted and not (api and post is None)
                    if ok:
                        sealed = {**body, "output_hash": record.output_hash("".join(parts)), **(post[0] if post else {}),
                                  "ext": ext(response_hash=relayed.hexdigest(), stop_reason=str(finish),
                                             tool_uses=uses)}
                    elif halted:
                        # The halt is checked before each line is relayed, so `parts` is exactly the content
                        # already delivered. Hash it like a completed stream; nothing delivered keeps "".
                        sealed = {**body, "decision": "block", "mode": "enforce", "rule_hits": policy.rule_hits_json(
                            hits + [policy.HALT_HIT, policy.UPSTREAM_ERROR_HIT]),
                            "output_hash": record.output_hash("".join(parts)) if parts else ""}
                    elif refused:
                        sealed = {**body, **post[0]}
                    else:
                        sealed = {**body, "rule_hits": policy.rule_hits_json(hits + [policy.UPSTREAM_ERROR_HIT])}
                    # Shielded: a client hang-up cancels this task (anyio, level-triggered), but the call
                    # must still be sealed. Seal first; closing the upstream may itself yield. The close
                    # runs even if the seal raises, so a signer outage does not leak the connection.
                    with anyio.CancelScope(shield=True):
                        try:
                            rec = await n.seal(sealed)
                            if ok and rec["decision"] != "block":
                                n.store.index_tool_uses(rec["seq"], uses)
                        finally:
                            await resp.aclose()
                yield (f": sijill seq={rec['seq']} decision={rec['decision']} "
                       f"record_hash={rec['record_hash']}\n\n").encode()
                if done and not halted:
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
                resp.json() if resp.headers.get("content-type", "").startswith("application/json")
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
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            return await upstream_failed(
                502, {"error": {"message": "model runtime returned a malformed response",
                                "type": UPSTREAM_ERROR_TYPE}}, upstream_ms)

        uses = chat.tool_uses(message)
        sealed = {**body, "output_hash": record.output_hash(text), **(post[0] if post else {}),
                  "ext": ext(response_hash=record.sha256_hex(resp.content),
                             provider_request_id=resp.headers.get("x-request-id", ""),
                             stop_reason=str(choice.get("finish_reason") or ""), tool_uses=uses)}
        if post and post[0]["decision"] == "block":
            # The provider answered, but not with an approved model: the answer is withheld.
            return blocked(await n.seal({**sealed, "output_hash": ""}), post[1], upstream_ms)
        rec = await n.seal(sealed)
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
        except Exception as e:
            raise HTTPException(400, f"policy not loaded: {e}")
        old = n.policy
        rec = await n.adopt_policy(new, old_hash=old.hash, old=old)
        changed = policy.mode_changes(old, new)
        return {"changed": changed, "seq": rec and rec["seq"], "policy_hash": new.hash}

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
