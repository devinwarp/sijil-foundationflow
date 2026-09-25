"""Sijill proxy: evaluate every chat completion against policy, forward or block, seal a record.

Run a single worker (records are sealed under an in-process lock):

    uvicorn sijill.proxy:app --port 8000 --env-file .env.local

Admin endpoints have NO authentication. This is a local demo build; say so.
"""

import asyncio
import os
import sys
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.background import BackgroundTask

from . import keys, policy, record
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
    default_model: str = "llama-3.2-3b-instruct"
    upstream_timeout: float = 120.0

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
            default_model=e("SIJILL_MODEL", cls.default_model),
            upstream_timeout=float(e("UPSTREAM_TIMEOUT", cls.upstream_timeout)),
        )


class Node:
    """Runtime state: the chain head, the policy in force and the node's current region."""

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None,
                 resolver: DigestResolver | None = None):
        self.settings = settings
        self.store = Store(settings.db_path)
        self.key = keys.load_or_generate(settings.key_path, settings.pubkey_path)
        self.policy = policy.load(settings.policy_path)
        last = self.store.last()
        self.region = last["node_region"] if last else self.policy.node_region
        # The writer trusts its own memory of the head, not the database: a record
        # deleted or edited at the tail while running still shows up as a break.
        self.head = self.store.head()
        self.lock = asyncio.Lock()
        self.resolver = resolver or DigestResolver()
        headers = {"Authorization": f"Bearer {settings.upstream_token}"} if settings.upstream_token else {}
        self.client = httpx.AsyncClient(base_url=settings.upstream, headers=headers,
                                        timeout=settings.upstream_timeout, transport=transport)

    def body(self, pol: policy.Policy, type_: str, **fields) -> dict:
        base = dict(type=type_, model_id="", model_digest="", node_id=pol.node_id, node_region=self.region,
                    policy_id=pol.policy_id, policy_hash=pol.hash, approval_ref=pol.approval_ref,
                    mode="record", decision="allow", rule_hits="[]", input_hash="", output_hash="")
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
        if payload.get("stream"):
            raise HTTPException(400, "streaming is not supported by Sijill")

        model_id = str(payload.get("model") or settings.default_model)
        digest = await asyncio.to_thread(n.resolver.resolve, model_id)
        pol, region = n.policy, n.region
        decision, mode, hits = policy.evaluate(pol, region, digest, payload["messages"])
        body = n.body(pol, "inference", model_id=model_id, model_digest=digest, mode=mode, decision=decision,
                      rule_hits=policy.rule_hits_json(hits), input_hash=record.input_hash(payload["messages"]))

        def headers(rec: dict, upstream_ms: float) -> dict:
            overhead = (perf_counter() - t0) * 1000 - upstream_ms
            return {"X-Sijill-Seq": str(rec["seq"]), "X-Sijill-Decision": rec["decision"],
                    "X-Sijill-Record-Hash": rec["record_hash"], "X-Sijill-Overhead-Ms": f"{overhead:.3f}"}

        if decision == "block":
            rec = await n.seal(body)
            return JSONResponse(status_code=403, headers=headers(rec, 0.0), content={
                "error": {"message": f"Blocked by Sijill policy: {', '.join(hits)}",
                          "type": "policy_block", "code": "sijill_block"},
                "sijill": {"seq": rec["seq"], "decision": "block", "rule_hits": hits,
                           "record_hash": rec["record_hash"]}})

        async def upstream_failed(status: int, content: dict, upstream_ms: float):
            """Seal the call marked with the reserved upstream-error hit and respond."""
            rec = await n.seal({**body, "rule_hits": policy.rule_hits_json(
                hits + [policy.UPSTREAM_ERROR_HIT])})
            return JSONResponse(status_code=status, headers=headers(rec, upstream_ms), content=content)

        t1 = perf_counter()
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
            message = data["choices"][0]["message"]
            if not isinstance(message, dict):
                raise TypeError("malformed choice")
            text = message.get("content")
            text = "" if text is None else text
            if not isinstance(text, str):
                raise TypeError("message content is not a string or null")
        except (ValueError, KeyError, IndexError, TypeError):
            return await upstream_failed(
                502, {"error": {"message": "model runtime returned a malformed response",
                                "type": UPSTREAM_ERROR_TYPE}}, upstream_ms)

        rec = await n.seal({**body, "output_hash": record.output_hash(text)})
        return JSONResponse(content=data, headers=headers(rec, upstream_ms))

    @app.get("/api/records")
    async def records(request: Request, since: int = 0, limit: int = 200):
        n = node(request)
        return {"total": n.store.count(), "records": n.store.since(since, max(1, min(limit, 1000)))}

    @app.get("/api/policy")
    async def current_policy(request: Request):
        n = node(request)
        p = n.policy
        return {"policy_id": p.policy_id, "version_label": p.version_label, "approval_ref": p.approval_ref,
                "policy_hash": p.hash, "node_id": p.node_id, "region": n.region,
                "region_allowed": p.region_allowed(n.region), "model": settings.default_model,
                "rules": [{"id": r["id"], "type": r["type"], "mode": r["mode"]} for r in p.rules],
                "admin_auth": "none (demo build)"}

    @app.get("/api/verify")
    async def verify():
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(VERIFIER), "--db", str(Path(settings.db_path).resolve()),
            "--pubkey", str(Path(settings.pubkey_path).resolve()), "--plain",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await proc.communicate()
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode, "output": out.decode().strip(),
                "checked_at": record.now_ts()}

    @app.post("/api/admin/policy/reload")
    async def reload_policy(request: Request):
        n = node(request)
        try:
            new = policy.load(settings.policy_path)
        except Exception as e:
            raise HTTPException(400, f"policy not loaded: {e}")
        old = n.policy
        rec = await n.adopt_policy(new, old_hash=old.hash, old=old)
        changed = policy.mode_changes(old, new)
        return {"changed": changed, "seq": rec and rec["seq"], "policy_hash": new.hash}

    @app.post("/api/admin/node/region")
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
