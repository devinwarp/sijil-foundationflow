"""The HTTP tool adapter (spec §17.3): a reverse proxy in front of an agent's REST tools. The agent's tool base
URL points here; each request is matched to an OpenAPI operation, sealed as a tool_call, an egress and a
tool_result, and forwarded only if the rules allow it. Without the base-URL change nothing is seen.

`POST /_sijil/task/start` and `/_sijil/task/end` open and close the agent's tasks under the adapter's agent
session, so the agent can bind its model calls to the same task (the ledger's H3).

What the agent receives is what was sealed: the result's output_hash and bytes commit to the upstream's bytes,
the relayed body is those bytes with invisible Unicode stripped (re-serialised JSON, or text), and it never
exceeds results.max_result_bytes; a result over the budget is withheld and recorded as truncated.
"""

import asyncio
import hmac
import json
import re
import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
import uvicorn
import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import identity, rules, task, unicode
from .canon import sha256_hex
from .cmdparse import host_of
from .config import HARNESSES, Config
from .ledger import Ledger, Refused, Unreachable
from .mcp import origin_ok
from .pipeline import Call, Pipeline, Refusal
from .rules import NOT_ALLOWLISTED

METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
UNKNOWN = "http-operation-unknown"
ALWAYS_FORWARD = ("content-type", "accept")       # needed to be understood; never credentials
MAX_UPSTREAM = 4 * 2 ** 20                        # bytes read from an upstream before the response is refused
MAX_TASK_BODY = 65536                             # /_sijil/task/* bodies


@dataclass(frozen=True)
class Operation:
    id: str                       # operationId, else "<METHOD> <path template>" (spec §17.3.3)
    method: str
    template: str
    regex: re.Pattern
    params: dict                  # name -> (in, schema type)


def _ref(doc: dict, obj: dict) -> dict:
    ref = obj.get("$ref") if isinstance(obj, dict) else None
    if isinstance(ref, str) and ref.startswith("#/"):
        for part in ref[2:].split("/"):
            doc = doc.get(part, {}) if isinstance(doc, dict) else {}
        return doc
    return obj


def load_spec(path: str) -> list[Operation]:
    try:
        doc = yaml.safe_load(Path(path).read_bytes())          # JSON is YAML
    except yaml.YAMLError as e:
        raise ValueError(f"{path}: not an OpenAPI document ({e})") from None
    paths = doc.get("paths") if isinstance(doc, dict) else None
    if not isinstance(paths, dict):
        raise ValueError(f"{path}: not an OpenAPI document (no paths mapping)")
    ops = []
    for template, item in paths.items():
        if not isinstance(template, str) or not template.startswith("/") or not isinstance(item, dict):
            raise ValueError(f"{path}: paths: {template!r} must be a /path with an object")
        shared = [_ref(doc, p) for p in item.get("parameters") or []]
        for method in METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = {}
            for p in shared + [_ref(doc, p) for p in op.get("parameters") or []]:
                if isinstance(p, dict) and isinstance(p.get("name"), str):
                    schema = p.get("schema") if isinstance(p.get("schema"), dict) else {}
                    params[p["name"]] = (p.get("in", "query"), schema.get("type", "string"))
            rx = re.compile("".join(f"(?P<p{i}>[^/]+)" if part.startswith("{") else re.escape(part)
                                    for i, part in enumerate(re.split(r"(\{[^}]+\})", template))) + r"\Z")
            op_id = op.get("operationId")
            ops.append(Operation(op_id if isinstance(op_id, str) and op_id else f"{method.upper()} {template}",
                                 method.upper(), template, rx, params))
    if len({o.id for o in ops}) != len(ops):
        raise ValueError(f"{path}: operation ids must be unique")
    return sorted(ops, key=lambda o: o.template.count("{"))   # literal segments win over parameters


def match(ops: list[Operation], method: str, path: str) -> tuple[Operation, dict] | None:
    if any(seg in (".", "..") for seg in path.split("/")):      # never forwarded: the upstream would resolve it
        return None
    for op in ops:
        m = op.regex.match(path) if op.method == method else None
        if m:
            names = re.findall(r"\{([^}]+)\}", op.template)
            return op, {n: m.group(f"p{2 * i + 1}") for i, n in enumerate(names)}
    return None


def _typed(value: str, kind: str):
    """Query and path values arrive as text; the model's function arguments are typed. Coerce by schema so
    args_hash can match (spec §17.3.3, §12 item 41)."""
    try:
        if kind == "integer":
            return int(value)
        if kind == "number":
            return int(value) if re.fullmatch(r"-?\d+", value) else float(value)
        if kind == "boolean" and value in ("true", "false"):
            return value == "true"
    except ValueError:
        pass
    return value


def arguments(op: Operation | None, path_params: dict, request: Request, body: bytes, forward: tuple) -> dict:
    """Path, query and declared header parameters plus the JSON body's members, in one object (§17.3.3). A
    path or query value wins over a body member of the same name: it is what the upstream is asked for."""
    kinds = op.params if op else {}
    args = {k: _typed(v, kinds.get(k, ("path", "string"))[1]) for k, v in path_params.items()}
    for k in dict.fromkeys(request.query_params.keys()):
        vals = [_typed(v, kinds.get(k, ("query", "string"))[1]) for v in request.query_params.getlist(k)]
        args[k] = vals[0] if len(vals) == 1 else vals
    for name, (where, kind) in kinds.items():
        if where == "header" and name.lower() not in forward and name in request.headers:
            args[name] = _typed(request.headers[name], kind)
    if body:
        ctype = request.headers.get("content-type", "").split(";")[0].strip()
        try:
            data = json.loads(body) if ctype.endswith("json") else None
        except (ValueError, RecursionError):
            data = None
        if isinstance(data, dict):
            args = {**data, **args}
        elif data is not None:
            args["body"] = data
        else:
            args.update({"_body_sha256": sha256_hex(body), "_content_type": ctype})
    return args


def _strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for k, v in obj.items() for s in [k, *_strings(v)]]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return []


def _strip_json(obj):
    if isinstance(obj, str):
        return unicode.strip(obj)
    if isinstance(obj, dict):
        return {unicode.strip(k): _strip_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_json(v) for v in obj]
    return obj


def scannable(body: bytes, ctype: str) -> tuple[str, object]:
    """(text to scan, parsed JSON or None). JSON is decoded first, so a \\u200b escape is seen as U+200B."""
    if ctype.endswith("json"):
        try:
            data = json.loads(body)
            return "\n".join(_strings(data)), data
        except ValueError:
            pass
    if ctype.startswith("text/") or ctype.endswith("json") or ctype.endswith("xml"):
        return unicode.decode(body), None
    return "", None


async def body_of(request: Request) -> dict | None:
    body = await request.body()
    if len(body) > MAX_TASK_BODY:
        return None
    try:
        b = json.loads(body or b"{}")
    except (ValueError, RecursionError):
        return None
    return b if isinstance(b, dict) else None


def blocked(seq, hits, status=403, kind="sijil_blocked", message="") -> JSONResponse:
    return JSONResponse({"error": {"type": kind, "rule_hits": hits, "seq": seq, **({"message": message} if message else {})}},
                        status, headers={"X-Sijil-Seq": str(seq)} if seq else {})


def unavailable(e: Exception) -> JSONResponse:
    """The ledger could not be used: the call does not proceed (fail closed)."""
    if isinstance(e, Unreachable):
        return JSONResponse({"error": "Sijil ledger unreachable"}, 503)
    return JSONResponse({"error": "Sijil session unavailable"}, 503)      # key or token problem on this side


class Adapter:
    def __init__(self, cfg: Config, ledger: Ledger, upstream: httpx.AsyncClient | None = None, open_session=None):
        self.cfg, self.ledger, self.tools = cfg, ledger, cfg.http_tools
        self.open_session = open_session or (lambda: identity.open_session(ledger, cfg))
        self.http = upstream or httpx.AsyncClient(timeout=60.0, follow_redirects=False)
        self.pipelines: dict[str, Pipeline] = {}       # one per agent session: the pack is parsed once
        self.servers = {s.name: (s, load_spec(s.spec)) for s in self.tools.servers}
        base = rules.load_pins(cfg.egress_pins)
        # the upstreams named in this config are pinned by it (spec §17.3.3: allowed_by rulepack)
        self.pins = rules.Pins(base.path or cfg.path, base.hosts | {host_of(s.upstream) for s in self.tools.servers},
                               base.suffixes)

    def state(self) -> task.State:
        return task.shared(task.state_path(self.cfg), self.cfg.agent_id, self.open_session)

    def authorised(self, request: Request) -> bool:
        if self.tools.auth != "bearer_env":
            return True                  # mtls is enforced by the TLS layer; none only on loopback
        return hmac.compare_digest(request.headers.get("x-sijil-tools-token", "").encode(), self.tools.token.encode())

    async def task_start(self, request: Request) -> JSONResponse:
        b = await body_of(request)
        if b is None or b.get("harness", "http-agent") not in HARNESSES or not isinstance(b.get("intent", ""), str):
            return JSONResponse({"error": "body: {intent, session_id, harness in " + ", ".join(HARNESSES) + "}"}, 400)
        harness = b.get("harness", "http-agent")
        token = request.headers.get(self.cfg.principal_header.lower())
        try:
            st = await asyncio.to_thread(self.state)
            seq = await asyncio.to_thread(task.start_task, self.ledger, st.agent_session, b.get("intent", ""),
                                          harness, str(b.get("session_id", "")), "", token,
                                          self.cfg.principal_header)
        except Refused as e:
            return JSONResponse({"error": e.detail}, e.status)
        except (Unreachable, OSError, ValueError) as e:
            return unavailable(e)
        return JSONResponse({"task_seq": seq, "agent_session": st.agent_session})

    async def task_end(self, request: Request) -> JSONResponse:
        b = await body_of(request)
        if b is None or b.get("outcome", "completed") not in ("completed", "aborted", "blocked", "error"):
            return JSONResponse({"error": "body: {task_seq, outcome}"}, 400)
        try:
            st = await asyncio.to_thread(self.state)
            r = await asyncio.to_thread(task.end_task, self.ledger, st.agent_session, b.get("task_seq"),
                                        b.get("outcome", "completed"))
        except Refused as e:
            return JSONResponse({"error": e.detail}, e.status)
        except (Unreachable, OSError, ValueError) as e:
            return unavailable(e)
        return JSONResponse(r)

    async def fetch(self, request: Request, url: str, body: bytes, headers: dict) -> tuple[int | None, bytes, str]:
        """(status, body, content-type) from the upstream. A transport failure, or a response over MAX_UPSTREAM,
        is (None, message, text/plain): the message is sealed as the result, and carries no upstream detail."""
        chunks, n = [], 0
        try:
            async with self.http.stream(request.method, url, params=request.query_params.multi_items(),
                                        content=body, headers=headers) as up:
                async for c in up.aiter_bytes():
                    n += len(c)
                    if n > MAX_UPSTREAM:
                        return None, b"upstream response too large", "text/plain"
                    chunks.append(c)
                return up.status_code, b"".join(chunks), up.headers.get("content-type", "")
        except httpx.HTTPError as e:
            return None, f"upstream unreachable ({type(e).__name__})".encode(), "text/plain"

    async def proxy(self, request: Request, server_name: str, path: str) -> Response:
        entry = self.servers.get(server_name)
        if entry is None:
            return JSONResponse({"error": "unknown tool server"}, 404)
        server, ops = entry
        body = await request.body()
        if len(body) > server.max_body_bytes:
            return JSONResponse({"error": f"body over max_body_bytes ({server.max_body_bytes})"}, 413)
        path = "/" + path
        found = match(ops, request.method, path)
        op, path_params = found if found else (None, {})
        name = op.id if op else f"{request.method} (unmatched)"      # a concrete path carries values
        forced = [UNKNOWN] if op is None else None if server.allowed(op.id) else [NOT_ALLOWLISTED]
        harness = request.headers.get("x-sijil-harness", "http-agent")
        upstream_host = host_of(server.upstream)
        try:
            args = arguments(op, path_params, request, body, server.forward_headers)
            call = Call(rule_tool=f"http:{server.name}:{name}", tool=name, server=server.name, args=args,
                        harness=harness if harness in HARNESSES else "other",
                        session_id=request.headers.get("x-sijil-session-id", ""), observed_by="http_adapter",
                        parent_names=[op.id] if op else [], tool_use_id=request.headers.get("x-sijil-tool-use-id", ""),
                        command_arg=server.command_arg, method=request.method,
                        path_template=op.template if op else "",
                        task_seq=request.headers.get("x-sijil-task-seq") or None,
                        qualified=f"http:{server.name}:{name}")
            call.summary = {"method": request.method, "host": upstream_host, "path_template": call.path_template,
                            "arg_keys": sorted(call.args)}
            st = await asyncio.to_thread(self.state)
            p = self.pipelines.get(st.agent_session)
            if p is None:
                p = self.pipelines[st.agent_session] = Pipeline(self.ledger, st.agent_session, self.cfg, pins=self.pins)
            sealed = await asyncio.to_thread(p.check, call, None, forced)
            u = urlsplit(server.upstream)
            port = u.port or (443 if u.scheme == "https" else 80)
            await asyncio.to_thread(p.egress, call, sealed, upstream_host, port, u.scheme, request.method, self.pins)
        except Refusal as r:
            if r.status is not None:       # the ledger refused (a 4xx): nothing was sealed
                if r.status == 409 and "task" in str(r.detail):     # H2: a call outside a task is never sealed
                    return blocked(None, ["http-task-ambiguous"], 409, "http-task-ambiguous", str(r.detail))
                return JSONResponse({"error": f"Sijil ledger refused the record: {r.detail}"},
                                    409 if r.status == 409 else 502)
            return blocked(r.seq, r.hits, 404 if forced and r.seq else 403, message=str(r))
        except RecursionError:
            return JSONResponse({"error": "request body is nested too deeply"}, 400)
        except (Unreachable, OSError, ValueError) as e:
            return unavailable(e)
        headers = {k: v for k, v in request.headers.items() if k.lower() in (*server.forward_headers, *ALWAYS_FORWARD)
                   and not k.lower().startswith("x-sijil-")}
        status, data, ctype = await self.fetch(request, server.upstream + quote(path), body, headers)
        media = ctype.split(";")[0].strip()
        try:
            text, parsed = scannable(data, media)
        except RecursionError:          # nested past what can be scanned: not relayed
            status, data, media, ctype = None, b"upstream response is not decodable", "text/plain", "text/plain"
            text, parsed = unicode.decode(data), None
        out, out_type = data, ctype
        if self.cfg.invisible_unicode == "strip" and unicode.flagged(text):
            if parsed is not None:
                out = json.dumps(_strip_json(parsed)).encode()          # ASCII: nothing left to hide
            else:
                out, out_type = unicode.strip(text).encode("utf-8", "surrogateescape"), f"{media}; charset=utf-8"
        cut = len(out) > self.cfg.max_result_bytes
        try:
            r = await asyncio.to_thread(p.result, call, sealed, text, "ok" if status and 200 <= status < 300 else "error",
                                        [media] if media else [], server.label, data, status, False, None, cut)
        except (Refusal, Refused, Unreachable) as e:
            return JSONResponse({"error": "Sijil ledger unreachable or refused the result"
                                 if isinstance(e, Unreachable) else f"Sijil ledger refused the record: {getattr(e, 'detail', e)}"},
                                503 if isinstance(e, Unreachable) else 502)
        seq = {"X-Sijil-Seq": str(r.seq)}
        if r.blocked:
            return blocked(r.seq, r.hits)
        if status is None:
            return JSONResponse({"error": data.decode()}, 502, headers=seq)
        if cut:
            return JSONResponse({"error": {"type": "sijil_result_too_large", "limit": self.cfg.max_result_bytes,
                                           "seq": r.seq}}, 502, headers=seq)
        return Response(out, status, media_type=out_type or None, headers=seq)


def app(adapter: Adapter) -> FastAPI:
    api = FastAPI()

    @api.middleware("http")
    async def inbound(request: Request, call_next):
        origin = request.headers.get("origin")
        if origin is not None and not origin_ok(origin):      # a browser page cannot drive the adapter
            return JSONResponse({"error": "Origin not allowed"}, 403)
        if not adapter.authorised(request):        # before anything is sealed (spec §17.3.2)
            return JSONResponse({"error": "X-Sijil-Tools-Token required"}, 401)
        return await call_next(request)

    api.post("/_sijil/task/start")(adapter.task_start)
    api.post("/_sijil/task/end")(adapter.task_end)

    @api.api_route("/{server_name}/{path:path}", methods=[m.upper() for m in METHODS])
    async def route(request: Request, server_name: str, path: str):
        return await adapter.proxy(request, server_name, path)
    return api


def run(cfg: Config, ledger: Ledger) -> None:
    t = cfg.http_tools
    if t is None:
        raise ValueError(f"{cfg.path}: no http_tools section")
    host, port = t.listen.rsplit(":", 1)
    tls = {"ssl_certfile": t.tls_cert, "ssl_keyfile": t.tls_key} if t.tls_cert else {}
    if t.auth == "mtls":
        tls.update(ssl_ca_certs=t.client_ca, ssl_cert_reqs=ssl.CERT_REQUIRED)
    uvicorn.run(app(Adapter(cfg, ledger)), host=host.strip("[]"), port=int(port), log_level="warning", **tls)
