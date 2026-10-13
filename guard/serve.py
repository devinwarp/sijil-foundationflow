"""The MCP guard (spec §5.1-5.7): one wrapped server per process; the harness sees it as that server.

initialize joins a task or starts one (§5.9); tools/list is filtered by tools.allow/deny; every tools/call goes
through the pipeline before and after the wrapped server runs it. resources/* and prompts/* are not proxied:
they would be a content channel the ledger never sees.
"""

import asyncio
import base64
import binascii
import ipaddress
import json
import os
import re
import uuid

import uvicorn

from . import identity, mcp, task, unicode
from .config import Config, Server
from .ledger import Ledger, Refused, Unreachable
from .pipeline import Call, Pipeline, Refusal
from .rules import NOT_ALLOWLISTED

ELICIT_SCHEMA = {"type": "object", "properties": {"allow": {"type": "boolean"}}, "required": ["allow"]}


BASE64 = re.compile(r"[A-Za-z0-9+/=\s]*")
# content item fields that reach the harness, per type: strings are sealed, stripped and truncated; `binary`
# is base64 (it cannot carry invisible characters) and bounded by the result budget; nothing else is relayed
ITEMS = {"text": (("text",), ()), "image": (("mimeType",), ("data",)), "audio": (("mimeType",), ("data",)),
         "resource_link": (("uri", "name", "description", "mimeType"), ())}
RESOURCE = (("uri", "mimeType", "text"), ("blob",))
REQUIRED = {"text": "text", "image": "data", "audio": "data"}
CODES = {-32700, -32600, -32601, -32602, -32603}


def _loopback(host: str) -> bool:
    """An allowlist: localhost and 127.0.0.0/8 and ::1. An empty host binds every interface."""
    host = host.strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _code(code) -> int:
    """A wrapped server's error code is relayed only when it is a JSON-RPC standard or server-error code."""
    ok = type(code) is int and (code in CODES or -32099 <= code <= -32000)
    return code if ok else mcp.INTERNAL


def _decode(data: str, limit: int) -> bytes | None:
    """The bytes of a base64 payload, or None when it is not base64 or is over the result budget."""
    if len(data) > limit or not BASE64.fullmatch(data):
        return None
    try:
        return base64.b64decode("".join(data.split()), validate=True)
    except (binascii.Error, ValueError):
        return None


def _size(fields: dict) -> int:
    """UTF-8 length of the string values of an item's fields (a note's `type` is not relayed text)."""
    return sum(len(v.encode("utf-8", "surrogatepass")) for k, v in fields.items() if k != "type")


def _note(why: str) -> dict:
    """The text item that replaces a content item the guard does not relay."""
    return {"type": "text", "text": f"sijil-guard: {why}"}


def _ledger_error(e: Exception) -> "mcp.RpcError":
    if isinstance(e, Unreachable):
        return mcp.RpcError(mcp.SIJIL, "Sijil ledger unreachable")
    return mcp.RpcError(mcp.SIJIL, f"Sijil ledger refused the record: {getattr(e, 'detail', e)}")


class Guard:
    def __init__(self, cfg: Config, server: Server, ledger: Ledger, open_session=None):
        self.cfg, self.server, self.ledger = cfg, server, ledger
        self.open_session = open_session or (lambda: identity.open_session(ledger, cfg))
        self.sessions: set = set()
        self.upstream = None
        self.init: dict = {}

    async def start(self) -> None:
        s = self.server
        if s.transport == "stdio":
            if os.path.realpath(s.command) != s.real:      # retargeted since the config was checked
                raise ValueError(f"server {s.name}: {s.command} no longer resolves to {s.real}")
            self.upstream = mcp.StdioUpstream(s.command, list(s.args), s.env, self.upstream_note)
        else:
            self.upstream = mcp.HttpUpstream(s.url, s.headers, self.upstream_note)
        await self.upstream.start()
        self.init = await self.upstream.request("initialize", {
            "protocolVersion": mcp.PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "sijil-guard", "version": "0.1.0"}})
        await self.upstream.notify("notifications/initialized")

    async def upstream_note(self, method: str, params: dict) -> None:
        if method == "notifications/tools/list_changed":
            for s in list(self.sessions):
                try:
                    await s.client.notify(method, params)
                except mcp.RpcError:      # one harness that went away must not silence the others
                    pass

    def state(self) -> task.State:
        return task.shared(task.state_path(self.cfg), self.cfg.agent_id, self.open_session)

    async def new_session(self, client: mcp.Client, headers: dict) -> "GuardSession":
        s = GuardSession(self, client, {k.lower(): v for k, v in headers.items()})
        self.sessions.add(s)
        return s

    async def aclose(self) -> None:
        for s in list(self.sessions):
            await s.close()
        if self.upstream:
            await self.upstream.close()


class GuardSession(mcp.Session):
    def __init__(self, guard: Guard, client: mcp.Client, headers: dict):
        self.guard, self.client, self.headers = guard, client, headers
        self.stdio = isinstance(client, mcp.StdioClient)
        self.elicit, self.owned, self.task_seq, self.pipeline = False, False, None, None
        self.session_id, self.last_blocked, self.closed = str(uuid.uuid4()), False, False
        self.loop = asyncio.get_running_loop()

    async def handle(self, method: str, params: dict) -> dict:
        if method == "initialize":
            return await self.initialize(params)
        if method == "ping":
            return {}
        if self.pipeline is None:
            raise mcp.RpcError(-32002, "initialize first")
        if method == "tools/list":
            return await self.tools_list(params)
        if method == "tools/call":
            return await self.tools_call(params)
        raise mcp.RpcError(mcp.METHOD_NOT_FOUND, f"{method} is not proxied by sijil-guard")

    def _join_or_start(self) -> tuple[task.State, int, bool]:
        """(state, task_seq, owned). A task named by X-Sijil-Task-Seq, or (stdio) the state file's open task,
        is joined; otherwise this session starts one and ends it at close (spec §5.9, MCP-only harness)."""
        g, cfg = self.guard, self.guard.cfg
        named = self.headers.get("x-sijil-task-seq")

        def join(state: task.State):
            if named:
                return state, int(named), False
            if self.stdio and state.task_seq:
                return state, state.task_seq, False
            token = self.headers.get(cfg.principal_header.lower()) or os.environ.get("SIJIL_PRINCIPAL_TOKEN")
            seq = task.start_task(g.ledger, state.agent_session, cfg.intent, cfg.harness, self.session_id,
                                  principal_token=token or None, principal_header=cfg.principal_header)
            if self.stdio:      # the harness's other guards and its model calls join this task
                state.tasks = [seq]
            return state, seq, True
        return task.update(task.state_path(cfg), cfg.agent_id, g.open_session, join)

    async def initialize(self, params: dict) -> dict:
        self.elicit = "elicitation" in (params.get("capabilities") or {}) and self.client.can_request
        try:
            state, self.task_seq, self.owned = await asyncio.to_thread(self._join_or_start)
        except (Unreachable, Refused, ValueError, OSError) as e:
            raise mcp.RpcError(mcp.SIJIL, f"Sijil: no agent session or task: {e}")
        self.agent_session = state.agent_session
        self.pipeline = Pipeline(self.guard.ledger, state.agent_session, self.guard.cfg)
        return {"protocolVersion": self.guard.init.get("protocolVersion", mcp.PROTOCOL),
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": self.guard.init.get("serverInfo", {"name": self.guard.server.name, "version": "0"}),
                "_meta": {"sijil": {"agent_session": state.agent_session, "task_seq": self.task_seq}}}

    async def tools_list(self, params: dict) -> dict:
        try:
            result = await self.guard.upstream.request("tools/list", params or None)
        except mcp.RpcError as e:      # its message and data are not relayed
            raise mcp.RpcError(_code(e.code), "wrapped server failed tools/list")
        tools = [t for t in result.get("tools", []) if isinstance(t, dict) and self.guard.server.allowed(t.get("name", ""))]
        cursor = result.get("nextCursor")
        return {"tools": tools, **({"nextCursor": cursor} if isinstance(cursor, str) else {})}

    def _confirm(self, rule) -> str:
        """Elicitation for a confirm rule (spec §5.7); runs on the pipeline's worker thread."""
        msg = {"message": f"Sijil rule {rule.id}: {rule.description}. Allow?", "requestedSchema": ELICIT_SCHEMA}
        fut = asyncio.run_coroutine_threadsafe(self.client.request("elicitation/create", msg), self.loop)
        try:
            answer = fut.result(timeout=300)
        except Exception:
            fut.cancel()                  # a timed-out ask must not stay pending on the harness
            return "denied"
        ok = answer.get("action") == "accept" and (answer.get("content") or {}).get("allow") is True
        return "granted" if ok else "denied"

    async def tools_call(self, params: dict) -> dict:
        s, cfg = self.guard.server, self.guard.cfg
        name, args = params.get("name"), params.get("arguments")
        args = {} if args is None else args
        if not isinstance(name, str) or not isinstance(args, dict):
            raise mcp.RpcError(mcp.INVALID_PARAMS, "tools/call needs a name and an arguments object")
        call = Call(rule_tool=f"mcp:{s.name}:{name}", tool=name, server=s.name, args=args, harness=cfg.harness,
                    session_id=self.session_id, observed_by="mcp_guard", parent_names=[name, f"mcp__{s.name}__{name}"],
                    command_arg=s.command_arg, task_seq=self.task_seq)
        forced = None if s.allowed(name) else [NOT_ALLOWLISTED]
        try:
            sealed = await asyncio.to_thread(self.pipeline.check, call, self._confirm if self.elicit else None, forced)
        except Refusal as r:
            self.last_blocked = r.seq is not None
            code = mcp.METHOD_NOT_FOUND if forced else mcp.SIJIL
            raise mcp.RpcError(code, str(r), {"sijil": {"seq": r.seq, "rule_hits": r.hits}})
        except (Unreachable, Refused) as e:      # fail closed: a ledger that cannot seal the call stops it
            raise _ledger_error(e)
        self.last_blocked, failed = False, None
        try:
            result = await self.guard.upstream.request("tools/call", {**params, "arguments": args})
        except mcp.RpcError as e:      # the call reached the wrapped server: its failure is still a result
            result, failed = {"content": [{"type": "text", "text": e.message}], "isError": True}, e
        content, replaced = self._items(result.get("content"))
        text = "".join(d[k] for _, _, d, k, binary in self._parts(content) if not binary)
        structured = result.get("structuredContent")
        if structured is not None:      # part of the result: sealed, scanned and bounded like the text
            text += json.dumps(structured, ensure_ascii=False, sort_keys=True)
        is_error = result.get("isError") is True
        raw, size = self._raw(content, text)
        types = [c["type"] for c in content]
        # what the harness gets, cleaned before the seal so the record says whether the budget cut anything
        content, left, cut = self._rewrite(content)
        clean, dropped = self._clean(structured, left) if structured is not None else (None, False)
        try:
            r = await asyncio.to_thread(self.pipeline.result, call, sealed, text, "error" if is_error else "ok",
                                        types, s.label, raw, size=size, cut=replaced or cut or dropped)
        except (Unreachable, Refused, Refusal) as e:      # fail closed: the result is withheld unsealed
            raise _ledger_error(e)
        if r.blocked:
            self.last_blocked = True
            raise mcp.RpcError(mcp.SIJIL, f"Result withheld by Sijil rule {', '.join(r.hits) or 'halted'}; seq={r.seq}",
                               {"sijil": {"seq": r.seq, "rule_hits": r.hits}})
        if failed:      # message only, as sealed (stripped, truncated); the server's `data` is not relayed
            raise mcp.RpcError(_code(failed.code), r.text)
        out = {"content": content}      # only these keys reach the harness; upstream _meta and the rest are dropped
        if clean is not None:
            out["structuredContent"] = clean
        if is_error:
            out["isError"] = True
        return {**out, "_meta": {"sijil": {"seq": r.seq, "parent_seq": sealed.seq}}}

    def _clean(self, value, budget: int) -> tuple:
        """structuredContent after the same treatment as the text: stripped, or dropped when over what is left of
        the result budget after the content. (value or None, dropped for the budget)."""
        raw = json.dumps(value, ensure_ascii=False)
        if self.guard.cfg.invisible_unicode == "strip":
            raw = unicode.strip(raw)
        if len(raw.encode("utf-8", "surrogatepass")) > budget:
            return None, True
        try:
            return json.loads(raw), False
        except ValueError:
            return None, False

    def _items(self, raw) -> tuple[list, bool]:
        """Each content item rebuilt from the allowlist for its type; _meta, annotations and unknown keys are
        dropped. Every upstream value is shape-checked: a `content` that is not a list, an item that is not an
        object, a type that is not a known string, an allowlisted field that is not a string, a text item without
        text, an image or audio item without data, or a payload that is not base64 becomes a text item saying so. One result budget covers the strings and the decoded payloads in
        item order; a binary item past it becomes a text item saying that. A payload is relayed re-encoded, so
        the harness gets exactly the bytes that are hashed. (items, whether the budget replaced any)."""
        limit, used, out, replaced = self.guard.cfg.max_result_bytes, 0, [], False
        for c in raw if isinstance(raw, list) else [] if raw is None else [None]:
            c = c if isinstance(c, dict) else {}
            kind = c.get("type") if isinstance(c.get("type"), str) else None
            holder = c.get("resource") if kind == "resource" else c
            holder = holder if isinstance(holder, dict) else {}
            strs, binary = RESOURCE if kind == "resource" else ITEMS.get(kind, ((), ()))
            known = kind in ITEMS or kind == "resource" and isinstance(c.get("resource"), dict)
            typed = all(isinstance(holder[k], str) for k in (*strs, *binary) if k in holder)
            fields = {k: holder[k] for k in strs if k in holder} if typed else {}
            blobs = {k: _decode(holder[k], limit) for k in binary if k in holder} if typed else {}
            missing = kind in REQUIRED and REQUIRED[kind] not in holder
            size = _size(fields) + sum(len(b) for b in blobs.values() if b is not None)
            if not known or not typed or missing or None in blobs.values():
                item = _note(f"unsupported content type {str(kind)[:40]}")
                size = _size(item)
            elif blobs and used + size > limit:
                item = _note(f"{kind} over the result budget")
                size, replaced = _size(item), True
            else:
                fields.update({k: base64.b64encode(b).decode("ascii") for k, b in blobs.items()})
                item = {"type": kind, "resource": fields} if kind == "resource" else {"type": kind, **fields}
            used += size
            out.append(item)
        return out, replaced

    def _raw(self, content: list, text: str) -> tuple[bytes | None, int | None]:
        """The pipeline's hash input and byte count. A text-only result is left to the pipeline: output_hash is
        sha256(utf8(text)) and bytes its length (§2.4.2). With an image, audio or blob payload, where T is
        utf8(sealed text), P the decoded payload of a binary part, n the index of its content item, t that
        item's type, and u64 an 8-byte big-endian length or index:
            output_hash = sha256(0xFF || u64(len T) || T || for each binary part, in item order:
                                 u64(n) || u64(len t) || t || u64(len P) || P)
            bytes = len T + the sum of len P (no framing)
        Every part is length-prefixed, and 0xFF never occurs in UTF-8, so no other result hashes the same."""
        parts = [(n, c["type"].encode("ascii"), base64.b64decode(d[k])) for n, c, d, k, binary in self._parts(content)
                 if binary]
        if not parts:
            return None, None
        u64 = lambda v: v.to_bytes(8, "big")
        t = text.encode("utf-8", "surrogatepass")
        framed = [b"\xff", u64(len(t)), t]
        for n, kind, p in parts:
            framed += [u64(n), u64(len(kind)), kind, u64(len(p)), p]
        return b"".join(framed), len(t) + sum(len(p) for _, _, p in parts)

    @staticmethod
    def _parts(content: list) -> list:
        """(index, item, container, key, binary) for every field of the items that reaches the harness, in order:
        strings (sealed and cleaned), then the base64 payload."""
        found = []
        for n, c in enumerate(content):
            if c["type"] == "resource":
                holder, (strs, binary) = c["resource"], RESOURCE
            else:
                holder, (strs, binary) = c, ITEMS[c["type"]]
            found += [(n, c, holder, k, False) for k in strs if k in holder]
            found += [(n, c, holder, k, True) for k in binary if k in holder]
        return found

    def _rewrite(self, content: list) -> tuple[list, int, bool]:
        """Strip and truncate every sealed string, in order, as the pipeline did the whole text. Decoded
        payloads draw on the same budget; _items already kept them within it. (content, budget left, cut)."""
        cfg, budget, cut = self.guard.cfg, self.guard.cfg.max_result_bytes, False
        for _, _, d, k, binary in self._parts(content):
            if binary:
                budget -= len(base64.b64decode(d[k]))
                continue
            t = unicode.strip(d[k]) if cfg.invisible_unicode == "strip" else d[k]
            b = t.encode("utf-8", "surrogatepass")
            cut = cut or len(b) > budget
            d[k], budget = b[:max(budget, 0)].decode("utf-8", "ignore"), budget - len(b)
        return content, budget, cut

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.guard.sessions.discard(self)
        if self.owned:
            outcome = "blocked" if self.last_blocked else "completed"
            try:
                await asyncio.to_thread(task.end_task, self.guard.ledger, self.agent_session, self.task_seq, outcome)
            except (Unreachable, Refused):
                pass                  # the ledger closes the task as timeout when the session expires
            if self.stdio:
                await asyncio.to_thread(self._clear)

    def _clear(self) -> None:
        """Drop the ended task from the state file. Load-only: shutdown never opens a session. The sibling
        guards of a stdio owner that closes first fail closed at the ledger (the task is ended)."""
        cfg = self.guard.cfg
        path = task.state_path(cfg)
        try:
            with task.locked(path):
                st = task.load(path, cfg.agent_id)
                if st and st.task_seq == self.task_seq:
                    st.tasks = []
                    task.save(st, path)
        except OSError:
            pass


async def run(cfg: Config, server_name: str, ledger: Ledger, http_listen: str = "") -> None:
    server = next((s for s in cfg.servers if s.name == server_name), None)
    if server is None:
        raise ValueError(f"no server named {server_name!r} in {cfg.path}")
    if http_listen and ":" not in http_listen:
        raise ValueError(f"--http {http_listen}: expected HOST:PORT")
    host, port = http_listen.rsplit(":", 1) if http_listen else ("", "")
    tls = {}
    if http_listen and not _loopback(host):
        if not (cfg.tls_cert and cfg.tls_key and cfg.tools_token):
            raise ValueError(f"--http {http_listen} is off loopback: mcp.tls_cert, mcp.tls_key and "
                             "mcp.tools_token_env are required")
        tls = {"ssl_certfile": cfg.tls_cert, "ssl_keyfile": cfg.tls_key}
    guard = Guard(cfg, server, ledger)
    await guard.start()
    try:
        if http_listen:
            app = mcp.http_app(guard.new_session, cfg.allowed_origins, cfg.tools_token)
            await uvicorn.Server(uvicorn.Config(app, host=host.strip("[]"), port=int(port), log_level="warning",
                                                **tls)).serve()
        else:
            reader, write = await mcp.stdio_streams()
            await mcp.serve_stdio(guard.new_session, reader, write)
    finally:
        await guard.aclose()
