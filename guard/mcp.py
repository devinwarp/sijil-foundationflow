"""MCP transports (protocol revision 2025-06-18): JSON-RPC 2.0 over stdio (one message per line) and over
streamable HTTP, both towards the wrapped server (upstream) and towards the harness (downstream).

The guard sits in the middle, so it is a client upstream and a server downstream. Downstream HTTP answers
with application/json only: it never opens an SSE stream, so it cannot send the harness a request; a session
there reports `can_request = False` and `confirm` rules get no elicitation (spec §5.7: unavailable).
"""

import asyncio
import itertools
import json
import os
import secrets
from contextlib import asynccontextmanager
from typing import Awaitable, Callable

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

PROTOCOL = "2025-06-18"
METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL, SIJIL = -32601, -32602, -32603, -32000


class RpcError(Exception):
    def __init__(self, code: int, message: str, data=None):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data

    def obj(self) -> dict:
        return {"code": self.code, "message": self.message, **({"data": self.data} if self.data is not None else {})}


Notify = Callable[[str, dict], Awaitable[None]]


async def _ignore(method: str, params: dict) -> None:
    return None


_background: set = set()


def _spawn(coro) -> None:
    """Run a notification handler on its own: it may call back into the transport that delivered it (a
    tools/list after list_changed), which would deadlock the reader if awaited in place."""
    t = asyncio.ensure_future(coro)
    _background.add(t)
    t.add_done_callback(_background.discard)


class StdioUpstream:
    """A wrapped server we spawn and talk to over its stdin and stdout."""

    def __init__(self, command: str, args: list[str], env: dict, on_notification: Notify = _ignore):
        self.command, self.args, self.env, self.on_notification = command, args, env, on_notification
        self.ids, self.pending, self.proc, self.reader = itertools.count(1), {}, None, None

    async def start(self) -> None:
        self.proc = await asyncio.create_subprocess_exec(
            self.command, *self.args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            env={**os.environ, **self.env}, limit=2 ** 24)
        self.reader = asyncio.create_task(self._read())

    async def _read(self) -> None:
        async for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            if "method" not in msg and msg.get("id") in self.pending:
                self.pending.pop(msg["id"]).set_result(msg)
            elif "method" in msg and "id" in msg:     # server-to-client requests are not relayed
                await self._send({"jsonrpc": "2.0", "id": msg["id"],
                                  "error": RpcError(METHOD_NOT_FOUND, "not supported through sijil-guard").obj()})
            elif "method" in msg:
                _spawn(self.on_notification(msg["method"], msg.get("params") or {}))
        for fut in self.pending.values():
            fut.set_exception(RpcError(INTERNAL, "wrapped server exited"))
        self.pending.clear()

    async def _send(self, msg: dict) -> None:
        self.proc.stdin.write(json.dumps(msg, ensure_ascii=False).encode() + b"\n")
        await self.proc.stdin.drain()

    async def request(self, method: str, params: dict | None = None, timeout: float = 120.0) -> dict:
        if self.proc.returncode is not None or self.reader.done():
            raise RpcError(INTERNAL, "wrapped server exited")
        rid = next(self.ids)
        fut = asyncio.get_running_loop().create_future()
        self.pending[rid] = fut
        await self._send({"jsonrpc": "2.0", "id": rid, "method": method, **({"params": params} if params else {})})
        msg = await asyncio.wait_for(fut, timeout)
        if "error" in msg:
            e = msg["error"]
            raise RpcError(e.get("code", INTERNAL), e.get("message", ""), e.get("data"))
        return msg.get("result", {})

    async def notify(self, method: str, params: dict | None = None) -> None:
        await self._send({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})

    async def close(self) -> None:
        if self.proc and self.proc.returncode is None:
            self.proc.stdin.close()
            try:
                await asyncio.wait_for(self.proc.wait(), 5)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()


class HttpUpstream:
    """A wrapped server reached over streamable HTTP. Answers come back as JSON or as an SSE stream."""

    def __init__(self, url: str, headers: dict, on_notification: Notify = _ignore,
                 http: httpx.AsyncClient | None = None):
        self.url, self.headers, self.on_notification = url, headers, on_notification
        self.http = http or httpx.AsyncClient(timeout=120.0)
        self.ids, self.session_id, self.version = itertools.count(1), None, None

    async def start(self) -> None:
        return None

    def _headers(self) -> dict:
        return {**self.headers, "Accept": "application/json, text/event-stream", "Content-Type": "application/json",
                **({"Mcp-Session-Id": self.session_id} if self.session_id else {}),
                **({"MCP-Protocol-Version": self.version} if self.version else {})}

    async def request(self, method: str, params: dict | None = None) -> dict:
        rid = next(self.ids)
        body = {"jsonrpc": "2.0", "id": rid, "method": method, **({"params": params} if params else {})}
        try:
            async with self.http.stream("POST", self.url, json=body, headers=self._headers()) as r:
                if r.status_code >= 400:
                    raise RpcError(INTERNAL, f"wrapped server answered HTTP {r.status_code}")
                if method == "initialize":
                    self.session_id = r.headers.get("mcp-session-id")
                msg = await self._answer(r, rid)
        except httpx.HTTPError as e:
            raise RpcError(INTERNAL, f"wrapped server unreachable: {e}") from e
        if "error" in msg:
            e = msg["error"]
            raise RpcError(e.get("code", INTERNAL), e.get("message", ""), e.get("data"))
        if method == "initialize":
            self.version = msg.get("result", {}).get("protocolVersion", PROTOCOL)
        return msg.get("result", {})

    async def _answer(self, r: httpx.Response, rid: int) -> dict:
        if r.headers.get("content-type", "").startswith("text/event-stream"):
            data = []
            async for line in r.aiter_lines():
                if line.startswith("data:"):
                    data.append(line[5:].lstrip())
                elif line == "" and data:
                    msg, data = json.loads("\n".join(data)), []
                    if msg.get("id") == rid and "method" not in msg:
                        return msg
                    if "method" in msg and "id" not in msg:
                        _spawn(self.on_notification(msg["method"], msg.get("params") or {}))
            raise RpcError(INTERNAL, "wrapped server closed the stream without an answer")
        return json.loads(await r.aread())

    async def notify(self, method: str, params: dict | None = None) -> None:
        body = {"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})}
        try:
            await self.http.post(self.url, json=body, headers=self._headers())
        except httpx.HTTPError as e:
            raise RpcError(INTERNAL, f"wrapped server unreachable: {e}") from e

    async def close(self) -> None:
        if self.session_id:
            try:
                await self.http.delete(self.url, headers=self._headers())
            except httpx.HTTPError:
                pass


class Client:
    """The harness, as one downstream session sees it."""
    can_request = False

    async def request(self, method: str, params: dict) -> dict:
        raise RpcError(METHOD_NOT_FOUND, "this transport cannot send the client a request")

    async def notify(self, method: str, params: dict) -> None:
        return None


class Session:
    """One downstream MCP session: what serve.py implements. handle() answers a request or raises RpcError."""

    async def handle(self, method: str, params: dict) -> dict:
        raise RpcError(METHOD_NOT_FOUND, f"method not found: {method}")

    async def notified(self, method: str, params: dict) -> None:
        return None

    async def close(self) -> None:
        return None


NewSession = Callable[[Client, dict], Awaitable[Session]]     # (client, request headers) -> session


class StdioClient(Client):
    can_request = True

    def __init__(self, write: Callable[[bytes], Awaitable[None]]):
        self.write, self.ids, self.pending = write, itertools.count(1), {}

    async def send(self, msg: dict) -> None:
        await self.write(json.dumps(msg, ensure_ascii=False).encode() + b"\n")

    async def request(self, method: str, params: dict, timeout: float = 300.0) -> dict:
        rid = f"sijil-{next(self.ids)}"
        fut = asyncio.get_running_loop().create_future()
        self.pending[rid] = fut
        await self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        msg = await asyncio.wait_for(fut, timeout)
        if "error" in msg:
            raise RpcError(msg["error"].get("code", INTERNAL), msg["error"].get("message", ""))
        return msg.get("result", {})

    async def notify(self, method: str, params: dict) -> None:
        await self.send({"jsonrpc": "2.0", "method": method, "params": params})


async def _answer(session: Session, msg: dict) -> dict:
    try:
        result = await session.handle(msg["method"], msg.get("params") or {})
        return {"jsonrpc": "2.0", "id": msg["id"], "result": result}
    except RpcError as e:
        return {"jsonrpc": "2.0", "id": msg["id"], "error": e.obj()}
    except Exception as e:                      # a guard bug must not hang the harness
        return {"jsonrpc": "2.0", "id": msg["id"], "error": RpcError(INTERNAL, f"sijil-guard: {e}").obj()}


async def serve_stdio(new_session: NewSession, reader: asyncio.StreamReader,
                      write: Callable[[bytes], Awaitable[None]]) -> None:
    """One session over a line stream; returns at EOF after closing the session (spec §5.9: task_end)."""
    client = StdioClient(write)
    session = await new_session(client, {})
    tasks = set()

    async def run(msg: dict) -> None:
        await client.send(await _answer(session, msg))
    try:
        while line := await reader.readline():
            try:
                msg = json.loads(line)
            except ValueError:
                await client.send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
                continue
            if not isinstance(msg, dict):
                continue
            if "method" in msg and "id" in msg:
                t = asyncio.create_task(run(msg))
                tasks.add(t)
                t.add_done_callback(tasks.discard)
            elif "method" in msg:
                await session.notified(msg["method"], msg.get("params") or {})
            elif msg.get("id") in client.pending:
                client.pending.pop(msg["id"]).set_result(msg)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        await session.close()


async def stdio_streams() -> tuple[asyncio.StreamReader, Callable[[bytes], Awaitable[None]]]:
    """The process's own stdin and stdout as an asyncio line reader and an awaitable writer."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=2 ** 24)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(0, "rb", 0))
    out = os.fdopen(1, "wb", 0)

    async def write(data: bytes) -> None:
        out.write(data)
    return reader, write


def http_app(new_session: NewSession) -> FastAPI:
    """Streamable HTTP, JSON answers only. initialize opens a session (Mcp-Session-Id); DELETE closes it."""
    sessions: dict[str, Session] = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        for session in list(sessions.values()):   # shutting down ends every open task (spec §5.9)
            await session.close()
        sessions.clear()

    app = FastAPI(lifespan=lifespan)

    @app.post("/mcp")
    async def post(request: Request):
        try:
            msg = await request.json()
        except ValueError:
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
                                400)
        if not isinstance(msg, dict) or "method" not in msg:
            return Response(status_code=202)       # responses and batches: nothing this server asked for
        sid = request.headers.get("mcp-session-id")
        if msg["method"] == "initialize" and "id" in msg:
            sid = "ms_" + secrets.token_hex(16)
            sessions[sid] = await new_session(Client(), dict(request.headers))
        elif sid not in sessions:
            return JSONResponse({"jsonrpc": "2.0", "id": msg.get("id"),
                                 "error": {"code": -32600, "message": "unknown or missing Mcp-Session-Id"}}, 404)
        session = sessions[sid]
        if "id" not in msg:
            await session.notified(msg["method"], msg.get("params") or {})
            return Response(status_code=202)
        return JSONResponse(await _answer(session, msg), headers={"Mcp-Session-Id": sid})

    @app.delete("/mcp")
    async def delete(request: Request):
        session = sessions.pop(request.headers.get("mcp-session-id", ""), None)
        if session is None:
            return Response(status_code=404)
        await session.close()
        return Response(status_code=204)

    @app.get("/mcp")
    async def get():
        return Response(status_code=405)           # no server-initiated stream

    app.state.sessions = sessions
    return app
