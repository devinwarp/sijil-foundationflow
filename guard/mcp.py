"""MCP transports (protocol revision 2025-06-18): JSON-RPC 2.0 over stdio (one message per line) and over
streamable HTTP, both towards the wrapped server (upstream) and towards the harness (downstream).

The guard sits in the middle, so it is a client upstream and a server downstream. Downstream HTTP answers
with application/json only: it never opens an SSE stream, so it cannot send the harness a request; a session
there reports `can_request = False` and `confirm` rules get no elicitation (spec §5.7: unavailable).

The wrapped server is untrusted. Every request ends in its result, an `RpcError` or a timeout; every pending
entry is removed on every exit path; the reader dying for any reason fails all pending requests; and nothing
the server sends is buffered past MAX_LINE bytes (a line, an HTTP body, or one SSE stream).
"""

import asyncio
import hmac
import itertools
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from typing import Awaitable, Callable
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

PROTOCOL = "2025-06-18"
METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL, SIJIL = -32601, -32602, -32603, -32000
INVALID_REQUEST = -32600
MAX_LINE = 2 ** 24            # most bytes taken from the wrapped server in one line, body or stream
MAX_REQUEST = 2 ** 22         # most bytes taken from the harness in one HTTP request body
MAX_TASKS = 64                # notification handlers in flight per transport; more are dropped and logged
MAX_SESSIONS = 256            # downstream HTTP sessions open at once
SESSION_TTL = 3600.0          # seconds a downstream HTTP session may sit idle

log = logging.getLogger("sijil.guard.mcp")


class RpcError(Exception):
    def __init__(self, code: int, message: str, data=None):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data

    def obj(self) -> dict:
        return {"code": self.code, "message": self.message, **({"data": self.data} if self.data is not None else {})}


Notify = Callable[[str, dict], Awaitable[None]]


async def _ignore(method: str, params: dict) -> None:
    return None


class _Tasks:
    """Handlers spawned off a transport's reader: they may call back into that transport (a tools/list after
    list_changed), which would deadlock the reader if awaited in place. Bounded, observed and cancellable."""

    def __init__(self, cap: int = MAX_TASKS):
        self.cap, self.live = cap, set()

    def spawn(self, coro, force: bool = False) -> None:
        if len(self.live) >= self.cap and not force:
            coro.close()
            log.warning("dropped a handler: %d already running", len(self.live))
            return
        t = asyncio.ensure_future(coro)
        self.live.add(t)
        t.add_done_callback(self._done)

    def _done(self, t: asyncio.Task) -> None:
        self.live.discard(t)
        if not t.cancelled() and t.exception() is not None:
            log.warning("handler failed: %r", t.exception())

    async def wait(self) -> None:
        while self.live:
            await asyncio.gather(*self.live, return_exceptions=True)

    async def cancel(self) -> None:
        others = [t for t in self.live if t is not asyncio.current_task()]
        for t in others:
            t.cancel()
        await asyncio.gather(*others, return_exceptions=True)


def _loads(raw):
    """json.loads for untrusted input: nesting too deep is malformed JSON like any other (ValueError)."""
    try:
        return json.loads(raw)
    except RecursionError:
        raise ValueError("JSON nested too deeply") from None


def _params(msg: dict) -> dict:
    p = msg.get("params")
    return p if isinstance(p, dict) else {}


def _fail_all(pending: dict, reason: str) -> None:
    for fut in pending.values():
        if not fut.done():
            fut.set_exception(RpcError(INTERNAL, reason))
    pending.clear()


def _resolve(pending: dict, msg: dict) -> None:
    """Give an answer to the request waiting for it. Ids that are not plain ints or strings (a list is
    unhashable, True == 1) match nothing."""
    rid = msg.get("id")
    if isinstance(rid, bool) or not isinstance(rid, (int, str)):
        return
    fut = pending.pop(rid, None)
    if fut is not None and not fut.done():
        fut.set_result(msg)


def _result(msg: dict) -> dict:
    if "error" in msg:
        e = msg["error"]
        if not isinstance(e, dict):
            raise RpcError(INTERNAL, "wrapped peer sent a malformed error")
        raise RpcError(e.get("code", INTERNAL), str(e.get("message", "")), e.get("data"))
    result = msg.get("result")
    if not isinstance(result, dict):
        raise RpcError(INTERNAL, "wrapped peer sent an answer without a result object")
    return result


async def _call(pending: dict, rid, send: Callable[[], Awaitable[None]], timeout: float) -> dict:
    """Send a request and wait for its answer. Ends in the result, an RpcError or a timeout; the pending
    entry is removed whichever way it ends."""
    fut = asyncio.get_running_loop().create_future()
    pending[rid] = fut
    try:
        await send()
        msg = await asyncio.wait_for(fut, timeout)
    except asyncio.TimeoutError:
        raise RpcError(INTERNAL, f"no answer within {timeout}s") from None
    except OSError as e:
        raise RpcError(INTERNAL, f"send failed: {e}") from e
    finally:
        pending.pop(rid, None)
    return _result(msg)


class StdioUpstream:
    """A wrapped server we spawn and talk to over its stdin and stdout."""

    def __init__(self, command: str, args: list[str], env: dict, on_notification: Notify = _ignore):
        self.command, self.args, self.env, self.on_notification = command, args, env, on_notification
        self.ids, self.pending, self.proc, self.reader, self.tasks = itertools.count(1), {}, None, None, _Tasks()

    async def start(self) -> None:
        self.proc = await asyncio.create_subprocess_exec(
            self.command, *self.args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            env={**os.environ, **self.env}, limit=MAX_LINE)
        self.reader = asyncio.create_task(self._read())

    async def _read(self) -> None:
        try:
            while line := await self.proc.stdout.readline():
                try:
                    msg = _loads(line)
                except ValueError:
                    log.warning("skipped a line from the wrapped server that is not JSON")
                    continue
                if not isinstance(msg, dict):
                    continue
                if "method" not in msg:
                    _resolve(self.pending, msg)
                elif not isinstance(msg["method"], str):
                    continue
                elif "id" in msg:                   # server-to-client requests are not relayed
                    self.tasks.spawn(self._refuse(msg["id"]))
                else:
                    self.tasks.spawn(self.on_notification(msg["method"], _params(msg)))
        except Exception as e:                      # an oversize line, or any bug: the session is no longer trusted
            log.warning("wrapped server stream failed: %r", e)
            if self.proc.returncode is None:
                self.proc.kill()
        finally:
            _fail_all(self.pending, "wrapped server exited")

    async def _refuse(self, rid) -> None:
        try:
            await self._send({"jsonrpc": "2.0", "id": rid,
                              "error": RpcError(METHOD_NOT_FOUND, "not supported through sijil-guard").obj()})
        except OSError:
            pass

    async def _send(self, msg: dict) -> None:
        self.proc.stdin.write(json.dumps(msg, ensure_ascii=False).encode() + b"\n")
        await self.proc.stdin.drain()

    def _alive(self) -> bool:
        return self.proc is not None and self.proc.returncode is None and not self.reader.done()

    async def request(self, method: str, params: dict | None = None, timeout: float = 120.0) -> dict:
        if not self._alive():
            raise RpcError(INTERNAL, "wrapped server exited")
        rid = next(self.ids)
        body = {"jsonrpc": "2.0", "id": rid, "method": method, **({"params": params} if params else {})}
        return await _call(self.pending, rid, lambda: self._send(body), timeout)

    async def notify(self, method: str, params: dict | None = None) -> None:
        if not self._alive():
            raise RpcError(INTERNAL, "wrapped server exited")
        try:
            await self._send({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})
        except OSError as e:
            raise RpcError(INTERNAL, f"send failed: {e}") from e

    async def close(self) -> None:
        if self.proc and self.proc.returncode is None:
            self.proc.stdin.close()
            try:
                await asyncio.wait_for(self.proc.wait(), 5)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        if self.reader:
            self.reader.cancel()
            await asyncio.gather(self.reader, return_exceptions=True)
        _fail_all(self.pending, "wrapped server exited")
        await self.tasks.cancel()


async def _capped(r: httpx.Response):
    """The chunks of a response body, never more than MAX_LINE bytes of it in all."""
    total = 0
    async for chunk in r.aiter_bytes():
        total += len(chunk)
        if total > MAX_LINE:
            raise RpcError(INTERNAL, "wrapped server sent too much")
        yield chunk


async def _lines(r: httpx.Response):
    buf = b""
    async for chunk in _capped(r):
        *done, buf = (buf + chunk).split(b"\n")
        for line in done:
            yield line.rstrip(b"\r").decode("utf-8", "replace")


class HttpUpstream:
    """A wrapped server reached over streamable HTTP. Answers come back as JSON or as an SSE stream."""

    def __init__(self, url: str, headers: dict, on_notification: Notify = _ignore,
                 http: httpx.AsyncClient | None = None):
        self.url, self.headers, self.on_notification = url, headers, on_notification
        self.http, self.own_http = http or httpx.AsyncClient(timeout=120.0), http is None
        self.ids, self.session_id, self.version, self.tasks = itertools.count(1), None, None, _Tasks()

    async def start(self) -> None:
        return None

    def _headers(self) -> dict:
        return {**self.headers, "Accept": "application/json, text/event-stream", "Content-Type": "application/json",
                **({"Mcp-Session-Id": self.session_id} if self.session_id else {}),
                **({"MCP-Protocol-Version": self.version} if self.version else {})}

    async def request(self, method: str, params: dict | None = None, timeout: float = 120.0) -> dict:
        rid = next(self.ids)
        body = {"jsonrpc": "2.0", "id": rid, "method": method, **({"params": params} if params else {})}
        try:
            msg = await asyncio.wait_for(self._post(method, rid, body), timeout)
        except asyncio.TimeoutError:
            raise RpcError(INTERNAL, f"no answer within {timeout}s") from None
        except httpx.HTTPError as e:
            raise RpcError(INTERNAL, f"wrapped server unreachable: {e}") from e
        result = _result(msg)
        if method == "initialize":
            v = result.get("protocolVersion", PROTOCOL)
            self.version = v if isinstance(v, str) else PROTOCOL
        return result

    async def _post(self, method: str, rid: int, body: dict) -> dict:
        async with self.http.stream("POST", self.url, json=body, headers=self._headers()) as r:
            if r.status_code >= 400:
                raise RpcError(INTERNAL, f"wrapped server answered HTTP {r.status_code}")
            if method == "initialize":
                self.session_id = r.headers.get("mcp-session-id")
            if r.headers.get("content-type", "").startswith("text/event-stream"):
                return await self._sse(r, rid)
            raw = b"".join([c async for c in _capped(r)])
        try:
            msg = _loads(raw)
        except ValueError:
            raise RpcError(INTERNAL, "wrapped server answered with a body that is not JSON") from None
        if not isinstance(msg, dict):
            raise RpcError(INTERNAL, "wrapped server answered with something other than a JSON object")
        return msg

    async def _sse(self, r: httpx.Response, rid: int) -> dict:
        data = []
        async for line in _lines(r):
            if line.startswith("data:"):
                data.append(line[6:] if line.startswith("data: ") else line[5:])
            elif line == "" and data:
                raw, data = "\n".join(data), []
                try:
                    msg = _loads(raw)
                except ValueError:
                    log.warning("skipped an SSE event that is not JSON")
                    continue
                if not isinstance(msg, dict):
                    continue
                if "method" not in msg:
                    if type(msg.get("id")) is int and msg["id"] == rid:
                        return msg
                elif not isinstance(msg["method"], str):
                    continue
                elif "id" in msg:                   # a server-to-client request, refused as on stdio
                    self.tasks.spawn(self._refuse(msg["id"]))
                else:
                    self.tasks.spawn(self.on_notification(msg["method"], _params(msg)))
        raise RpcError(INTERNAL, "wrapped server closed the stream without an answer")

    async def _refuse(self, rid) -> None:
        body = {"jsonrpc": "2.0", "id": rid,
                "error": RpcError(METHOD_NOT_FOUND, "not supported through sijil-guard").obj()}
        try:
            await self._ack(body)
        except (httpx.HTTPError, RpcError):
            pass

    async def _ack(self, body: dict, timeout: float = 30.0) -> None:
        """POST a message that wants no answer; only the status is read."""
        async def go():
            async with self.http.stream("POST", self.url, json=body, headers=self._headers()) as r:
                if r.status_code >= 400:
                    raise RpcError(INTERNAL, f"wrapped server answered HTTP {r.status_code}")
        try:
            await asyncio.wait_for(go(), timeout)
        except asyncio.TimeoutError:
            raise RpcError(INTERNAL, f"no answer within {timeout}s") from None

    async def notify(self, method: str, params: dict | None = None) -> None:
        try:
            await self._ack({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})
        except httpx.HTTPError as e:
            raise RpcError(INTERNAL, f"wrapped server unreachable: {e}") from e

    async def close(self) -> None:
        await self.tasks.cancel()
        if self.session_id:
            try:
                await asyncio.wait_for(self.http.delete(self.url, headers=self._headers()), 5)
            except (httpx.HTTPError, asyncio.TimeoutError):
                pass
        if self.own_http:
            await self.http.aclose()


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
        self.write, self.ids, self.pending, self.closed = write, itertools.count(1), {}, False

    def close(self) -> None:
        """The harness is gone: fail what waits for it, and every request made from here on."""
        self.closed = True
        _fail_all(self.pending, "the harness closed the stream")

    async def send(self, msg: dict) -> None:
        await self.write(json.dumps(msg, ensure_ascii=False).encode() + b"\n")

    async def request(self, method: str, params: dict, timeout: float = 300.0) -> dict:
        if self.closed:
            raise RpcError(INTERNAL, "the harness closed the stream")
        rid = f"sijil-{next(self.ids)}"
        body = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        return await _call(self.pending, rid, lambda: self.send(body), timeout)

    async def notify(self, method: str, params: dict) -> None:
        try:
            await self.send({"jsonrpc": "2.0", "method": method, "params": params})
        except OSError as e:
            raise RpcError(INTERNAL, f"send failed: {e}") from e


async def _answer(session: Session, msg: dict) -> dict:
    method, params = msg["method"], msg.get("params")
    try:
        if not isinstance(method, str):
            raise RpcError(INVALID_REQUEST, "method must be a string")
        if params is not None and not isinstance(params, dict):
            raise RpcError(INVALID_PARAMS, "params must be an object")
        return {"jsonrpc": "2.0", "id": msg["id"], "result": await session.handle(method, params or {})}
    except RpcError as e:
        return {"jsonrpc": "2.0", "id": msg["id"], "error": e.obj()}
    except Exception:                               # a guard bug must not hang the harness
        log.exception("session.handle failed")
        return {"jsonrpc": "2.0", "id": msg["id"], "error": RpcError(INTERNAL, "sijil-guard: internal error").obj()}


async def serve_stdio(new_session: NewSession, reader: asyncio.StreamReader,
                      write: Callable[[bytes], Awaitable[None]]) -> None:
    """One session over a line stream; returns at EOF after closing the session (spec §5.9: task_end).
    A line over MAX_LINE ends the session. On any exit the handlers still running are cancelled."""
    client = StdioClient(write)
    session = await new_session(client, {})
    tasks = _Tasks()

    async def run(msg: dict) -> None:
        try:
            await client.send(await _answer(session, msg))
        except OSError:
            log.warning("could not write an answer: the harness is gone")

    async def notified(method: str, params: dict) -> None:
        await session.notified(method, params)
    try:
        while True:
            try:
                line = await reader.readline()
            except ValueError:
                await client.send({"jsonrpc": "2.0", "id": None,
                                   "error": {"code": INVALID_REQUEST, "message": "line too long"}})
                return                              # fail closed: the handlers still running are cancelled below
            if not line:
                break
            if not line.strip():
                continue
            try:
                msg = _loads(line)
            except ValueError:
                await client.send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
                continue
            if not isinstance(msg, dict):
                continue
            if "method" in msg and "id" in msg:
                tasks.spawn(run(msg), force=True)
            elif isinstance(msg.get("method"), str):
                tasks.spawn(notified(msg["method"], _params(msg)))
            elif "method" not in msg:
                _resolve(client.pending, msg)
        client.close()
        await tasks.wait()
    finally:
        client.close()
        try:
            await tasks.cancel()
        finally:
            await session.close()


async def stdio_streams() -> tuple[asyncio.StreamReader, Callable[[bytes], Awaitable[None]]]:
    """The process's own stdin and stdout as an asyncio line reader and an awaitable writer."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=MAX_LINE)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(0, "rb", 0))
    out = os.fdopen(1, "wb", 0)

    async def write(data: bytes) -> None:
        out.write(data)
    return reader, write


def _error(status: int, code: int, message: str, rid=None) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}, status)


def origin_ok(origin: str, allowed: tuple = ()) -> bool:
    """MCP 2025-06-18 DNS-rebinding defence: loopback origins and the configured ones pass."""
    if origin in allowed:
        return True
    try:
        u = urlsplit(origin)
        return u.scheme in ("http", "https") and u.hostname in ("localhost", "127.0.0.1", "::1")
    except ValueError:
        return False


def http_app(new_session: NewSession, allowed_origins: tuple = (), token: str = "") -> FastAPI:
    """Streamable HTTP, JSON answers only. initialize opens a session (Mcp-Session-Id); DELETE closes it.
    At most MAX_SESSIONS sessions are open, and one idle for SESSION_TTL seconds is closed. A request whose
    Origin header is present and neither loopback nor in allowed_origins gets 403. With a token, every request
    must carry it in X-Sijil-Tools-Token (compared in constant time) or gets 401."""
    sessions: dict[str, Session] = {}
    touched: dict[str, float] = {}
    opening = [0]                                   # initializes in flight, counted against MAX_SESSIONS

    async def drop(sid: str) -> None:
        session = sessions.pop(sid, None)
        touched.pop(sid, None)
        if session is not None:
            try:
                await session.close()
            except Exception:
                log.exception("closing a session failed")

    async def expire() -> None:
        now = time.monotonic()
        for sid in [s for s, t in touched.items() if now - t > SESSION_TTL]:
            await drop(sid)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            yield
        finally:
            for sid in list(sessions):                # shutting down ends every open task (spec §5.9)
                await drop(sid)

    app = FastAPI(lifespan=lifespan)

    @app.middleware("http")
    async def check_origin(request: Request, call_next):
        origin = request.headers.get("origin")
        if origin is not None and not origin_ok(origin, allowed_origins):
            return _error(403, INVALID_REQUEST, "Origin not allowed")
        if token and not hmac.compare_digest(request.headers.get("x-sijil-tools-token", "").encode(), token.encode()):
            return _error(401, INVALID_REQUEST, "missing or wrong X-Sijil-Tools-Token")
        return await call_next(request)

    async def body_of(request: Request) -> bytes | None:
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_REQUEST:
                return None
        return body

    @app.post("/mcp")
    async def post(request: Request):
        raw = await body_of(request)
        if raw is None:
            return _error(413, INVALID_REQUEST, "request body too large")
        try:
            msg = _loads(raw)
        except ValueError:
            return _error(400, -32700, "parse error")
        if isinstance(msg, list):
            return _error(400, INVALID_REQUEST, "batches are not supported")
        if not isinstance(msg, dict) or "method" not in msg:
            return Response(status_code=202)       # responses: nothing this server asked for
        await expire()
        sid = request.headers.get("mcp-session-id")
        if msg["method"] == "initialize" and "id" in msg:
            if len(sessions) + opening[0] >= MAX_SESSIONS:      # a slot is held from here, across the awaits
                return _error(503, SIJIL, "too many open sessions", msg["id"])
            opening[0] += 1
            try:
                sid = "ms_" + secrets.token_hex(16)
                session = await new_session(Client(), dict(request.headers))
                try:
                    out = await _answer(session, msg)
                except BaseException:                           # cancelled: its owned task must not stay open
                    await session.close()
                    raise
                if "error" in out:                              # a failed initialize opens nothing
                    await session.close()
                    return JSONResponse(out)
                sessions[sid], touched[sid] = session, time.monotonic()
            finally:
                opening[0] -= 1
            return JSONResponse(out, headers={"Mcp-Session-Id": sid})
        if not sid:                                     # MCP 2025-06-18: 400; 404 would tell it to re-initialize
            return _error(400, INVALID_REQUEST, "missing Mcp-Session-Id", msg.get("id"))
        if sid not in sessions:
            return _error(404, INVALID_REQUEST, "unknown Mcp-Session-Id", msg.get("id"))
        session, touched[sid] = sessions[sid], time.monotonic()
        if "id" not in msg:
            try:
                await session.notified(msg["method"], _params(msg))
            except Exception:
                log.exception("session.notified failed")
            return Response(status_code=202)
        return JSONResponse(await _answer(session, msg), headers={"Mcp-Session-Id": sid})

    @app.delete("/mcp")
    async def delete(request: Request):
        sid = request.headers.get("mcp-session-id", "")
        if sid not in sessions:
            return Response(status_code=404 if sid else 400)
        await drop(sid)
        return Response(status_code=204)

    @app.get("/mcp")
    async def get():
        return Response(status_code=405)           # no server-initiated stream

    app.state.sessions = sessions
    return app
