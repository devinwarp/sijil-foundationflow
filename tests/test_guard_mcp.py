"""Row 8 transports: JSON-RPC over MCP stdio and streamable HTTP, upstream and downstream (MCP 2025-06-18)."""

import asyncio
import json
import logging
import sys
import time

import httpx
import pytest
from fastapi.testclient import TestClient

import mcp_mock
from conftest import ROOT
from guard import mcp

MOCK = [sys.executable, str(ROOT / "tests" / "mcp_mock.py")]


def test_stdio_upstream_round_trip_notifications_and_refused_server_requests():
    async def go():
        notes = []

        async def on_note(method, params):
            notes.append(method)
        up = mcp.StdioUpstream(MOCK[0], MOCK[1:], {}, on_note)
        await up.start()
        init = await up.request("initialize", {"protocolVersion": mcp.PROTOCOL, "capabilities": {},
                                               "clientInfo": {"name": "t", "version": "1"}})
        await up.notify("notifications/initialized")
        names = [t["name"] for t in (await up.request("tools/list"))["tools"]]
        got = await up.request("tools/call", {"name": "get_issue", "arguments": {"issueId": "S-1"}})
        roots = await up.request("tools/call", {"name": "ask_roots", "arguments": {}})
        await up.request("tools/call", {"name": "changed", "arguments": {}})
        with pytest.raises(mcp.RpcError) as e:
            await up.request("tools/call", {"name": "nope", "arguments": {}})
        await up.close()
        with pytest.raises(mcp.RpcError, match="exited"):
            await up.request("tools/list")
        return init, names, got, roots, notes, e.value
    init, names, got, roots, notes, err = asyncio.run(go())
    assert init["serverInfo"]["name"] == "mock" and "get_issue" in names
    assert got["content"][0]["text"] == mcp_mock.SENTRY_TEXT
    assert json.loads(roots["content"][0]["text"])["error"]["code"] == mcp.METHOD_NOT_FOUND
    assert notes == ["notifications/tools/list_changed"] and err.code == -32602


@pytest.mark.parametrize("sse", [False, True])
def test_http_upstream_json_and_sse_answers_and_the_session_header(sse):
    app = mcp_mock.app()

    async def go():
        notes = []

        async def on_note(method, params):
            notes.append(method)
        http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://mock")
        up = mcp.HttpUpstream("http://mock/mcp", {"Authorization": "Bearer pat", **({"X-Mock-SSE": "1"} if sse else {})},
                              on_note, http)
        await up.request("initialize", {"protocolVersion": mcp.PROTOCOL, "capabilities": {},
                                        "clientInfo": {"name": "t", "version": "1"}})
        await up.notify("notifications/initialized")
        got = await up.request("tools/call", {"name": "run_command", "arguments": {"command": "ls"}})
        await up.close()
        return got, notes
    got, notes = asyncio.run(go())
    assert got["content"][0]["text"] == "ran: ls"
    assert notes == (["notifications/progress"] * 2 if sse else [])
    assert app.state.seen == [("initialize", None, "Bearer pat"), ("notifications/initialized", "mock-session", "Bearer pat"),
                              ("tools/call", "mock-session", "Bearer pat"), ("DELETE", "mock-session", None)]


def test_http_upstream_unreachable_is_an_rpc_error():
    def down(request):
        raise httpx.ConnectError("refused")

    async def go():
        up = mcp.HttpUpstream("http://x/mcp", {}, http=httpx.AsyncClient(transport=httpx.MockTransport(down)))
        await up.request("tools/list")
    with pytest.raises(mcp.RpcError, match="unreachable"):
        asyncio.run(go())


class Echo(mcp.Session):
    """Answers echo; `confirm` asks the client first; records the lifecycle."""

    def __init__(self, client, headers, log):
        self.client, self.log = client, log
        log.append(("open", client.can_request, headers.get("x-sijil-principal-token")))

    async def handle(self, method, params):
        if method == "initialize":
            return {"protocolVersion": mcp.PROTOCOL}
        if method == "echo":
            return {"echo": params}
        if method == "confirm":
            answer = await self.client.request("elicitation/create", {"message": "Allow?"})
            return {"answer": answer}
        if method == "crash":
            raise ValueError("bug")
        raise mcp.RpcError(mcp.METHOD_NOT_FOUND, method)

    async def notified(self, method, params):
        self.log.append(("note", method))

    async def close(self):
        self.log.append(("close",))


def test_stdio_downstream_answers_requests_asks_the_client_and_closes_at_eof():
    log, out = [], []

    async def go():
        reader = asyncio.StreamReader()

        async def write(data: bytes):
            msg = json.loads(data)
            out.append(msg)
            if msg.get("method") == "elicitation/create":     # the harness answers the guard's question
                reader.feed_data(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                             "result": {"action": "accept", "content": {"allow": True}}}).encode() + b"\n")
                reader.feed_eof()

        async def new(client, headers):
            return Echo(client, headers, log)
        for m in ({"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"a": 1}},
                  {"jsonrpc": "2.0", "method": "notifications/initialized"}, "not json",
                  {"jsonrpc": "2.0", "id": 2, "method": "crash"}, {"jsonrpc": "2.0", "id": 3, "method": "confirm"}):
            reader.feed_data((m if isinstance(m, str) else json.dumps(m)).encode() + b"\n")
        await mcp.serve_stdio(new, reader, write)
    asyncio.run(go())
    by_id = {m.get("id"): m for m in out if "method" not in m}
    assert by_id[1]["result"] == {"echo": {"a": 1}} and by_id[None]["error"]["code"] == -32700
    assert by_id[2]["error"] == {"code": mcp.INTERNAL, "message": "sijil-guard: internal error"}
    assert by_id[3]["result"] == {"answer": {"action": "accept", "content": {"allow": True}}}
    assert log == [("open", True, None), ("note", "notifications/initialized"), ("close",)]


def test_a_cancelled_initialize_closes_its_session():
    """Final review Minor 12: a session whose initialize never finished is closed (its owned task ended)."""
    log, started = [], asyncio.Event()

    class Slow(Echo):
        async def handle(self, method, params):
            started.set()
            await asyncio.Event().wait()

    async def go():
        async def new(client, headers):
            return Slow(client, headers, log)
        app = mcp.http_app(new)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://guard") as h:
            req = asyncio.create_task(h.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"}))
            await started.wait()
            req.cancel()
            with pytest.raises(asyncio.CancelledError):
                await req
        return app.state.sessions
    assert asyncio.run(go()) == {} and log[-1] == ("close",)


def test_http_downstream_sessions():
    log = []

    async def new(client, headers):
        return Echo(client, headers, log)
    with TestClient(mcp.http_app(new)) as c:
        r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                   headers={"X-Sijil-Principal-Token": "tok"})
        sid = r.headers["mcp-session-id"]
        assert r.json()["result"] == {"protocolVersion": mcp.PROTOCOL} and sid.startswith("ms_")
        assert c.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "echo"}).status_code == 400   # missing
        assert c.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "echo"},
                      headers={"Mcp-Session-Id": "ms_x"}).status_code == 404                           # unknown
        assert c.delete("/mcp").status_code == 400
        h = {"Mcp-Session-Id": sid}
        assert c.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "echo", "params": {"b": 2}},
                      headers=h).json()["result"] == {"echo": {"b": 2}}
        assert c.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "confirm"}, headers=h).json()["error"][
            "code"] == mcp.METHOD_NOT_FOUND                     # no elicitation over JSON-only HTTP
        assert c.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=h).status_code == 202
        assert c.get("/mcp").status_code == 405 and c.post("/mcp", content=b"{").status_code == 400
        assert c.delete("/mcp", headers=h).status_code == 204 and c.delete("/mcp", headers=h).status_code == 404
        c.post("/mcp", json={"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {}})
    assert log == [("open", False, "tok"), ("note", "notifications/initialized"), ("close",),
                   ("open", False, None), ("close",)]        # the open session is closed at shutdown


# ---- failure modes of the transports ----

INIT = {"protocolVersion": mcp.PROTOCOL, "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}


def call(name, **args):
    return {"name": name, "arguments": args}


def stdio(coro_fn, on_note=None):
    """Run coro_fn(up) against a started, initialized mock; always closes it."""
    async def go():
        up = mcp.StdioUpstream(MOCK[0], MOCK[1:], {}, on_note or mcp._ignore)
        await up.start()
        try:
            await up.request("initialize", INIT)
            return await asyncio.wait_for(coro_fn(up), 20)
        finally:
            await up.close()
    return asyncio.run(go())


def test_stdio_upstream_crash_with_a_request_pending_fails_it_and_every_later_one():
    async def go(up):
        waiting = asyncio.ensure_future(up.request("tools/call", call("sleep", seconds=30)))
        await asyncio.sleep(0.1)
        with pytest.raises(mcp.RpcError, match="exited"):
            await up.request("tools/call", call("crash"))
        with pytest.raises(mcp.RpcError, match="exited"):
            await waiting
        with pytest.raises(mcp.RpcError, match="exited"):
            await up.request("tools/list")
        with pytest.raises(mcp.RpcError):
            await up.notify("notifications/initialized")
        return up.pending
    assert stdio(go) == {}


def test_stdio_upstream_timeout_then_a_late_answer_leaves_the_session_working():
    async def go(up):
        with pytest.raises(mcp.RpcError, match="no answer"):
            await up.request("tools/call", call("sleep", seconds=0.3), timeout=0.1)
        assert up.pending == {}
        await asyncio.sleep(0.5)                          # the late answer arrives for an id nobody waits on
        assert not up.reader.done()
        return (await up.request("tools/list"))["tools"]
    assert stdio(go)


def test_stdio_upstream_concurrent_requests_are_matched_by_id_not_by_order():
    async def go(up):
        slow = asyncio.ensure_future(up.request("tools/call", call("sleep", seconds=0.4, say="slow")))
        await asyncio.sleep(0.05)
        fast, listing = await asyncio.gather(up.request("tools/call", call("run_command", command="x")),
                                             up.request("tools/list"))
        return fast, listing, await slow
    fast, listing, slow = stdio(go)
    assert fast["content"][0]["text"] == "ran: x" and listing["tools"]
    assert slow["content"][0]["text"] == "slow"


def test_stdio_upstream_skips_garbage_lines_and_odd_ids():
    async def go(up):
        return await up.request("tools/call", call("garbage"))
    assert stdio(go)["content"][0]["text"] == "ok"


def test_stdio_upstream_oversize_line_fails_the_session_closed(monkeypatch):
    monkeypatch.setattr(mcp, "MAX_LINE", 1000)

    async def go(up):
        with pytest.raises(mcp.RpcError, match="exited"):
            await up.request("tools/call", call("oversize", size=5000))
        with pytest.raises(mcp.RpcError, match="exited"):
            await up.request("tools/list")
        return up.pending
    assert stdio(go) == {}


def test_stdio_upstream_notification_handler_may_call_back_into_the_transport():
    seen = []

    async def go(up):
        async def on_note(method, params):
            seen.append((method, len((await up.request("tools/list"))["tools"])))
        up.on_notification = on_note
        await up.request("tools/call", call("changed"))
        await up.tasks.wait()
    stdio(go)
    assert seen and seen[0][0] == "notifications/tools/list_changed" and seen[0][1] > 0


def test_tasks_are_bounded_logged_and_cancelled(caplog):
    async def go():
        tasks, ran = mcp._Tasks(cap=2), []

        async def boom():
            raise ValueError("handler bug")

        async def hang():
            await asyncio.sleep(30)
        tasks.spawn(boom())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        for _ in range(4):
            tasks.spawn(hang())
        n = len(tasks.live)
        await tasks.cancel()
        return n, len(tasks.live)
    with caplog.at_level(logging.WARNING, logger="sijil.guard.mcp"):
        assert asyncio.run(go()) == (2, 0)
    assert "handler bug" in caplog.text and "dropped a handler" in caplog.text


def http_up(handler, **kw):
    return mcp.HttpUpstream("http://x/mcp", {}, http=httpx.AsyncClient(transport=httpx.MockTransport(handler)), **kw)


def run_http(handler, method="tools/list", **kw):
    async def go():
        up = http_up(handler)
        try:
            return await up.request(method, **kw)
        finally:
            await up.close()
    return asyncio.run(go())


@pytest.mark.parametrize("response", [
    httpx.Response(200, content=b"", headers={"content-type": "application/json"}),
    httpx.Response(200, content=b"<html>", headers={"content-type": "text/html"}),
    httpx.Response(200, json=[1, 2]),
    httpx.Response(200, json={"jsonrpc": "2.0", "id": 1}),
    httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": "nope"}),
    httpx.Response(500, content=b"down"),
    httpx.Response(200, content=b"data: {}\n\n", headers={"content-type": "text/event-stream"}),
])
def test_http_upstream_bad_answers_are_rpc_errors(response):
    with pytest.raises(mcp.RpcError):
        run_http(lambda request: response)


def test_http_upstream_oversize_bodies_are_cut_off(monkeypatch):
    monkeypatch.setattr(mcp, "MAX_LINE", 1000)
    with pytest.raises(mcp.RpcError, match="too much"):
        run_http(lambda request: httpx.Response(200, content=b"x" * 5000))
    with pytest.raises(mcp.RpcError, match="too much"):
        run_http(lambda request: httpx.Response(200, content=b"data: " + b"x" * 5000,
                                                headers={"content-type": "text/event-stream"}))


def test_http_upstream_overall_timeout():
    async def slow(request):
        await asyncio.sleep(5)
    with pytest.raises(mcp.RpcError, match="no answer"):
        run_http(slow, timeout=0.1)


def test_http_upstream_sse_server_request_is_refused_and_junk_events_are_skipped():
    posted = []

    def handler(request):
        msg = json.loads(request.content)
        posted.append(msg)
        if "method" not in msg:
            return httpx.Response(202)
        events = ["data: not json", '{"id": 7}'.replace("{", "data: {", 1),
                  "data: " + json.dumps({"jsonrpc": "2.0", "id": "srv-9", "method": "roots/list"}),
                  "data: " + json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"ok": True}})]
        return httpx.Response(200, content="\n\n".join(events).encode() + b"\n\n",
                              headers={"content-type": "text/event-stream"})

    async def go():
        up = http_up(handler)
        got = await up.request("tools/list")
        await up.tasks.wait()
        await up.close()
        return got
    assert asyncio.run(go()) == {"ok": True}
    refusal = [m for m in posted if "method" not in m][0]
    assert refusal["id"] == "srv-9" and refusal["error"]["code"] == mcp.METHOD_NOT_FOUND


def test_http_upstream_notify_reports_a_rejection():
    with pytest.raises(mcp.RpcError, match="HTTP 404"):
        asyncio.run(http_up(lambda request: httpx.Response(404)).notify("notifications/initialized"))


def test_http_downstream_caps_sessions_expires_idle_ones_and_refuses_failures(monkeypatch):
    monkeypatch.setattr(mcp, "MAX_SESSIONS", 2)
    monkeypatch.setattr(mcp, "MAX_REQUEST", 100)
    log = []

    async def new(client, headers):
        return Echo(client, headers, log)
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    with TestClient(mcp.http_app(new)) as c:
        first = c.post("/mcp", json=init).headers["mcp-session-id"]
        assert c.post("/mcp", json=init).status_code == 200
        assert c.post("/mcp", json=init).status_code == 503 and len(c.app.state.sessions) == 2
        monkeypatch.setattr(mcp, "SESSION_TTL", 0.0)
        time.sleep(0.01)                                  # both sessions are now idle past the TTL
        assert c.post("/mcp", json={**init, "id": 2}).status_code == 200
        assert list(c.app.state.sessions) != [first] and len(c.app.state.sessions) == 1
        assert c.post("/mcp", content=b'{"x": "' + b"a" * 200 + b'"}').status_code == 413
        assert c.post("/mcp", json=[init]).status_code == 400
    assert log.count(("close",)) == 3                      # two expired, one closed at shutdown


def test_http_downstream_failed_initialize_opens_no_session():
    class Refuse(mcp.Session):
        async def handle(self, method, params):
            raise mcp.RpcError(mcp.SIJIL, "no")
    closed = []

    async def new(client, headers):
        s = Refuse()
        s.close = lambda: closed.append(1) or asyncio.sleep(0)
        return s
    with TestClient(mcp.http_app(new)) as c:
        r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert r.json()["error"]["code"] == mcp.SIJIL and c.app.state.sessions == {}
    assert closed == [1]


def stdio_session(lines, write, new=None):
    async def go():
        reader = asyncio.StreamReader()
        for m in lines:
            reader.feed_data((m if isinstance(m, bytes) else json.dumps(m).encode()) + b"\n")
        reader.feed_eof()

        async def default(client, headers):
            return Echo(client, headers, [])
        await asyncio.wait_for(mcp.serve_stdio(new or default, reader, write), 5)
    asyncio.run(go())


def test_stdio_downstream_eof_with_a_pending_elicitation_ends_at_once():
    out, log = [], []

    async def write(data):
        out.append(json.loads(data))                      # the harness never answers the elicitation

    async def new(client, headers):
        return Echo(client, headers, log)
    started = time.monotonic()
    stdio_session([{"jsonrpc": "2.0", "id": 3, "method": "confirm"}], write, new)
    assert time.monotonic() - started < 3 and log == [("open", True, None), ("close",)]
    assert [m for m in out if m.get("id") == 3][0]["error"]["code"] == mcp.INTERNAL


def test_stdio_downstream_oversize_line_ends_the_session_and_cancels_its_handlers():
    out, log = [], []

    async def write(data):
        out.append(json.loads(data))

    async def go():
        reader = asyncio.StreamReader(limit=100)
        reader.feed_data(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "hang"}).encode() + b"\n" + b"x" * 500 + b"\n")

        class Hang(Echo):
            async def handle(self, method, params):
                await asyncio.sleep(30)

        async def new(client, headers):
            return Hang(client, headers, log)
        await asyncio.wait_for(mcp.serve_stdio(new, reader, write), 5)
    asyncio.run(go())
    assert out[-1]["error"]["message"] == "line too long" and log == [("open", True, None), ("close",)]


def test_stdio_downstream_notification_handler_may_ask_the_client():
    out = []
    reader_box = []

    class Asker(Echo):
        async def notified(self, method, params):
            self.log.append(("asked", await self.client.request("elicitation/create", {})))

    async def go():
        reader = asyncio.StreamReader()
        reader_box.append(reader)
        log = []

        async def write(data):
            msg = json.loads(data)
            out.append(msg)
            reader.feed_data(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"action": "accept"}}).encode() + b"\n")
            reader.feed_eof()

        async def new(client, headers):
            return Asker(client, headers, log)
        reader.feed_data(json.dumps({"jsonrpc": "2.0", "method": "notifications/x"}).encode() + b"\n")
        await asyncio.wait_for(mcp.serve_stdio(new, reader, write), 5)
        return log
    assert ("asked", {"action": "accept"}) in asyncio.run(go())


DEEP = b"[" * 50_000


def test_deeply_nested_json_is_malformed_not_a_crash():
    with pytest.raises(mcp.RpcError):
        run_http(lambda request: httpx.Response(200, content=DEEP))
    with pytest.raises(mcp.RpcError, match="without an answer"):   # the event is skipped, not fatal
        run_http(lambda request: httpx.Response(200, content=b"data: " + DEEP + b"\n\n",
                                                headers={"content-type": "text/event-stream"}))
    out = []

    async def write(data):
        out.append(json.loads(data))
    stdio_session([DEEP], write)
    assert out[0]["error"]["code"] == -32700
    with TestClient(mcp.http_app(lambda client, headers: None)) as c:
        assert c.post("/mcp", content=DEEP).status_code == 400

    async def go(up):
        return await up.request("tools/call", call("garbage"))
    assert stdio(go)


def test_concurrent_initializes_cannot_exceed_the_session_cap(monkeypatch):
    monkeypatch.setattr(mcp, "MAX_SESSIONS", 3)
    log = []

    async def new(client, headers):
        await asyncio.sleep(0.05)                         # every initialize is in flight together
        return Echo(client, headers, log)

    async def go():
        app = mcp.http_app(new)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            rs = await asyncio.gather(*[c.post("/mcp", json={"jsonrpc": "2.0", "id": i, "method": "initialize"})
                                        for i in range(10)])
            codes = sorted(r.status_code for r in rs)
            kept = len(app.state.sessions)
            for sid in list(app.state.sessions):
                await c.delete("/mcp", headers={"Mcp-Session-Id": sid})
            again = await c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        return codes, kept, again.status_code
    assert asyncio.run(go()) == ([200] * 3 + [503] * 7, 3, 200)
