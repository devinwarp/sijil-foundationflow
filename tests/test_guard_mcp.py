"""Row 8 transports: JSON-RPC over MCP stdio and streamable HTTP, upstream and downstream (MCP 2025-06-18)."""

import asyncio
import json
import sys

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
    assert by_id[2]["error"] == {"code": mcp.INTERNAL, "message": "sijil-guard: bug"}
    assert by_id[3]["result"] == {"answer": {"action": "accept", "content": {"allow": True}}}
    assert log == [("open", True, None), ("note", "notifications/initialized"), ("close",)]


def test_http_downstream_sessions():
    log = []

    async def new(client, headers):
        return Echo(client, headers, log)
    with TestClient(mcp.http_app(new)) as c:
        r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                   headers={"X-Sijil-Principal-Token": "tok"})
        sid = r.headers["mcp-session-id"]
        assert r.json()["error"]["code"] == mcp.METHOD_NOT_FOUND and sid.startswith("ms_")
        assert c.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "echo"}).status_code == 404
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
