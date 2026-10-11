"""stream: true is relayed as it arrives and sealed once, on the hash of the whole answer."""

import asyncio
import json

import httpx
import pytest

from conftest import ADMIN, MODEL, rows, sse, stub_stream, verify
from sijill import record
from sijill.policy import HALT_HIT, UPSTREAM_ERROR_HIT


def stream(client, content: str, model: str = MODEL):
    return client.stream("POST", "/v1/chat/completions", json={
        "model": model, "stream": True, "messages": [{"role": "user", "content": content}]})


def test_stream_relays_and_seals_full_answer(node_with):
    client, s = node_with(stub_stream)
    with client, stream(client, "hello") as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        assert r.headers["x-sijill-decision"] == "allow"
        lines = [l for l in r.iter_lines() if l]
    assert lines[-1] == "data: [DONE]"
    assert lines[-2].startswith(": sijill seq=1 decision=allow record_hash=")
    deltas = [json.loads(l[6:])["choices"][0]["delta"]["content"] for l in lines if l.startswith("data: {")]
    assert "".join(deltas) == "Stub answer"
    [rec] = rows(s.db_path)
    assert rec["output_hash"] == record.output_hash("Stub answer")
    assert UPSTREAM_ERROR_HIT not in rec["rule_hits"]
    assert lines[-2].endswith(rec["record_hash"])
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_stream_blocked_is_403_json_and_sealed(node_with):
    client, s = node_with(stub_stream)
    with client:
        r = client.post("/v1/chat/completions", json={
            "model": "other", "stream": True, "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 403 and r.json()["sijill"]["decision"] == "block"
    assert rows(s.db_path)[0]["decision"] == "block"


def test_stream_without_done_seals_upstream_error(node_with):
    def cut(request):
        return httpx.Response(200, content=sse(["partial"], done=False),
                              headers={"content-type": "text/event-stream"})
    client, s = node_with(cut)
    with client, stream(client, "hello") as r:
        lines = [l for l in r.iter_lines() if l]
    assert lines[-1].startswith(": sijill seq=1")
    [rec] = rows(s.db_path)
    assert UPSTREAM_ERROR_HIT in json.loads(rec["rule_hits"]) and rec["output_hash"] == ""


def test_stream_upstream_500_is_sealed_and_returned(node_with):
    def fail(request):
        return httpx.Response(500, json={"error": {"message": "boom"}})
    client, s = node_with(fail)
    with client:
        r = client.post("/v1/chat/completions", json={
            "model": MODEL, "stream": True, "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 500
    assert UPSTREAM_ERROR_HIT in json.loads(rows(s.db_path)[0]["rule_hits"])


class SlowStream(httpx.AsyncByteStream):
    """Upstream body that yields between chunks and whose close yields, like a real socket close."""

    async def __aiter__(self):
        for i in range(2000):
            await asyncio.sleep(0.001)
            yield sse([f"w{i} "], done=False)

    async def aclose(self):
        await asyncio.sleep(0)


async def raw_stream(app, *, disconnect: bool, during=None, after=None) -> list[bytes]:
    """Drive one streamed call through raw ASGI (spec 2.3, like uvicorn), lifespan included.

    disconnect=True hangs up after the first body chunk. during(client) runs once the first chunk
    is out and after(client) once the call has ended, each with an in-process client for the other
    endpoints. Returns the body chunks.
    """
    inbox: asyncio.Queue = asyncio.Queue()
    started = asyncio.Event()

    async def lifespan_send(msg):
        started.set() if msg["type"] == "lifespan.startup.complete" else None
    await inbox.put({"type": "lifespan.startup"})
    life = asyncio.create_task(app({"type": "lifespan", "asgi": {"version": "3.0"}}, inbox.get, lifespan_send))
    await asyncio.wait_for(started.wait(), 5)

    body = json.dumps({"model": MODEL, "stream": True, "messages": [{"role": "user", "content": "hello"}]}).encode()
    first_chunk = asyncio.Event()
    sent_body = False
    chunks: list[bytes] = []

    async def receive():
        nonlocal sent_body
        if not sent_body:
            sent_body = True
            return {"type": "http.request", "body": body, "more_body": False}
        await first_chunk.wait()
        if not disconnect:
            await asyncio.Event().wait()  # client stays connected; cancelled when the response ends
        return {"type": "http.disconnect"}

    async def send(msg):
        if msg["type"] == "http.response.body" and msg.get("body"):
            chunks.append(msg["body"])
            first_chunk.set()

    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
             "method": "POST", "scheme": "http", "path": "/v1/chat/completions", "raw_path": b"",
             "query_string": b"", "server": ("test", 80), "client": ("test", 1),
             "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                         (b"authorization", ADMIN["Authorization"].encode())]}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                                 headers=ADMIN) as other:
        call = asyncio.create_task(app(scope, receive, send))
        if during:
            await asyncio.wait_for(first_chunk.wait(), 5)
            await during(other)
        await asyncio.wait_for(call, 10)
        if after:
            await after(other)
    await inbox.put({"type": "lifespan.shutdown"})
    await asyncio.wait_for(life, 5)
    return chunks


def slow(request):
    return httpx.Response(200, stream=SlowStream(), headers={"content-type": "text/event-stream"})


def test_client_disconnect_still_seals_one_record(node_with):
    """Disconnect cancels the body task; the call must still seal once."""
    client, s = node_with(slow)
    asyncio.run(raw_stream(client.app, disconnect=True))
    [rec] = rows(s.db_path)
    assert UPSTREAM_ERROR_HIT in json.loads(rec["rule_hits"]) and rec["output_hash"] == ""
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_halt_mid_stream_ends_stream_and_seals_it_halted(node_with):
    """A stream already relaying when the operator halts stops; nothing is sealed `allow` after `halted`.
    The `block` record's output_hash covers exactly the content delivered before the halt."""
    client, s = node_with(slow)

    async def halt(other):
        assert (await other.post("/api/admin/halt", json={"halted": True})).json()["seq"]

    async def resume(other):
        assert (await other.post("/api/admin/halt", json={"halted": False})).json()["seq"]

    text = b"".join(asyncio.run(raw_stream(client.app, disconnect=False, during=halt, after=resume))).decode()
    assert "data: [DONE]" not in text and text.count("data: {") < 2000
    recs = rows(s.db_path)
    kinds = [(r["type"], json.loads(r["rule_hits"])) for r in recs]
    start = kinds.index(("policy_change", [HALT_HIT]))
    end = kinds.index(("policy_change", ["resumed"]))
    between = recs[start + 1:end]
    assert [r for r in between if r["decision"] == "allow"] == []
    [rec] = [r for r in recs if r["type"] == "inference"]
    assert {HALT_HIT, UPSTREAM_ERROR_HIT} <= set(json.loads(rec["rule_hits"]))
    delivered = [json.loads(line[6:])["choices"][0]["delta"]["content"]
                 for line in text.splitlines() if line.startswith("data: {")]
    assert delivered                                  # halted after partial output reached the client
    assert rec["output_hash"] == record.output_hash("".join(delivered))
    assert f"record_hash={rec['record_hash']}" in text
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_in_stream_error_event_seals_upstream_error(node_with):
    """vLLM reports a mid-stream failure as `data: {"error": ...}` and may still send [DONE]."""
    def errs(request):
        body = sse(["partial"], done=False) + b'data: {"error": {"message": "out of memory"}}\n\ndata: [DONE]\n\n'
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})
    client, s = node_with(errs)
    with client, stream(client, "hello") as r:
        "".join(r.iter_lines())
    [rec] = rows(s.db_path)
    assert UPSTREAM_ERROR_HIT in json.loads(rec["rule_hits"]) and rec["output_hash"] == ""


def test_upstream_closed_even_when_seal_fails(node_with):
    """A seal failure (e.g. HSM session lost) must not leak the upstream connection."""
    closed = []

    class Tracked(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield sse(["a"])

        async def aclose(self):
            closed.append(True)

    client, _ = node_with(lambda req: httpx.Response(200, stream=Tracked(),
                                                     headers={"content-type": "text/event-stream"}))
    with client:
        async def broken(body):
            raise RuntimeError("signer unavailable")
        client.app.state.node.seal = broken
        with pytest.raises(RuntimeError, match="signer unavailable"):
            with stream(client, "hello") as r:
                "".join(r.iter_lines())
    assert closed
