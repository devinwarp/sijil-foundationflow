"""stream: true is relayed as it arrives and sealed once, on the hash of the whole answer."""

import asyncio
import json

import httpx

from conftest import ADMIN, MODEL, rows, sse, stub_stream, verify
from sijill import record
from sijill.policy import UPSTREAM_ERROR_HIT


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


def test_client_disconnect_still_seals_one_record(node_with):
    """Raw ASGI, spec 2.3 (uvicorn): disconnect cancels the body task; the call must still seal once."""
    def slow(request):
        return httpx.Response(200, stream=SlowStream(), headers={"content-type": "text/event-stream"})
    client, s = node_with(slow)
    app = client.app

    async def drive():
        inbox: asyncio.Queue = asyncio.Queue()
        started = asyncio.Event()

        async def lifespan_send(msg):
            started.set() if msg["type"] == "lifespan.startup.complete" else None
        await inbox.put({"type": "lifespan.startup"})
        life = asyncio.create_task(app({"type": "lifespan", "asgi": {"version": "3.0"}}, inbox.get, lifespan_send))
        await asyncio.wait_for(started.wait(), 5)

        body = json.dumps({"model": MODEL, "stream": True,
                           "messages": [{"role": "user", "content": "hello"}]}).encode()
        first_chunk = asyncio.Event()
        sent_body = False

        async def receive():
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": body, "more_body": False}
            await first_chunk.wait()
            return {"type": "http.disconnect"}

        async def send(msg):
            if msg["type"] == "http.response.body" and msg.get("body"):
                first_chunk.set()

        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
                 "method": "POST", "scheme": "http", "path": "/v1/chat/completions", "raw_path": b"",
                 "query_string": b"", "server": ("test", 80), "client": ("test", 1),
                 "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                             (b"authorization", ADMIN["Authorization"].encode())]}
        await asyncio.wait_for(app(scope, receive, send), 10)
        await inbox.put({"type": "lifespan.shutdown"})
        await asyncio.wait_for(life, 5)

    asyncio.run(drive())
    [rec] = rows(s.db_path)
    assert UPSTREAM_ERROR_HIT in json.loads(rec["rule_hits"]) and rec["output_hash"] == ""
    assert verify(s.db_path, s.pubkey_path)[0] == 0
