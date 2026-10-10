"""stream: true is relayed as it arrives and sealed once, on the hash of the whole answer."""

import json

import httpx

from conftest import MODEL, rows, sse, stub_stream, verify
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


def test_client_disconnect_still_seals_one_record(node_with):
    def long_stream(request):
        return httpx.Response(200, content=sse([f"w{i} " for i in range(2000)]),
                              headers={"content-type": "text/event-stream"})
    client, s = node_with(long_stream)
    with client:
        with stream(client, "hello") as r:
            next(r.iter_lines())  # read one line, then hang up
        recs = rows(s.db_path)
    assert len(recs) == 1
    assert verify(s.db_path, s.pubkey_path)[0] == 0
