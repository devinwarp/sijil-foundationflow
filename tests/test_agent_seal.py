"""Row 5: /api/agent/seal, /parent and /context; every record they write passes the verifier (spec §5.4-5.6)."""

import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from agentkit import AGENT, OPS, agent_node, chat, register, session, start_task
from conftest import rows, verify
from sijill import agents, record

NOTE = {"caseId": "MOI-2026-004211", "note": "Applicant uploaded the missing salary certificate."}
NOTE_HASH = record.sha256_hex(record.canonical_json(NOTE))
PACK = "rulepack_id: moi-case-pack\nversion: 0.1.0\nrules: []\n"
PACK_HASH = record.sha256_hex(PACK.encode())


def model(request: httpx.Request) -> httpx.Response:
    """Asks for addCaseNote unless the prompt says 'plain'."""
    prompt = json.loads(request.content)["messages"][-1]["content"]
    message = {"role": "assistant", "content": "Done."} if "plain" in prompt else {
        "role": "assistant", "content": None, "tool_calls": [
            {"id": "call_N1aB", "type": "function", "function": {"name": "addCaseNote", "arguments": json.dumps(NOTE)}}]}
    return httpx.Response(200, json={"id": "c", "model": "m", "choices": [{"index": 0, "message": message,
                                                                           "finish_reason": "stop"}]})


TOOL_CALL = {"type": "tool_call", "input_hash": NOTE_HASH, "rulepack_hash": PACK_HASH,
             "ext": {"harness": "http-agent", "session_id": "conv-1", "tool": "addCaseNote", "server": "case-api",
                     "qualified": "http:case-api:addCaseNote", "tool_use_id": "call_N1aB",
                     "correlation": "tool_use_id", "observed_by": "http_adapter",
                     "summary": {"method": "POST", "host": "case.moi.internal",
                                 "path_template": "/cases/{caseId}/notes", "arg_keys": ["caseId", "note"]}}}
RESULT_EXT = {"tool": "addCaseNote", "server": "case-api", "status": "ok", "bytes": 2,
              "content_types": ["application/json"], "invisible_unicode": {"found": False, "count": 0, "action": "none"},
              "http_status": 201}
EGRESS_EXT = {"host": "case.moi.internal", "port": 443, "proto": "https", "observed_by": "http_adapter",
              "allowed_by": "rulepack"}


@pytest.fixture
def flow(tmp_path):
    """A registered agent with a session, an open task and one inference that requested addCaseNote."""
    (tmp_path / "pack.yaml").write_text(PACK)
    client, s = agent_node(tmp_path, model, rulepack_path=str(tmp_path / "pack.yaml"))
    with client:
        register(client)
        sess = session(client)
        task = start_task(client, sess)
        assert chat(client, sess, "add the note").status_code == 200
        h = {"X-Sijil-Agent-Session": sess["agent_session"]}
        yield client, s, sess, task, h


def seal(client, h, **body):
    return client.post("/api/agent/seal", json=body, headers=h)


def test_parent_by_tool_use_id_and_by_args_hash(flow):
    client, s, sess, task, h = flow
    inference = task + 1
    r = client.get("/api/agent/parent", params={"tool_use_id": "call_N1aB"}, headers=h).json()
    assert r == {"tool_use_id": "call_N1aB", "seq": inference, "name": "addCaseNote", "args_hash": NOTE_HASH,
                 "correlation": "tool_use_id"}
    r = client.get("/api/agent/parent", params={"name": "addCaseNote", "args_hash": NOTE_HASH}, headers=h).json()
    assert (r["seq"], r["correlation"]) == (inference, "args_hash")
    assert client.get("/api/agent/parent", params={"name": "closeCase", "args_hash": NOTE_HASH},
                      headers=h).json() == {"detail": {"correlation": "none"}}


def test_full_tool_round_trip_passes_the_verifier(flow):
    client, s, sess, task, h = flow
    inference = task + 1
    call = seal(client, h, **TOOL_CALL, parent_seq=str(inference), task_seq=task)   # an int task_seq is accepted
    assert call.status_code == 200 and call.json()["decision"] == "allow"
    call_seq = str(call.json()["seq"])
    # consumed: the same (name, args_hash) no longer resolves to that inference
    assert client.get("/api/agent/parent", params={"name": "addCaseNote", "args_hash": NOTE_HASH},
                      headers=h).status_code == 404
    assert seal(client, h, type="egress", parent_seq=call_seq, rulepack_hash=PACK_HASH, ext=EGRESS_EXT).status_code == 200
    result = seal(client, h, type="tool_result", parent_seq=call_seq, source_label="http:case-api",
                  output_hash=record.sha256_hex(b"{}"), rulepack_hash=PACK_HASH, ext=RESULT_EXT)
    assert result.status_code == 200
    again = seal(client, h, type="tool_result", parent_seq=call_seq, source_label="http:case-api",
                 rulepack_hash=PACK_HASH, ext=RESULT_EXT)
    assert again.status_code == 409
    assert chat(client, sess, "add another").status_code == 200
    nxt = rows(s.db_path)[-1]["seq"]
    ctx = client.get("/api/agent/context", params={"before_seq": nxt}, headers=h).json()
    assert ctx == {"labels": ["http:case-api"], "seqs": [result.json()["seq"]]}
    end = client.post("/api/agent/task/end", json={"task_seq": str(task), "outcome": "completed"}, headers=h).json()
    assert (end["inference"], end["tool_calls"], end["egress"]) == (2, 1, 1)
    for rec in rows(s.db_path, f"seq > {task}"):
        assert (rec["agent_id"], rec["principal"], rec["task_seq"], rec["rulepack_hash"]) == \
            (AGENT, OPS, str(task), PACK_HASH)
    code, line = verify(s.db_path, s.pubkey_path)
    assert code == 0 and line.startswith(f"PASS records={len(rows(s.db_path))} ")


def test_turn_window_starts_after_the_last_plain_answer(flow):
    client, s, sess, task, h = flow
    call = seal(client, h, **TOOL_CALL, parent_seq=str(task + 1)).json()["seq"]
    seal(client, h, type="tool_result", parent_seq=str(call), source_label="http:case-api",
         rulepack_hash=PACK_HASH, ext=RESULT_EXT)
    chat(client, sess, "plain answer please")                    # a turn boundary: no tools requested
    chat(client, sess, "add the note again")
    nxt = rows(s.db_path)[-1]["seq"]
    assert client.get("/api/agent/context", params={"before_seq": nxt, "window": "turn"},
                      headers=h).json() == {"labels": [], "seqs": []}
    assert client.get("/api/agent/context", params={"before_seq": nxt},
                      headers=h).json()["labels"] == ["http:case-api"]


@pytest.mark.parametrize("change, status", [
    ({"input_hash": record.sha256_hex(b"other args")}, 400),            # B2: not what the model asked for
    ({"parent_seq": "1"}, 400),                                         # A2: seq 1 is the rulepack_change
    ({"rulepack_hash": "0" * 64}, 409),                                 # stale rule pack
    ({"type": "task_start"}, 400),                                      # not sealable here
    ({"type": "approval"}, 400),                                        # row 18g, M2d
])
def test_refused_bodies_seal_nothing(flow, change, status):
    client, s, sess, task, h = flow
    before = len(rows(s.db_path))
    assert seal(client, h, **{**TOOL_CALL, "parent_seq": str(task + 1), **change}).status_code == status
    assert len(rows(s.db_path)) == before


def test_parent_in_another_task_is_refused(flow):
    client, s, sess, task, h = flow
    other = start_task(client, sess, session_id="conv-2")
    r = seal(client, h, **TOOL_CALL, parent_seq=str(task + 1), task_seq=str(other))
    assert r.status_code == 400 and r.json()["detail"] == "parent in a different task"


def test_body_identity_is_ignored(flow):
    client, s, sess, task, h = flow
    r = seal(client, h, **TOOL_CALL, parent_seq=str(task + 1), agent_id="spiffe://evil/agent/x",
             principal="local:" + "0" * 64)
    assert r.status_code == 200
    rec = rows(s.db_path)[-1]
    assert (rec["agent_id"], rec["principal"]) == (AGENT, OPS)


def test_halt_turns_an_agent_tool_call_into_a_block(flow):
    client, s, sess, task, h = flow
    client.post("/api/admin/halt", json={"halted": True})
    r = seal(client, h, **TOOL_CALL, parent_seq=str(task + 1))
    assert r.json()["decision"] == "block"
    rec = rows(s.db_path)[-1]
    assert (rec["mode"], json.loads(rec["rule_hits"])) == ("enforce", ["halted"])
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_orphan_tool_call_is_sealed_and_counted(flow):
    client, s, sess, task, h = flow
    ext = {**TOOL_CALL["ext"], "correlation": "none"}
    del ext["tool_use_id"]
    assert seal(client, h, **{**TOOL_CALL, "ext": ext}).status_code == 200
    assert verify(s.db_path, s.pubkey_path)[1].endswith("tool_call without parent inference")
    code, line = verify(s.db_path, s.pubkey_path, "--allow-orphan-tool-calls")
    assert code == 0 and "orphans=1" in line


def test_seal_without_a_task_is_refused_for_task_types(tmp_path):
    (tmp_path / "pack.yaml").write_text(PACK)
    client, s = agent_node(tmp_path, model, rulepack_path=str(tmp_path / "pack.yaml"))
    with client:
        register(client)
        h = {"X-Sijil-Agent-Session": session(client)["agent_session"]}
        assert seal(client, h, **TOOL_CALL).status_code == 409
        baseline = {"lockfile": ".sijil/lock.json", "lockfile_hash": "0b1c" + "8" * 60, "entries": 3, "files": 1,
                    "mcp_tools": 2, "roots": ["repo"], "tool": "sijil-lock/0.1.0", "invisible_unicode_entries": 0}
        r = seal(client, h, type="integrity_baseline", input_hash=baseline["lockfile_hash"],
                 rulepack_hash=PACK_HASH, ext=baseline)
        assert r.status_code == 200
    rec = rows(s.db_path)[-1]
    assert (rec["agent_id"], rec["task_seq"]) == (AGENT, "")
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def hold_lock(client, n):
    """Hold the seal lock from the server loop; returns (loop, release)."""
    loop = client.portal.call(asyncio.get_running_loop)
    asyncio.run_coroutine_threadsafe(n.lock.acquire(), loop).result()
    return loop, lambda: loop.call_soon_threadsafe(n.lock.release)


def test_concurrent_tool_results_for_one_call_seal_once(flow):
    client, s, sess, task, h = flow
    n = client.app.state.node
    call = str(seal(client, h, **TOOL_CALL, parent_seq=str(task + 1)).json()["seq"])
    body = dict(type="tool_result", parent_seq=call, source_label="http:case-api", rulepack_hash=PACK_HASH,
                ext=RESULT_EXT)
    _, release = hold_lock(client, n)
    with ThreadPoolExecutor(2) as pool:
        futs = [pool.submit(seal, client, h, **body) for _ in range(2)]
        time.sleep(0.3)                 # both requests are past their pre-checks and queued on the lock
        release()
        codes = sorted(f.result().status_code for f in futs)
    assert codes == [200, 409]
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_task_end_between_check_and_seal_seals_nothing_into_the_task(flow):
    client, s, sess, task, h = flow
    n = client.app.state.node
    loop, release = hold_lock(client, n)
    ended = asyncio.run_coroutine_threadsafe(agents.end_task(n, n.store.get(task), "aborted"), loop)
    with ThreadPoolExecutor(1) as pool:
        fut = pool.submit(seal, client, h, **TOOL_CALL, parent_seq=str(task + 1), task_seq=str(task))
        time.sleep(0.3)                 # task_end is queued first; the seal passed task_for while the task was open
        release()
        r = fut.result()
    ended.result()
    assert r.status_code == 409 and r.json()["detail"] == "task already ended"
    assert [x["type"] for x in rows(s.db_path)][-1] == "task_end"
    assert verify(s.db_path, s.pubkey_path)[0] == 0


@pytest.mark.parametrize("change", [
    {"mode": 1}, {"parent_seq": None}, {"output_hash": [1]}, {"ext": {"x": "\\ud800"}},   # JSON-escaped lone surrogate, sent as raw bytes
    {"type": "integrity_baseline", "parent_seq": "2"},
])
def test_malformed_bodies_are_400_and_seal_nothing(flow, change):
    client, s, sess, task, h = flow
    before = len(rows(s.db_path))
    body = {**TOOL_CALL, "parent_seq": str(task + 1), **change}
    r = client.post("/api/agent/seal", content=json.dumps(body).replace("\\\\ud800", "\\ud800"),
                    headers={**h, "Content-Type": "application/json"})
    assert r.status_code == 400
    assert len(rows(s.db_path)) == before
