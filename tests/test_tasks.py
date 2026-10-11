"""Row 5b, task half: task start/end with ledger counts, timeout close, and chat calls bound to their task."""

import json

from agentkit import AGENT, INTENT, OPS, agent_node, chat, register, session, start_task
from conftest import rows, sqlite, verify
from sijill import agents


def opened(client) -> dict:
    """Register the agent and open a key-mode session."""
    register(client)
    return session(client)


def end(client, sess, task_seq, outcome="completed"):
    return client.post("/api/agent/task/end", json={"task_seq": str(task_seq), "outcome": outcome},
                       headers={"X-Sijil-Agent-Session": sess["agent_session"]})


def test_task_start_is_stamped_by_the_ledger(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        sess = opened(client)
        seq = start_task(client, sess, agent_auth="oidc", principal_auth="oidc", cwd="/srv/agent")
    rec = rows(s.db_path)[-1]
    x = json.loads(rec["ext"])
    assert seq == 2 and (rec["agent_id"], rec["principal"], rec["task_seq"], rec["input_hash"]) == (AGENT, OPS, "", INTENT)
    assert (x["agent_auth"], x["principal_auth"], x["agent_session"], x["cwd"]) == \
        ("key", "none", sess["agent_session"], "/srv/agent")
    code, line = verify(s.db_path, s.pubkey_path)
    assert code == 0 and "agent_auth=key:1,mtls:0,oidc:0,relay:0,none:0" in line


def test_chat_in_a_task_carries_the_task_and_counts_are_ints(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        sess = opened(client)
        t = start_task(client, sess)
        assert chat(client, sess).status_code == 200
        assert chat(client, sess, "my emirates id is 784").headers["x-sijill-decision"] == "flag"
        r = end(client, sess, t, "completed")
        assert r.status_code == 200
    *_, inf1, inf2, task_end = rows(s.db_path)
    assert [(i["agent_id"], i["principal"], i["task_seq"]) for i in (inf1, inf2, task_end)] == [(AGENT, OPS, "2")] * 3
    x = json.loads(task_end["ext"])
    assert x == {"outcome": "completed", "inference": 2, "tool_calls": 0, "blocked": 0, "confirmed": 0,
                 "denied": 0, "flagged": 1, "egress": 0, "last_seq": 4}
    assert all(type(v) is int for k, v in x.items() if k != "outcome")
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_empty_task_ends_with_zero_counts_at_its_own_seq(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        sess = opened(client)
        t = start_task(client, sess)
        assert end(client, sess, t, "aborted").json()["last_seq"] == t
        assert end(client, sess, t).status_code == 409             # one task_end per task
    assert [r["type"] for r in rows(s.db_path)].count("task_end") == 1
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_two_open_tasks_need_the_task_header(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        sess = opened(client)
        start_task(client, sess)
        second = start_task(client, sess, session_id="conv-2")
        before = len(rows(s.db_path))
        assert chat(client, sess).status_code == 409
        assert len(rows(s.db_path)) == before
        assert chat(client, sess, task_seq=second).status_code == 200
    assert rows(s.db_path)[-1]["task_seq"] == str(second)


def test_another_sessions_task_is_refused(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        sess = opened(client)
        t = start_task(client, sess)
        other = session(client)
        assert chat(client, other, task_seq=t).status_code == 409
        assert end(client, other, t).status_code == 409


def test_outside_a_task_the_session_identity_is_used(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        sess = opened(client)
        assert chat(client, sess).status_code == 200
        assert chat(client).status_code == 200                      # a plain proxy user: no identity
    inf, plain = rows(s.db_path)[1:]
    assert (inf["agent_id"], inf["principal"], inf["task_seq"]) == (AGENT, OPS, "")
    assert (plain["agent_id"], plain["principal"]) == ("", "")
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_bad_session_header_is_401_and_unsealed(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        sess = opened(client)
        assert chat(client, {"agent_session": "as_nope"}).status_code == 401
        sqlite(s.db_path, "UPDATE agent_sessions SET remote_addr = '10.0.0.9'")
        assert chat(client, sess).status_code == 401
        assert chat(client, None, task_seq=2).status_code == 401
    assert len(rows(s.db_path)) == 1


def test_expired_session_closes_its_task_as_timeout(tmp_path, monkeypatch):
    client, s = agent_node(tmp_path)
    with client:
        sess = opened(client)
        t = start_task(client, sess)
        chat(client, sess)
        later = agents.clock() + 3601
        monkeypatch.setattr(agents, "clock", lambda: later)
        assert chat(client, sess).status_code == 401
        fresh = session(client)
        start_task(client, fresh)                                   # any session-bound call sweeps
    ends = [r for r in rows(s.db_path) if r["type"] == "task_end"]
    assert len(ends) == 1 and ends[0]["task_seq"] == str(t)
    assert json.loads(ends[0]["ext"])["outcome"] == "timeout" and json.loads(ends[0]["ext"])["inference"] == 1
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_restart_after_expiry_closes_open_tasks(tmp_path, monkeypatch):
    client, s = agent_node(tmp_path)
    with client:
        sess = opened(client)
        start_task(client, sess)
    later = agents.clock() + 3601
    monkeypatch.setattr(agents, "clock", lambda: later)
    client, s = agent_node(tmp_path)
    with client:
        pass
    assert rows(s.db_path)[-1]["type"] == "task_end"
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_delegated_from_must_name_a_task_start(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        sess = opened(client)
        r = client.post("/api/agent/task/start", headers={"X-Sijil-Agent-Session": sess["agent_session"]},
                        json={"intent_hash": INTENT, "harness": "http-agent", "delegated_from": "1"})
        assert r.status_code == 400
        parent = start_task(client, sess)
        child = start_task(client, sess, delegated_from=str(parent))
        assert end(client, sess, child).status_code == 200
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_task_endpoints_need_a_session(tmp_path):
    client, s = agent_node(tmp_path)
    with client:
        opened(client)
        assert client.post("/api/agent/task/start", json={"intent_hash": INTENT}).status_code == 401
