"""An agent session is bound to the address that opened it. Behind a load balancer or from serverless functions the node cannot see a stable
address, so a hosted node can switch the check off (SIJILL_SESSION_ADDR_BIND=0); the agent's key proof and tokens still guard the session."""

from agentkit import HDR, agent_node, register, session
from conftest import sqlite

BODY = {"intent_hash": "a" * 64, "harness": "http-agent", "session_id": "conv-1", "repo": "", "commit": "", "lockfile_hash": "", "delegated_from": ""}


def start_from_another_address(tmp_path, **settings) -> int:
    client, s = agent_node(tmp_path, **settings)
    with client:
        register(client)
        sess = session(client)
        sqlite(s.db_path, "UPDATE agent_sessions SET remote_addr = '203.0.113.9'")
        r = client.post("/api/agent/task/start", json=BODY, headers={**HDR, "X-Sijil-Agent-Session": sess["agent_session"]})
        return r.status_code


def test_a_session_used_from_another_address_is_refused_by_default(tmp_path):
    assert start_from_another_address(tmp_path) == 401


def test_the_address_check_can_be_switched_off_for_a_hosted_node(tmp_path):
    assert start_from_another_address(tmp_path, bind_session_addr=False) == 200


def test_the_setting_reads_the_environment(monkeypatch):
    from sijill.proxy import Settings
    assert Settings.from_env().bind_session_addr is True
    monkeypatch.setenv("SIJILL_SESSION_ADDR_BIND", "0")
    assert Settings.from_env().bind_session_addr is False
