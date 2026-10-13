"""Row 18g, ledger side: named human approval (spec §17.5). Requests and decisions are sealed by the ledger, the
approver is a named Entra user holding the route's role, and the ledger owns the deadline."""

import json
import time

import httpx

from agentkit import HDR, register, session
from conftest import ADMIN, MODEL, rows, verify
from govkit import CLOSE, CLOSER, OFFICER, PACK, SUPERVISOR, gov_node, human, officer, supervisor
from jwtkit import Idp, rsa_jwk
from sijill import approvals, record

RULE = "case-closure-needs-approval"


def h(obj) -> str:
    return record.sha256_hex(record.canonical_json(obj))


def open_task(client) -> tuple[dict, int]:
    assert register(client).status_code == 200
    sess = session(client)
    r = client.post("/api/agent/task/start", json={"intent_hash": "c" * 64, "harness": "http-agent",
                                                   "session_id": "conv-1"},
                    headers={"X-Sijil-Agent-Session": sess["agent_session"], "X-Sijil-Principal-Token": officer()})
    assert r.status_code == 200, r.text
    return sess, r.json()["seq"]


def think(client, sess, task, prompt="close the case") -> tuple[int, str]:
    """The model asks for closeCase; returns (inference seq, tool call id)."""
    r = client.post("/v1/chat/completions", json={"model": MODEL, "messages": [{"role": "user", "content": prompt}]},
                    headers={"X-Sijil-Agent-Session": sess["agent_session"], "X-Sijil-Task-Seq": str(task),
                             "X-Sijil-Principal-Token": officer()})
    assert r.status_code == 200, r.text
    return int(r.headers["x-sijill-seq"]), r.json()["choices"][0]["message"]["tool_calls"][0]["id"]


def ask(client, sess, parent, **over):
    body = {"parent_seq": str(parent), "correlation": "tool_use_id", "tool": "closeCase", "server": "case-api",
            "qualified": "http:case-api:closeCase", "input_hash": h(CLOSE), "rule_hits": [RULE],
            "arg_keys": sorted(CLOSE), **over}
    return client.post("/api/agent/approval/request", json=body, headers={"X-Sijil-Agent-Session": sess["agent_session"]})


def decide(client, approval_id, decision="grant", token=None, reason="Salary certificate verified."):
    return client.post(f"/api/approval/{approval_id}/decide",
                       json={"decision": decision, "reason": reason, "token": token or supervisor()})


def status(client, sess, approval_id, wait=0):
    return client.get(f"/api/agent/approval/{approval_id}", params={"wait": wait},
                      headers={"X-Sijil-Agent-Session": sess["agent_session"]}).json()


def seal_call(client, sess, parent, call_id, decision_seq, granted=True, **over):
    """The guard's tool_call after the decision (§17.5.2 step 6)."""
    rp = rows(client.app.state.node.settings.db_path)[-1]["rulepack_hash"]
    ext = {"harness": "http-agent", "session_id": "conv-1", "tool": "closeCase", "server": "case-api",
           "qualified": "http:case-api:closeCase", "tool_use_id": call_id, "correlation": "tool_use_id",
           "observed_by": "http_adapter", "confirmation": "granted" if granted else "denied",
           "approval_seq": decision_seq,
           "summary": {"method": "POST", "host": "case.moi.internal", "path_template": "/cases/{caseId}/close",
                       "arg_keys": sorted(CLOSE)}}
    body = {"type": "tool_call", "parent_seq": str(parent), "input_hash": h(CLOSE), "rule_hits": [RULE],
            "decision": "flag" if granted else "block", "mode": "record" if granted else "enforce",
            "rulepack_hash": rp, "ext": ext, **over}
    return client.post("/api/agent/seal", json=body, headers={"X-Sijil-Agent-Session": sess["agent_session"]})


def end(client, sess, task):
    return client.post("/api/agent/task/end", json={"task_seq": str(task), "outcome": "completed"},
                       headers={"X-Sijil-Agent-Session": sess["agent_session"]})


class Hooked(Idp):
    """The identity provider, plus a Teams incoming webhook that keeps what it was sent."""

    def __init__(self):
        super().__init__({"keys": [rsa_jwk()]})
        self.posted = []

    def __call__(self, request):
        if str(request.url) == "https://teams.test/hook":
            self.posted.append(json.loads(request.content))
            return httpx.Response(200)
        return super().__call__(request)


def test_a_named_approval_round_trip_is_sealed_and_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("SIJIL_TEST_TEAMS_WEBHOOK", "https://teams.test/hook")
    idp = Hooked()
    client, s, _ = gov_node(tmp_path, idp=idp, public_url="https://sijil.moi.internal")
    with client:
        sess, task = open_task(client)
        parent, call_id = think(client, sess, task)
        r = ask(client, sess, parent)
        assert r.status_code == 200, r.text
        a = r.json()
        req = rows(s.db_path, f"seq = {a['seq']}")[0]
        assert a["deadline"] == approvals.ms_ts(approvals.ts_ms(req["ts"]) + 900000)
        assert status(client, sess, a["approval_id"]) == {"approval_id": a["approval_id"], "status": "pending",
                                                          "deadline": a["deadline"], "request_seq": a["seq"],
                                                          "decision_seq": None}
        page = client.get(f"/api/approval/{a['approval_id']}").json()
        assert (page["tool"], page["arg_keys"], page["rule_hits"], page["route_id"]) == \
            ("closeCase", ["caseId", "resolution"], [RULE], "case-closure")
        assert "Sijil approval" in client.get(f"/approval/{a['approval_id']}").text
        for _ in range(100):
            if idp.posted:
                break
            time.sleep(0.01)
        assert f"https://sijil.moi.internal/approval/{a['approval_id']}" in idp.posted[0]["text"]
        assert decide(client, a["approval_id"]).json()["outcome"] == "granted"
        st = status(client, sess, a["approval_id"])
        assert st["status"] == "granted" and st["decision_seq"] == a["seq"] + 1
        assert seal_call(client, sess, parent, call_id, st["decision_seq"]).status_code == 200
        r = seal_call(client, sess, parent, call_id, st["decision_seq"])
        assert r.status_code == 409 and "already used" in r.text                      # V3
        assert end(client, sess, task).json()["confirmed"] == 1
    x, dx = (json.loads(r["ext"]) for r in rows(s.db_path, "type = 'approval'"))
    assert (x["phase"], x["approver_set"], x["min_assurance"], x["timeout_ms"], x["sod"], x["on_timeout"]) == \
        ("request", {"role": CLOSER}, "high", 900000, True, "deny")
    assert (dx["outcome"], dx["approver"], dx["approver_claims"]["roles_matched"],
            dx["approver_claims"]["assurance"]) == ("granted", human(SUPERVISOR), [CLOSER], "high")
    decision = rows(s.db_path, "type = 'approval'")[1]
    assert decision["output_hash"] == record.output_hash("Salary certificate verified.")
    assert decision["principal"] == human(OFFICER) and SUPERVISOR not in decision["ext"]
    code, line = verify(s.db_path, s.pubkey_path)
    assert code == 0 and " approvals=granted:1,refused:0,timeout:0 " in line, line


def test_answers_that_may_not_decide_are_refused_and_not_sealed(tmp_path):
    client, s, _ = gov_node(tmp_path)
    with client:
        sess, task = open_task(client)
        parent, _ = think(client, sess, task)
        aid = ask(client, sess, parent).json()["approval_id"]
        before = len(rows(s.db_path))
        for token, status_, code in ((supervisor(roles=()), 403, "role"), (supervisor(acrs=()), 403, "assurance"),
                                     (supervisor(oid=OFFICER), 403, "separation_of_duties"),
                                     (officer(), 401, "audience"), ("not-a-token", 401, "malformed")):
            r = decide(client, aid, token=token)
            assert (r.status_code, r.json()["detail"]) == (status_, {"approval_error": code}), token
        assert decide(client, aid, decision="maybe").status_code == 400
        assert len(rows(s.db_path)) == before
        assert decide(client, aid, decision="refuse").json()["outcome"] == "refused"
        assert decide(client, aid).status_code == 409
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_the_ledger_seals_a_timeout_at_the_deadline(tmp_path):
    client, s, _ = gov_node(tmp_path, pack=PACK.replace("timeout_seconds: 900", "timeout_seconds: 1"))
    with client:
        sess, task = open_task(client)
        parent, call_id = think(client, sess, task)
        a = ask(client, sess, parent).json()
        assert end(client, sess, task).status_code == 409                              # V4: still pending
        st = status(client, sess, a["approval_id"], wait=5)
        assert st["status"] == "timeout"
        assert decide(client, a["approval_id"]).status_code == 409
        assert seal_call(client, sess, parent, call_id, st["decision_seq"], granted=False).status_code == 200
        assert end(client, sess, task).json()["denied"] == 1
    t = rows(s.db_path, "type = 'approval'")[1]
    assert (t["rule_hits"], t["decision"], t["mode"]) == ('["approval-timeout"]', "block", "enforce")
    assert t["ts"] >= a["deadline"]
    code, line = verify(s.db_path, s.pubkey_path)
    assert code == 0 and " approvals=granted:0,refused:0,timeout:1 " in line


def test_a_ledger_restarted_after_the_deadline_seals_the_timeout_at_startup(tmp_path):
    pack = PACK.replace("timeout_seconds: 900", "timeout_seconds: 1")
    client, s, _ = gov_node(tmp_path, pack=pack)
    with client:
        sess, task = open_task(client)
        parent, _ = think(client, sess, task)
        a = ask(client, sess, parent).json()
    time.sleep(1.2)                                       # the ledger is down across the deadline
    client, s, _ = gov_node(tmp_path, pack=pack)
    with client:
        sess = session(client)
        assert status(client, sess, a["approval_id"], wait=5)["status"] == "timeout"
    t = rows(s.db_path, "type = 'approval'")[1]
    assert t["ts"] > a["deadline"] and json.loads(t["ext"])["outcome"] == "timeout"
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_a_request_must_name_confirm_rules_with_a_route_and_a_parent_that_asked(tmp_path):
    client, s, _ = gov_node(tmp_path)
    with client:
        sess, task = open_task(client)
        parent, _ = think(client, sess, task)
        before = len(rows(s.db_path))
        assert ask(client, sess, parent, rule_hits=["no-such-rule"]).status_code == 400
        assert ask(client, sess, parent, route_id="budget-overrun").status_code == 400
        assert ask(client, sess, parent, input_hash="e" * 64).status_code == 400       # not what the model asked
        assert ask(client, sess, task).status_code == 400                               # parent is no inference
        assert len(rows(s.db_path)) == before


def test_a_tool_call_must_follow_the_decision_it_cites(tmp_path):
    client, s, _ = gov_node(tmp_path)
    with client:
        sess, task = open_task(client)
        parent, call_id = think(client, sess, task)
        a = ask(client, sess, parent).json()
        decide(client, a["approval_id"])
        assert seal_call(client, sess, parent, call_id, a["seq"]).status_code == 400            # the request
        assert seal_call(client, sess, parent, call_id, a["seq"] + 1, granted=False).status_code == 400
        assert client.post("/api/admin/halt", json={"halted": True}, headers=ADMIN).status_code == 200
        r = seal_call(client, sess, parent, call_id, a["seq"] + 1)
        assert r.status_code == 200 and r.json()["decision"] == "block"
    x = json.loads(rows(s.db_path, "type = 'tool_call'")[0]["ext"])
    assert x["confirmation"] == "denied" and "approval_seq" not in x                   # a halted call uses no grant
    assert verify(s.db_path, s.pubkey_path)[0] == 0
