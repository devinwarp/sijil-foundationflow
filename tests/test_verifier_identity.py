"""Verifier identity checks H-N (spec §4.2, §5.8-5.9): tasks, identity columns, the agent registry
and its offline proofs, task_end counts. Numbers in brackets are the §4.4 test list."""

import json

import pytest

import v2chain
from conftest import verify, verify_json
from v2chain import AGENT, AGENT_KEY, NEW_KEY, PRINCIPAL, SENTRY_ARGS

DEMO_PASS = ("PASS records=15 first=2026-10-01T08:00:00.000Z last=2026-10-01T08:00:14.000Z "
             "attestation=weights:0,api:2,api+tee:0,none:0 agent_auth=key:1,mtls:0,oidc:0,relay:0,none:0 "
             "principals=human:0,workload:0,local:1,none:0 principal_tokens=verified:0,unverified:0,unverifiable:0")
OTHER = "spiffe://acme.example/agent/intruder"


def run(c, tmp_path, *flags):
    return verify(*c.write(tmp_path, validate=False), *flags)


def short_task(c, agent_auth="key", agent=AGENT, principal=PRINCIPAL, delegated_from=""):
    """task_start, one inference asking for get_issue, the tool_call, task_end. Returns the task seq."""
    t = v2chain.task_start(c, agent=agent, principal=principal, agent_auth=agent_auth, delegated_from=delegated_from)
    i = v2chain.inference(c, t, [("toolu_x" + t, "mcp__sentry__get_issue", SENTRY_ARGS)], agent=agent,
                          principal=principal)
    c.add("tool_call", agent_id=agent, principal=principal, task_seq=t, parent_seq=i,
          input_hash=v2chain.h(SENTRY_ARGS),
          ext={"harness": "claude-code", "session_id": v2chain.SESSION, "tool": "get_issue", "server": "sentry",
               "qualified": "mcp__sentry__get_issue", "tool_use_id": "toolu_x" + t, "correlation": "tool_use_id",
               "observed_by": "mcp_guard"})
    c.add("task_end", agent_id=agent, principal=principal, task_seq=t,
          ext={"outcome": "completed", "inference": 1, "tool_calls": 1, "blocked": 0, "confirmed": 0, "denied": 0,
               "flagged": 0, "egress": 0, "last_seq": int(t) + 2})
    return t


def test_demo_chain_passes_with_agent_auth_counts(tmp_path):
    assert verify(*v2chain.demo().write(tmp_path)) == (0, DEMO_PASS)


def test_json_lists_the_agent_registry(tmp_path):
    code, res = verify_json(*v2chain.demo().write(tmp_path))
    assert code == 0 and res["agent_auth"]["key"] == 1
    assert res["agents"] == {AGENT: {"registered_seq": 2, "current_pubkey": v2chain.pub(NEW_KEY), "revoked": False}}


def test_9_agent_id_differs_from_task(tmp_path):
    c = v2chain.demo()
    c[7]["agent_id"] = OTHER
    assert run(c, tmp_path) == (1, "FAIL seq=7 agent_id differs from task")


def test_9b_principal_differs_from_task(tmp_path):
    c = v2chain.demo()
    c[7]["principal"] = "email:" + "1" * 64
    assert run(c, tmp_path) == (1, "FAIL seq=7 principal differs from task")


def test_10_agent_not_registered(tmp_path):
    c = v2chain.demo()
    c[4]["agent_id"] = OTHER
    assert run(c, tmp_path) == (1, "FAIL seq=4 agent not registered")


def test_11_self_proof_invalid(tmp_path):
    c = v2chain.demo()
    sp = json.loads(c[2]["ext"])["self_proof"]
    c.ext(2, self_proof=("0" if sp[0] != "0" else "1") + sp[1:])
    assert run(c, tmp_path) == (1, "FAIL seq=2 agent self-proof invalid")


def test_11b_input_hash_must_be_the_proof_message_hash(tmp_path):
    c = v2chain.demo()
    c[2]["input_hash"] = "e" * 64
    assert run(c, tmp_path) == (1, "FAIL seq=2 agent self-proof invalid")


def test_11c_v2_1_register_without_continuity_fields(tmp_path):
    """A pre-v2.2 registration signs only {agent_id, agent_pubkey, nonce, registered_by}."""
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    nonce = "5f1e" + "7" * 60
    msg = {"agent_id": AGENT, "agent_pubkey": v2chain.pub(AGENT_KEY), "nonce": nonce, "registered_by": PRINCIPAL}
    c.add("agent_register", agent_id=AGENT, principal=PRINCIPAL, input_hash=v2chain.h(msg),
          ext={**{k: v for k, v in msg.items() if k != "agent_id"}, "auth": "key", "principal_auth": "none",
               "id_form": "spiffe", "self_proof": v2chain.proof(AGENT_KEY, msg)})
    short_task(c)
    assert run(c, tmp_path)[0] == 0


def test_12_agent_revoked_before_task_start(tmp_path):
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    v2chain.register(c)
    v2chain.revoke(c)
    short_task(c)
    assert run(c, tmp_path) == (1, "FAIL seq=4 agent revoked")


def test_13_duplicate_task_end(tmp_path):
    c = v2chain.demo()
    c.bodies.append(dict(c[14]))
    assert run(c, tmp_path) == (1, "FAIL seq=16 duplicate task_end")


@pytest.mark.parametrize("key,value", [("blocked", 0), ("flagged", 1), ("egress", 2), ("last_seq", 12),
                                       ("inference", None)])
def test_14_task_end_counts_mismatch(tmp_path, key, value):
    c = v2chain.demo()
    c.ext(14, **{key: value})
    assert run(c, tmp_path) == (1, "FAIL seq=14 task_end counts mismatch")


def test_15_tool_call_outside_task(tmp_path):
    c = v2chain.demo()
    c[6]["task_seq"] = ""
    assert run(c, tmp_path) == (1, "FAIL seq=6 record outside task")


def test_16_unauthenticated_agent(tmp_path):
    c = v2chain.demo()
    c.ext(4, agent_auth="none")
    assert run(c, tmp_path) == (1, "FAIL seq=4 unauthenticated agent")
    code, line = run(c, tmp_path, "--allow-unauthenticated-agents")
    assert code == 0
    assert " agent_auth=key:0,mtls:0,oidc:0,relay:0,none:1 " in line and line.endswith(" unauthenticated=1")


@pytest.mark.parametrize("agent_auth", ["magic", ""])
def test_unknown_agent_auth_is_unauthenticated(tmp_path, agent_auth):
    c = v2chain.demo()
    c.ext(4, agent_auth=agent_auth)
    assert run(c, tmp_path, "--allow-unauthenticated-agents") == (1, "FAIL seq=4 unauthenticated agent")


def test_task_end_without_task_seq(tmp_path):
    c = v2chain.demo()
    c[14]["task_seq"] = ""
    assert run(c, tmp_path) == (1, "FAIL seq=14 task_end without task_start")


def test_task_seq_not_allowed(tmp_path):
    c = v2chain.demo()
    c[15]["task_seq"] = "4"
    assert run(c, tmp_path) == (1, "FAIL seq=15 task_seq not allowed on agent_rotate")
    c = v2chain.demo()
    v2chain.rulepack_change(c, before=v2chain.RP, after="5" * 64)
    c[16]["task_seq"] = "4"
    assert run(c, tmp_path) == (1, "FAIL seq=16 task_seq not allowed on rulepack_change")


@pytest.mark.parametrize("value,line", [("5", "FAIL seq=6 task type inference expected task_start"),
                                        ("9", "FAIL seq=6 task not earlier"),
                                        ("04", "FAIL seq=6 task missing")])
def test_task_reference(tmp_path, value, line):
    c = v2chain.demo()
    c[6]["task_seq"] = value
    assert run(c, tmp_path) == (1, line)


def test_parent_in_different_task(tmp_path):
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    v2chain.register(c)
    t1 = v2chain.task_start(c)
    i1 = v2chain.inference(c, t1, [("toolu_1", "mcp__sentry__get_issue", SENTRY_ARGS)])
    t2 = v2chain.task_start(c, delegated_from=t1)
    v2chain.tool_call(c, t2, i1, "toolu_1", "mcp__sentry__get_issue", "get_issue", "sentry", SENTRY_ARGS)
    assert run(c, tmp_path) == (1, "FAIL seq=6 parent in different task")


def test_drift_may_cite_a_baseline_outside_the_task(tmp_path):
    assert verify(*v2chain.demo().write(tmp_path))[0] == 0      # seq 13 cites baseline 3, outside task 4


@pytest.mark.parametrize("value", ["99", "2", "x"])
def test_delegated_from_missing(tmp_path, value):
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    v2chain.register(c)
    short_task(c, delegated_from=value)
    assert run(c, tmp_path) == (1, "FAIL seq=3 delegated_from missing")


def test_delegation_to_an_earlier_task_passes(tmp_path):
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    v2chain.register(c)
    t1 = short_task(c)
    short_task(c, delegated_from=t1)
    assert run(c, tmp_path)[0] == 0


def test_agent_id_and_principal_malformed(tmp_path):
    c = v2chain.demo()
    c[3]["agent_id"] = "Agent X"
    assert run(c, tmp_path) == (1, "FAIL seq=3 agent_id malformed")
    c = v2chain.demo()
    c[3]["principal"] = "email:dev@acme.example"
    assert run(c, tmp_path) == (1, "FAIL seq=3 principal malformed")


def test_human_principal_passes_i2_and_needs_claims(tmp_path):
    """I2 accepts the human: syntax; U (spec §17.7) then asks for the token claims it was validated from."""
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    v2chain.register(c)
    short_task(c, principal="human:entra-moi:" + "6" * 64)
    assert run(c, tmp_path) == (1, "FAIL seq=3 principal claims malformed")


def test_declared_runtime_identity_is_a_valid_agent_id(tmp_path):
    """I2 from v2.2: an identifier declared by a registration passes even when it is not spiffe://.../agent/..."""
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    v2chain.register(c, agent="spiffe://acme.example/workload/ci-fixer")
    short_task(c, agent="spiffe://acme.example/workload/ci-fixer")
    assert run(c, tmp_path)[0] == 0


def test_already_registered(tmp_path):
    c = v2chain.demo()
    v2chain.register(c)
    assert run(c, tmp_path) == (1, "FAIL seq=16 agent already registered")


def test_oidc_register_structure_and_consistency(tmp_path):
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    bot = v2chain.register_oidc(c)
    c.ext(bot, oidc_binding={"issuer": "https://token.actions.githubusercontent.com"})
    assert run(c, tmp_path) == (1, "FAIL seq=2 agent register malformed")
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    v2chain.register_oidc(c)
    short_task(c, agent="spiffe://acme.example/agent/ci-bot", principal=v2chain.CI_PRINCIPAL, agent_auth="key")
    assert run(c, tmp_path) == (1, "FAIL seq=3 agent_auth inconsistent with registration")
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    v2chain.register_oidc(c)
    short_task(c, agent="spiffe://acme.example/agent/ci-bot", principal=v2chain.CI_PRINCIPAL, agent_auth="oidc")
    code, line = run(c, tmp_path)
    assert code == 0 and " agent_auth=key:0,mtls:0,oidc:1,relay:0,none:0" in line


def test_mtls_task_on_a_key_registration(tmp_path):
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    v2chain.register(c)
    short_task(c, agent_auth="mtls")
    assert run(c, tmp_path)[0] == 0


def test_rotation_key_mismatch_and_proof(tmp_path):
    c = v2chain.demo()
    v2chain.rotate(c)                                          # second rotation still claims the old key
    assert run(c, tmp_path) == (1, "FAIL seq=16 rotation key mismatch")
    c = v2chain.demo()
    pn = json.loads(c[15]["ext"])["proof_new"]
    c.ext(15, proof_new=("0" if pn[0] != "0" else "1") + pn[1:])
    assert run(c, tmp_path) == (1, "FAIL seq=15 agent rotation proof invalid")


def test_rotation_then_revoke_needs_the_new_key(tmp_path):
    c = v2chain.demo()
    v2chain.revoke(c, key=AGENT_KEY)
    assert run(c, tmp_path) == (1, "FAIL seq=16 revoke key mismatch")
    c = v2chain.demo()
    v2chain.revoke(c, key=NEW_KEY)
    v2chain.revoke(c, key=NEW_KEY)
    assert run(c, tmp_path) == (1, "FAIL seq=17 agent already revoked")


def test_rotate_unregistered_agent(tmp_path):
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    v2chain.rotate(c)
    assert run(c, tmp_path) == (1, "FAIL seq=2 agent not registered")


def test_empty_task_counts_zero_and_last_seq_is_the_task_start(tmp_path):
    c = v2chain.Chain()
    v2chain.rulepack_change(c)
    v2chain.register(c)
    t = v2chain.task_start(c)
    c.add("task_end", agent_id=AGENT, principal=PRINCIPAL, task_seq=t,
          ext={"outcome": "aborted", "inference": 0, "tool_calls": 0, "blocked": 0, "confirmed": 0, "denied": 0,
               "flagged": 0, "egress": 0, "last_seq": int(t)})
    assert run(c, tmp_path)[0] == 0
