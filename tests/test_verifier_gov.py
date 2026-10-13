"""Verifier checks U-X1 (spec §17.7): the human principal, named approval, autonomy budgets, HTTP and after-the-fact
tool calls of the government profile. Test numbers are the §17.8 list; the chain is the golden vectors 70-79
(tests/v2chain.py gov())."""

import hashlib
import json
from pathlib import Path

import v2chain
import vectors_v2
from conftest import verify, verify_json

TOKENS = Path(__file__).parent / "tokens"


def run(c, tmp_path, *flags):
    return verify(*c.write(tmp_path, validate=False), *flags)


def test_40_vectors_70_to_79_verify_with_and_without_the_kept_token(tmp_path):
    code, line = run(v2chain.gov(), tmp_path)
    assert code == 0, line
    assert " principals=human:1,workload:0,local:0,none:0 principal_tokens=verified:0,unverified:1,unverifiable:0" in line
    code, line = run(v2chain.gov(), tmp_path, "--token-dir", str(TOKENS), "--jwks-dir", str(TOKENS))
    assert code == 0 and " principal_tokens=verified:1,unverified:0,unverifiable:0" in line, line
    code, line = run(v2chain.gov(), tmp_path, "--token-dir", str(TOKENS))           # JWKS beside the tokens
    assert code == 0 and "verified:1" in line


def test_41_a_principal_that_is_not_the_tokens_subject(tmp_path):
    c = v2chain.gov()
    forged = "human:entra-moi:" + "7" * 64
    for seq in range(70, 80):
        c[seq]["principal"] = forged
    assert run(c, tmp_path)[0] == 0                       # without the token nothing contradicts it
    assert run(c, tmp_path, "--token-dir", str(TOKENS)) == (1, "FAIL seq=70 principal token mismatch")


def test_42_an_inference_sealed_after_the_token_expired(tmp_path):
    c = v2chain.gov()
    c[71]["ts"] = "2026-10-01T10:55:00.000Z"               # == exp: not before it
    assert run(c, tmp_path) == (1, "FAIL seq=71 principal token not valid at ts")


def test_43_assurance_floor(tmp_path):
    assert run(v2chain.gov(), tmp_path, "--min-principal-assurance", "substantial")[0] == 0
    assert run(v2chain.gov(), tmp_path, "--min-principal-assurance", "high") == \
        (1, "FAIL seq=70 principal assurance below high")
    code, res = verify_json(*v2chain.gov().write(tmp_path), "--min-principal-assurance", "high")
    assert res["code"] == "principal_assurance_low"


def test_55_a_v2_3_chain_passes_unchanged_with_zero_counts(tmp_path):
    code, line = run(v2chain.demo(), tmp_path)
    assert code == 0
    assert line.endswith(" principals=human:0,workload:0,local:1,none:0 "
                         "principal_tokens=verified:0,unverified:0,unverifiable:0 "
                         "approvals=granted:0,refused:0,timeout:0 budgets=hits:0 after_the_fact=0")


def claims_of(c, seq) -> dict:
    return json.loads(c[seq]["ext"])["principal_claims"]


def test_claims_shape_issuer_and_principal_auth(tmp_path):
    c = v2chain.gov()
    c.ext(70, principal_claims={k: v for k, v in claims_of(c, 70).items() if k != "jwks_hash"})
    assert run(c, tmp_path) == (1, "FAIL seq=70 principal claims malformed")
    c = v2chain.gov()
    c.ext(70, principal_claims={**claims_of(c, 70), "assurance": "medium"})
    assert run(c, tmp_path) == (1, "FAIL seq=70 principal claims malformed")
    c = v2chain.gov()
    c.ext(70, principal_auth="none")
    assert run(c, tmp_path) == (1, "FAIL seq=70 principal claims malformed")
    c = v2chain.gov()
    c.ext(70, principal_claims=None)
    assert run(c, tmp_path) == (1, "FAIL seq=70 principal claims malformed")


def test_a_refreshed_token_inside_the_task_must_be_the_tasks_issuer(tmp_path):
    c = v2chain.gov()
    c.ext(71, principal_claims={**claims_of(c, 70), "issuer_id": "uaepass-moi"})
    assert run(c, tmp_path) == (1, "FAIL seq=71 principal claims malformed")
    c = v2chain.gov()
    c.ext(71, principal_claims={**claims_of(c, 70), "token_hash": "ab" * 32,
                                "exp": "2026-10-01T11:55:00.000Z"})
    c[79]["ts"] = "2026-10-01T11:00:00.000Z"               # task_end is not an action under the token (Ruling)
    assert run(c, tmp_path)[0] == 0


def test_out_of_task_human_inference_needs_claims_unless_it_is_a_refusal(tmp_path):
    c = v2chain.gov()
    c.add("inference", agent_id=v2chain.AGENT, principal=vectors_v2.GOV_PRINCIPAL, rulepack_hash=vectors_v2.GOV_RP,
          model_id="gpt-4.1", model_digest="api:azure-openai:gpt-4.1", ts="2026-10-01T10:04:00.000Z",
          ext={"api": "openai_chat", "attestation": "api"})
    assert run(c, tmp_path) == (1, "FAIL seq=80 principal claims malformed")
    c.ext(80, principal_error="assurance")
    c[80].update(mode="enforce", decision="block", rule_hits='["principal-assurance-low"]')
    assert run(c, tmp_path)[0] == 0


def test_a_kept_token_or_jwks_that_differs_from_the_sealed_hash(tmp_path):
    claims = json.loads(vectors_v2.out[70]["ext"])["principal_claims"]
    kept = tmp_path / "kept"
    kept.mkdir()
    for name in (claims["token_hash"] + ".jwt", claims["jwks_hash"] + ".json"):
        (kept / name).write_bytes((TOKENS / name).read_bytes())
    (kept / (claims["token_hash"] + ".jwt")).write_bytes(vectors_v2.OFFICER_JWT[:-2].encode() + b"AA")
    assert run(v2chain.gov(), tmp_path, "--token-dir", str(kept)) == (1, "FAIL seq=70 principal token mismatch")
    (kept / (claims["token_hash"] + ".jwt")).write_bytes(vectors_v2.OFFICER_JWT.encode())
    (kept / (claims["jwks_hash"] + ".json")).write_bytes(b'{"keys": []}')
    assert run(v2chain.gov(), tmp_path, "--token-dir", str(kept)) == (1, "FAIL seq=70 principal token mismatch")
    (kept / (claims["token_hash"] + ".jwt")).unlink()
    code, line = run(v2chain.gov(), tmp_path, "--token-dir", str(kept))
    assert code == 0 and "principal_tokens=verified:0,unverified:1," in line



# ---- V-V4, W-W2, X-X1: named approval, budgets, the HTTP adapter and Foundry's after-the-fact calls

GOV_PACK = """rulepack_id: moi-case-pack
version: 0.1.0
rules: []
budgets:
  - id: case-agent
    match: {harness: [http-agent]}
    limits: {tool_calls: 40, tool_calls_by: {"http:case-api:addCaseNote": LIMIT}, egress_hosts: 4,
             model_spend_micro: 3000000}
    currency: AED
    on_exceed: block
pricing:
  - {id: aoai-gpt41-uae, model: "api:azure-openai:gpt-4.1*", input_per_mtok_micro: 7340000,
     output_per_mtok_micro: 29360000, missing_usage_cost_micro: 50000}
"""


def packed(tmp_path, limit=1):
    """The vector chain under a real rule pack file, and that file."""
    p = tmp_path / "moi-case-pack.yaml"
    p.write_text(GOV_PACK.replace("LIMIT", str(limit)))
    return v2chain.gov(hashlib.sha256(p.read_bytes()).hexdigest()), str(p)


def test_40b_the_pass_line_counts_approvals_and_budget_hits(tmp_path):
    code, line = run(v2chain.gov(), tmp_path)
    assert code == 0 and line.endswith(" approvals=granted:1,refused:0,timeout:0 budgets=hits:1 after_the_fact=0")


def test_44_a_grant_at_the_deadline(tmp_path):
    c = v2chain.gov()
    c[76]["ts"] = "2026-10-01T10:15:02.050Z"                # request ts + 900000 ms
    assert run(c, tmp_path) == (1, "FAIL seq=76 approval after deadline")
    c[76]["ts"] = "2026-10-01T10:15:02.049Z"
    assert run(c, tmp_path)[0] == 0


def test_45_a_timeout_before_the_deadline(tmp_path):
    c = v2chain.gov()
    c.ext(76, outcome="timeout", approver=None, approver_claims=None)
    c[76].update(mode="enforce", decision="block", rule_hits='["approval-timeout"]', output_hash="")
    assert run(c, tmp_path) == (1, "FAIL seq=76 approval decision invalid")


def test_46_the_approver_is_the_task_principal(tmp_path):
    c = v2chain.gov()
    c.ext(76, approver=vectors_v2.GOV_PRINCIPAL)
    assert run(c, tmp_path) == (1, "FAIL seq=76 approver is task principal")


def test_47_a_grant_is_single_use(tmp_path):
    c = v2chain.gov()
    c.bodies[77] = {**c[77], "ts": "2026-10-01T10:03:12.690Z"}  # seq 78 becomes a second closeCase citing 76
    assert run(c, tmp_path) == (1, "FAIL seq=78 approval reused")


def test_48_a_request_left_undecided_at_task_end(tmp_path):
    c = v2chain.gov()
    x = json.loads(c[75]["ext"]) | {"approval_id": "ap_" + "1" * 26}
    c.bodies[77] = {**c[75], "ts": "2026-10-01T10:03:12.690Z", "ext": record_json(x)}
    assert run(c, tmp_path) == (1, "FAIL seq=79 approval undecided at task_end")


def record_json(x) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def test_49_the_approved_call_is_not_the_call_that_ran(tmp_path):
    c = v2chain.gov()
    other = {"caseId": "MOI-2026-004211", "resolution": "rejected"}
    c[77]["input_hash"] = v2chain.h(other)
    uses = json.loads(c[71]["ext"])["tool_uses"]
    c.ext(71, tool_uses=[{**u, "args_hash": v2chain.h(other)} if u["name"] == "closeCase" else u for u in uses])
    assert run(c, tmp_path) == (1, "FAIL seq=77 tool_call approval mismatch")


def test_49b_confirmation_and_decision_follow_the_outcome(tmp_path):
    c = v2chain.gov()
    c.ext(77, confirmation="denied")
    assert run(c, tmp_path) == (1, "FAIL seq=77 tool_call approval mismatch")
    c = v2chain.gov()
    c[77].update(decision="block", mode="enforce")
    assert run(c, tmp_path) == (1, "FAIL seq=77 tool_call approval mismatch")


def test_refused_and_timed_out_approvals_pass_with_the_call_denied(tmp_path):
    for outcome, ts in (("refused", "2026-10-01T10:03:12.400Z"), ("timeout", "2026-10-01T10:15:02.050Z")):
        c = v2chain.gov()
        decision = {"phase": "decision", "approval_id": vectors_v2.APPROVAL_ID, "outcome": outcome}
        if outcome == "refused":
            decision |= {k: json.loads(c[76]["ext"])[k] for k in ("approver", "approver_claims")}
        c[76].update(ts=ts, mode="enforce", decision="block", ext=record_json(decision),
                     rule_hits='["approval-timeout"]' if outcome == "timeout" else "[]")
        c[77].update(decision="block", mode="enforce", ts="2026-10-01T10:15:03.000Z")
        c.ext(77, confirmation="denied")
        c[78]["ts"] = c[79]["ts"] = "2026-10-01T10:15:04.000Z"
        c.ext(78, budget={"case-agent": {"tool_calls": {"limit": 40, "used": 1},
                                         "tool_calls_by:http:case-api:addCaseNote": {"limit": 1, "used": 1}}})
        c.ext(79, blocked=3, confirmed=0, denied=1, flagged=1)
        code, line = run(c, tmp_path)
        assert code == 0, (outcome, line)
        assert f"approvals=granted:0,{'refused:1,timeout:0' if outcome == 'refused' else 'refused:0,timeout:1'}" in line


def test_50_a_budget_counter_that_is_not_the_count(tmp_path):
    c = v2chain.gov()
    budget = json.loads(c[78]["ext"])["budget"]
    budget["case-agent"]["tool_calls"]["used"] = 4
    c.ext(78, budget=budget)
    assert run(c, tmp_path) == (1, "FAIL seq=78 budget counter mismatch")


def test_51_an_excess_that_was_let_through(tmp_path):
    c = v2chain.gov()
    c[78].update(rule_hits="[]", decision="allow", mode="record")
    assert run(c, tmp_path) == (1, "FAIL seq=78 budget exceeded without enforcement")


def test_51b_a_budget_hit_without_an_excess(tmp_path):
    c = v2chain.gov()
    c[72].update(rule_hits='["budget:case-agent:tool_calls"]', decision="block", mode="enforce")
    assert run(c, tmp_path) == (1, "FAIL seq=72 budget hit without excess")


def test_52_a_sealed_limit_that_is_not_the_packs(tmp_path):
    c, pack = packed(tmp_path)
    code, line = run(c, tmp_path, "--rulepack", pack)
    assert code == 0, line
    c, pack = packed(tmp_path, limit=6)
    assert run(c, tmp_path, "--rulepack", pack) == (1, "FAIL seq=72 budget limit not in rule pack")
    assert run(v2chain.gov(), tmp_path, "--rulepack", pack)[0] == 0       # another pack's records: not compared


def test_53_a_cost_that_does_not_recompute(tmp_path):
    c, pack = packed(tmp_path)
    c.ext(71, usage={"input_tokens": 1840, "output_tokens": 97})
    assert run(c, tmp_path)[0] == 0
    assert run(c, tmp_path, "--rulepack", pack) == (1, "FAIL seq=71 cost mismatch")
    c, pack = packed(tmp_path)
    c.ext(71, price_rule="local")
    assert run(c, tmp_path, "--rulepack", pack) == (1, "FAIL seq=71 cost mismatch")


def test_54_an_after_the_fact_call_that_claims_a_block(tmp_path):
    c = v2chain.gov()
    c.ext(72, after_the_fact=True)
    c[72].update(mode="record", decision="flag")
    c.ext(79, flagged=3)
    code, line = run(c, tmp_path)
    assert code == 0 and line.endswith(" after_the_fact=1")
    c[72].update(mode="enforce", decision="block")
    assert run(c, tmp_path) == (1, "FAIL seq=72 after-the-fact tool_call claims enforcement")


def test_x_http_tool_calls_name_their_server_and_operation(tmp_path):
    c = v2chain.gov()
    c.ext(72, qualified="addCaseNote")
    assert run(c, tmp_path) == (1, "FAIL seq=72 http tool_call malformed")
    c = v2chain.gov()
    c.ext(72, summary={"method": "POST", "host": vectors_v2.CASE_HOST, "arg_keys": ["caseId", "note"]})
    assert run(c, tmp_path) == (1, "FAIL seq=72 http tool_call malformed")
    c = v2chain.gov()                                      # an operation without operationId (§17.3.3)
    c.ext(72, qualified="http:case-api:POST /cases/{caseId}/notes", tool="POST /cases/{caseId}/notes")
    budget = json.loads(c[78]["ext"])["budget"]
    budget["case-agent"]["tool_calls_by:http:case-api:addCaseNote"]["used"] = 0
    c.ext(78, budget=budget)
    c[78].update(rule_hits="[]", decision="allow", mode="record")
    c.ext(79, blocked=0, flagged=2)
    code, line = run(c, tmp_path)
    assert code == 0, line


def test_v_an_approval_request_needs_its_keys_and_a_parent_inference(tmp_path):
    c = v2chain.gov()
    c.ext(75, route_id=None)
    assert run(c, tmp_path) == (1, "FAIL seq=75 approval request malformed")
    c = v2chain.gov()
    c[75]["parent_seq"] = "74"
    assert run(c, tmp_path) == (1, "FAIL seq=75 approval request malformed")
