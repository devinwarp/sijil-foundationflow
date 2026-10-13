"""Verifier checks U-X1 (spec §17.7): the human principal, named approval, autonomy budgets, HTTP and after-the-fact
tool calls of the government profile. Test numbers are the §17.8 list; the chain is the golden vectors 70-79
(tests/v2chain.py gov())."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

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

def refusal(c, **fields):
    """An out-of-task sealed principal refusal (spec §17.2.7), then the fields changed on top."""
    c.add("inference", agent_id=v2chain.AGENT, principal="", rulepack_hash=vectors_v2.GOV_RP, model_id="gpt-4.1",
          model_digest="api:azure-openai:gpt-4.1", ts="2026-10-01T10:04:00.000Z", mode="enforce", decision="block",
          rule_hits='["principal-expired"]', ext={"api": "openai_chat", "attestation": "api", "principal_error": "expired"})
    c[80].update(fields)
    return c


def test_a_real_refusal_is_exempt_and_nothing_else_with_principal_error_is(tmp_path):
    assert run(refusal(v2chain.gov()), tmp_path)[0] == 0
    c = v2chain.gov()                                      # in a task, after exp: not a refusal, checked normally
    c[71]["ts"] = "2026-10-01T12:00:00.000Z"
    c.ext(71, principal_error="expired")
    c[71].update(decision="block", mode="enforce")
    assert run(c, tmp_path) == (1, "FAIL seq=71 principal token not valid at ts")
    c = v2chain.gov()                                      # a task_start that lost its claims
    c.ext(70, principal_claims=None, principal_error="expired")
    assert run(c, tmp_path) == (1, "FAIL seq=70 principal claims malformed")
    c = refusal(v2chain.gov(), principal=vectors_v2.GOV_PRINCIPAL, decision="allow")     # decision allow: no exemption
    assert run(c, tmp_path) == (1, "FAIL seq=80 principal claims malformed")
    c = refusal(v2chain.gov(), principal=vectors_v2.GOV_PRINCIPAL)
    c.ext(80, principal_error="made_up")                   # code the ledger never seals
    assert run(c, tmp_path) == (1, "FAIL seq=80 principal claims malformed")


@pytest.mark.parametrize("nbf,ok", [("2026-10-01T10:01:00.000Z", True), ("2026-10-01T10:01:01.000Z", False)])
def test_nbf_may_lead_ts_by_the_ledgers_60_s_skew_and_no_more(tmp_path, nbf, ok):
    c = v2chain.gov()
    c.ext(70, principal_claims={**claims_of(c, 70), "nbf": nbf})
    got = run(c, tmp_path)
    assert got[0] == 0 if ok else got == (1, "FAIL seq=70 principal token not valid at ts")


@pytest.mark.parametrize("key,value", [
    ("exp", 9999), ("exp", "9999"), ("exp", "2026-10-01T10:55:00Z"), ("nbf", "2026-10-01T09:55:00.000+00:00"),
    ("nbf", None), ("assurance", 5), ("tenant", None), ("token_hash", 5), ("token_hash", "../../etc/passwd"), ("token_hash", "AB" * 32),
    ("jwks_hash", ["x"]), ("kid", 7), ("alg", None), ("iss", 1), ("delegated", "yes")])
def test_malformed_claim_values_are_a_fail_line_never_a_crash(tmp_path, key, value):
    c = v2chain.gov()
    c.ext(70, principal_claims={**claims_of(c, 70), key: value})
    for flags in ((), ("--token-dir", str(TOKENS))):
        assert run(c, tmp_path, *flags) == (1, "FAIL seq=70 principal claims malformed"), (key, value, flags)


@pytest.mark.parametrize("kept", [b"", b"notajws", b"a.b", b"a.b.c", b"\xff\xfe", b"e30.WzFd.AA"])
def test_a_kept_token_that_is_not_a_json_object_jws_is_a_mismatch(tmp_path, kept):
    claims = json.loads(vectors_v2.out[70]["ext"])["principal_claims"]
    d = tmp_path / "kept"
    d.mkdir()
    (d / (claims["jwks_hash"] + ".json")).write_bytes((TOKENS / (claims["jwks_hash"] + ".json")).read_bytes())
    (d / (claims["token_hash"] + ".jwt")).write_bytes(kept)
    assert run(v2chain.gov(), tmp_path, "--token-dir", str(d)) == (1, "FAIL seq=70 principal token mismatch")


@pytest.mark.parametrize("jwks", [b"[]", b"null", b'{"keys": 5}', b"not json"])
def test_a_kept_jwks_that_is_not_an_object_with_a_key_list_is_a_mismatch(tmp_path, jwks):
    claims = json.loads(vectors_v2.out[70]["ext"])["principal_claims"]
    d = tmp_path / "kept"
    d.mkdir()
    (d / (claims["token_hash"] + ".jwt")).write_bytes((TOKENS / (claims["token_hash"] + ".jwt")).read_bytes())
    (d / (claims["jwks_hash"] + ".json")).write_bytes(jwks)
    assert run(v2chain.gov(), tmp_path, "--token-dir", str(d)) == (1, "FAIL seq=70 principal token mismatch")


def test_jwk_crv_use_alg_and_rsa_size_are_checked(tmp_path):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    spec = importlib.util.spec_from_file_location("sv", Path(__file__).parent.parent / "verifier" / "sijill_verify.py")
    sv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sv)
    claims = json.loads(vectors_v2.out[70]["ext"])["principal_claims"]
    token = (TOKENS / (claims["token_hash"] + ".jwt")).read_text()
    jwks = json.loads((TOKENS / (claims["jwks_hash"] + ".json")).read_text())
    assert sv.jws_valid(token, claims["kid"], "EdDSA", jwks)
    for change in ({"crv": "X25519"}, {"use": "enc"}, {"alg": "RS256"}):
        bad = {"keys": [{**jwks["keys"][0], **change}]}
        assert not sv.jws_valid(token, claims["kid"], "EdDSA", bad), change

    def b64(i):
        return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    for bits, ok in ((1024, False), (2048, True)):
        key = rsa.generate_private_key(65537, bits)
        n = key.public_key().public_numbers()
        head = base64.urlsafe_b64encode(b'{"alg":"RS256","kid":"k"}').rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(b"{}").rstrip(b"=").decode()
        sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
        tok = f"{head}.{body}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
        assert sv.jws_valid(tok, "k", "RS256", {"keys": [{"kid": "k", "kty": "RSA", "n": b64(n.n), "e": b64(n.e)}]}) is ok


def test_deeply_nested_kept_token_or_jwks_is_a_mismatch_not_a_crash(tmp_path):
    claims = json.loads(vectors_v2.out[70]["ext"])["principal_claims"]
    deep = b"[" * 100000
    b64 = base64.urlsafe_b64encode(deep).rstrip(b"=")
    d = tmp_path / "kept"
    d.mkdir()
    (d / (claims["token_hash"] + ".jwt")).write_bytes(b64 + b"." + b64 + b".AA")
    (d / (claims["jwks_hash"] + ".json")).write_bytes((TOKENS / (claims["jwks_hash"] + ".json")).read_bytes())
    assert run(v2chain.gov(), tmp_path, "--token-dir", str(d)) == (1, "FAIL seq=70 principal token mismatch")
    (d / (claims["token_hash"] + ".jwt")).write_bytes((TOKENS / (claims["token_hash"] + ".jwt")).read_bytes())
    (d / (claims["jwks_hash"] + ".json")).write_bytes(deep)
    assert run(v2chain.gov(), tmp_path, "--token-dir", str(d)) == (1, "FAIL seq=70 principal token mismatch")


def test_a_deeply_nested_ext_is_ext_not_canonical(tmp_path):
    c = v2chain.gov()
    c[71]["ext"] = "[" * 100000
    assert run(c, tmp_path) == (1, "FAIL seq=71 ext not canonical")


def test_malformed_values_are_a_fail_line_not_an_exception(tmp_path):
    c = v2chain.gov()
    c.ext(76, approval_id=["x"])
    assert run(c, tmp_path) == (1, "FAIL seq=76 approval decision invalid")
    c = v2chain.gov()
    c[75]["ts"] = "yesterday"
    assert run(c, tmp_path) == (1, "FAIL seq=75 approval request malformed")
    c = v2chain.gov()
    c[72]["rule_hits"] = "[[" * 5000
    assert run(c, tmp_path) == (1, "FAIL seq=72 rule_hits malformed")
    c, pack = packed(tmp_path)
    c.ext(71, usage={"input_tokens": "9", "output_tokens": 97})
    assert run(c, tmp_path, "--rulepack", pack) == (1, "FAIL seq=71 cost mismatch")


def test_an_unreadable_rule_pack_is_a_fail_line(tmp_path):
    for body in (b"a: [", b"- 1\n", b"[" * 100000):
        p = tmp_path / "bad.yaml"
        p.write_bytes(body)
        code, line = run(v2chain.gov(), tmp_path, "--rulepack", str(p))
        assert (code, line.startswith("FAIL rule pack unreadable")) == (1, True), body[:8]
    p.write_text("budgets: [1, {id: [a]}, {id: b, limits: 3}]\npricing: [x]\n")
    assert run(v2chain.gov(), tmp_path, "--rulepack", str(p))[0] == 0
    assert run(v2chain.gov(), tmp_path, "--rulepack", str(tmp_path / "nope.yaml"))[1].startswith("FAIL rule pack unreadable")


def test_53b_a_priced_inference_must_carry_its_cost(tmp_path):
    c, pack = packed(tmp_path)
    x = json.loads(c[71]["ext"])
    del x["cost_micro"]
    c[71]["ext"] = record_json(x)
    assert run(c, tmp_path, "--rulepack", pack) == (1, "FAIL seq=71 cost mismatch")
    c[71]["ext"] = record_json(x | {"cost_micro": None})
    assert run(c, tmp_path, "--rulepack", pack) == (1, "FAIL seq=71 cost mismatch")
    assert run(c, tmp_path) == (1, "FAIL seq=71 cost mismatch")          # a non-int cost is wrong with or without a pack


def test_53c_cost_is_recomputed_outside_a_task_too(tmp_path):
    c, pack = packed(tmp_path)
    c[71].update(task_seq="", parent_seq="")
    c.ext(71, usage={"input_tokens": 1840, "output_tokens": 98})
    code, line = run(c, tmp_path, "--rulepack", pack)
    assert (code, line) == (1, "FAIL seq=71 cost mismatch")


def test_v_request_fields_are_checked(tmp_path):
    for change in ({"approval_id": "x"}, {"on_timeout": "allow"}, {"timeout_ms": 0}, {"timeout_ms": -5}):
        c = v2chain.gov()
        c.ext(75, **change)
        assert run(c, tmp_path) == (1, "FAIL seq=75 approval request malformed"), change
    c = v2chain.gov()
    c[75].update(mode="enforce", decision="block")
    assert run(c, tmp_path) == (1, "FAIL seq=75 approval request malformed")


def test_rule_hits_are_checked_on_every_record(tmp_path):
    c = v2chain.gov()
    c[10]["rule_hits"] = "{}"
    assert run(c, tmp_path) == (1, "FAIL seq=10 rule_hits malformed")


def test_a_record_in_an_ended_task_fails(tmp_path):
    c = v2chain.gov()
    c.bodies.insert(79, {**c[78], "ts": "2026-10-01T10:03:14.000Z"})        # a tool_result-free copy after task_end
    code, line = run(c, tmp_path)
    assert code == 1 and line in ("FAIL seq=80 record in an ended task",), line


def test_the_pass_line_and_json_report_how_many_records_the_pack_covered(tmp_path):
    c, pack = packed(tmp_path)
    code, line = run(c, tmp_path, "--rulepack", pack)
    assert code == 0 and line.endswith(" rulepack_matched=1"), line
    assert "rulepack_matched" not in run(c, tmp_path)[1]
    code, line = run(v2chain.gov(), tmp_path, "--rulepack", pack)
    assert code == 0 and line.endswith(" rulepack_matched=0"), line
    code, res = verify_json(*c.write(tmp_path, validate=False), "--rulepack", pack)
    assert res["rulepack_matched"] == 1


def test_an_empty_rulepack_path_is_a_usage_error(tmp_path):
    assert run(v2chain.gov(), tmp_path, "--rulepack", "") == (2, "")


def test_json_counters_on_a_fail_are_the_ones_seen_so_far(tmp_path):
    c = v2chain.gov()
    c.ext(79, blocked=99)
    code, res = verify_json(*c.write(tmp_path, validate=False))
    assert (code, res["ok"]) == (1, False) and res["budget_hits"] == 1 and res["approvals"]["granted"] == 1


def test_53d_priced_by_the_pack_not_by_the_record(tmp_path):
    c, pack = packed(tmp_path)
    x = json.loads(c[71]["ext"])
    for label, ext in (("both deleted", {k: v for k, v in x.items() if k not in ("price_rule", "cost_micro")}),
                       ("price_rule deleted", {k: v for k, v in x.items() if k != "price_rule"}),
                       ("price_rule null", x | {"price_rule": None}),
                       ("wrong price_rule", x | {"price_rule": "other"})):
        c[71]["ext"] = record_json(ext)
        assert run(c, tmp_path, "--rulepack", pack) == (1, "FAIL seq=71 cost mismatch"), label
    c[71]["ext"] = record_json(x)
    assert run(c, tmp_path, "--rulepack", pack)[0] == 0


def test_53e_a_cost_on_a_model_the_pack_does_not_price(tmp_path):
    c, pack = packed(tmp_path)
    c[71]["model_digest"] = "api:other:model-1"
    assert run(c, tmp_path, "--rulepack", pack) == (1, "FAIL seq=71 cost mismatch")
    x = json.loads(c[71]["ext"])
    c[71]["ext"] = record_json({k: v for k, v in x.items() if k not in ("price_rule", "cost_micro")})
    assert run(c, tmp_path, "--rulepack", pack)[0] == 0


ENTRA_PACK = GOV_PACK.replace("rules: []", """rules:
  - {id: case-closure-needs-approval, on: tool_call, match: {tool: ["http:case-api:closeCase"]}, action: confirm}
hitl:
  channel: entra""")


def test_a_confirm_hit_let_through_without_a_citation_fails_under_the_rulepack(tmp_path):
    p = tmp_path / "entra-pack.yaml"
    p.write_text(ENTRA_PACK.replace("LIMIT", "1"))
    rp = hashlib.sha256(p.read_bytes()).hexdigest()
    assert run(v2chain.gov(rp), tmp_path, "--rulepack", str(p))[0] == 0
    for drop in (("approval_seq", "confirmation"), ("approval_seq",)):    # the probe: no confirmation at all
        c = v2chain.gov(rp)
        x = json.loads(c[77]["ext"])
        c[77]["ext"] = record_json({k: v for k, v in x.items() if k not in drop})
        c.ext(79, confirmed=int("confirmation" not in drop))
        assert run(c, tmp_path)[0] == 0                                    # without the pack, rule actions are unseen
        assert run(c, tmp_path, "--rulepack", str(p)) == (1, "FAIL seq=77 tool_call approval mismatch")


def test_a_grant_is_bound_to_the_parent_its_request_named(tmp_path):
    def chain(parent):
        c = v2chain.gov()
        c.bodies[73] = {**c[71], "ts": c[74]["ts"]}          # seq 74 becomes a second inference of the task
        budget = json.loads(c[74]["ext"])["budget"]
        budget["case-agent"]["model_spend_micro"]["used"] = json.loads(c[71]["ext"])["cost_micro"]
        c.ext(74, budget=budget)
        c.ext(79, inference=2)
        c[77]["parent_seq"] = parent
        return c
    assert run(chain("71"), tmp_path)[0] == 0
    assert run(chain("74"), tmp_path) == (1, "FAIL seq=77 tool_call approval mismatch")


def test_a_grant_covers_only_the_hits_its_request_listed(tmp_path):
    def chain(asked):
        c = v2chain.gov()
        c.ext(77, budget={"case-agent": {"tool_calls": {"limit": 1, "used": 1}}})
        c[77]["rule_hits"] = '["case-closure-needs-approval","budget:case-agent:tool_calls"]'
        c[75]["rule_hits"] = json.dumps(asked, separators=(",", ":"))
        return c
    assert run(chain(["case-closure-needs-approval", "budget:case-agent:tool_calls"]), tmp_path)[0] == 0
    assert run(chain(["case-closure-needs-approval"]), tmp_path) == (1, "FAIL seq=77 tool_call approval mismatch")
