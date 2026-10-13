"""Verifier checks U-U3 (spec §17.7): the human principal of the government profile. Numbers in brackets are
the §17.8 test list; the chain is the golden vectors 70-79 (tests/v2chain.py gov())."""

import base64
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
                         "principal_tokens=verified:0,unverified:0,unverifiable:0")


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
