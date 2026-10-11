"""Row 5c: sijill/oidc.py (JWS, JWKS fetch/pinned, snapshots) and OIDC workload sessions (spec §5.8.5, §17.2.6)."""

import asyncio
import json
import time
from pathlib import Path

import httpx
import pytest

from agentkit import AGENT, HDR, OPEN_POLICY, agent_node, start_task
from conftest import rows, verify
from jwtkit import AUDIENCE, ENTRA_ISS, Idp, b64u, claims, jws, rsa_jwk
from sijill import oidc, record

HERE = Path(__file__).parent
FIXTURE_JWKS = HERE / "tokens" / "7178fa37eccd7fa82260bd6faaca752e357381418c594ac5f736df5b725df546.json"
FIXTURE_JWT = HERE / "tokens" / "65c52bfdc0cbbd75527e406af12348304dab443d815edaa9516c518423649ab6.jwt"
FETCH = oidc.issuer_cfg({"issuer": ENTRA_ISS, "audience": AUDIENCE}, "test")


def check(token, idp, tmp, now=None, cfg=FETCH):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(idp)) as http:
            keys = oidc.build_jwks([cfg], str(tmp), http)
            return await oidc.validate(token, {cfg["issuer"]: cfg}, keys, now or time.time())
    return asyncio.run(go())


def test_rs256_token_verifies_and_the_snapshot_is_canonical(tmp_path):
    idp = Idp({"keys": [rsa_jwk()]})
    v = check(jws(claims(sub="mi-1")), idp, tmp_path)
    assert v.claims["sub"] == "mi-1" and v.header["alg"] == "RS256"
    snap = tmp_path / f"{v.jwks_hash}.json"
    assert snap.read_bytes() == record.canonical_json({"keys": [rsa_jwk()]})
    assert record.sha256_hex(snap.read_bytes()) == v.jwks_hash


def test_the_m2a_fixture_token_verifies_under_its_pinned_jwks(tmp_path):
    """Golden vector seq 70's officer token (EdDSA) and JWKS: the hash the vector sealed is the one we compute."""
    cfg = oidc.issuer_cfg({"issuer": ENTRA_ISS, "audience": AUDIENCE, "algs": ["EdDSA"],
                           "jwks": {"mode": "pinned", "path": str(FIXTURE_JWKS),
                                    "sha256": record.sha256_hex(FIXTURE_JWKS.read_bytes())}}, "test")
    token = FIXTURE_JWT.read_text()
    nbf = json.loads(oidc.b64d(token.split(".")[1]))["nbf"]
    v = check(token, Idp({}), tmp_path, now=nbf + 60, cfg=cfg)
    assert v.jwks_hash == FIXTURE_JWKS.stem and v.claims["oid"] == "5f6e7d8c-1a2b-4c3d-8e9f-0a1b2c3d4e5f"


@pytest.mark.parametrize("token, code", [
    ("not-a-jwt", "malformed"),
    (jws(claims(), alg="none"), "alg"),
    (jws(claims(), alg="HS256"), "alg"),
    (jws(claims(), typ="at+jwt"), "malformed"),
    (jws(claims(iss="https://sts.windows.net/x/")), "issuer"),
    (jws(claims(), kid="other"), "kid"),
    (jws(claims(), alg="EdDSA"), "alg"),                       # FETCH allows RS256 only
    (jws(claims(aud="api://someone-else")), "audience"),
    (jws(claims(life=-1)), "expired"),
    (jws({**claims(), "nbf": int(time.time()) + 120}), "not_yet_valid"),
])
def test_refusal_codes(tmp_path, token, code):
    with pytest.raises(oidc.OidcError) as e:
        check(token, Idp({"keys": [rsa_jwk()]}), tmp_path)
    assert e.value.code == code


def test_bad_signature_and_skew(tmp_path):
    idp = Idp({"keys": [rsa_jwk()]})
    head, body, sig = jws(claims()).split(".")
    with pytest.raises(oidc.OidcError, match="signature"):
        check(f"{head}.{b64u(json.dumps({**claims(), 'sub': 'x'}).encode())}.{sig}", idp, tmp_path)
    assert check(jws({**claims(), "nbf": int(time.time()) + 30}), idp, tmp_path)       # 60 s skew on nbf


def test_unknown_kid_forces_one_refresh_per_300_s(tmp_path):
    idp = Idp({"keys": [rsa_jwk()]})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(idp)) as http:
            keys = oidc.build_jwks([FETCH], str(tmp_path), http)
            issuers, t0 = {ENTRA_ISS: FETCH}, time.time()
            await oidc.validate(jws(claims()), issuers, keys, t0)
            for dt in (1, 2, 299):
                with pytest.raises(oidc.OidcError):
                    await oidc.validate(jws(claims(), kid="rotated"), issuers, keys, t0 + dt)
            fetches_before = len(idp.calls)
            with pytest.raises(oidc.OidcError):
                await oidc.validate(jws(claims(), kid="rotated"), issuers, keys, t0 + 301)
            return fetches_before, len(idp.calls)
    before, after = asyncio.run(go())
    assert before == 4 and after == 6          # startup fetch (2 requests), one forced refresh (2), one more at 301 s


def test_stale_jwks_fails_closed_at_max_stale_and_not_before(tmp_path):
    cfg = oidc.issuer_cfg({"issuer": ENTRA_ISS, "audience": AUDIENCE,
                           "jwks": {"mode": "fetch", "refresh_s": 60, "max_stale_s": 600}}, "test")
    idp = Idp({"keys": [rsa_jwk()]})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(idp)) as http:
            keys, t0 = oidc.build_jwks([cfg], str(tmp_path), http), time.time()
            token = jws(claims(life=7200))
            await oidc.validate(token, {ENTRA_ISS: cfg}, keys, t0)
            idp.down = True
            await oidc.validate(token, {ENTRA_ISS: cfg}, keys, t0 + 599)          # stale but not too stale
            with pytest.raises(oidc.OidcError) as e:
                await oidc.validate(token, {ENTRA_ISS: cfg}, keys, t0 + 600)
            return e.value
    err = asyncio.run(go())
    assert (err.code, err.status) == ("jwks_stale", 503)


def test_pinned_jwks_with_a_wrong_sha256_refuses_to_start(tmp_path):
    policy = OPEN_POLICY.replace("agents:\n", f"""agents:
  oidc_issuers:
    - issuer: {ENTRA_ISS}
      audience: {AUDIENCE}
      algs: [EdDSA]
      jwks: {{mode: pinned, path: "{FIXTURE_JWKS}", sha256: "{'0' * 64}"}}
""")
    client, _ = agent_node(tmp_path, policy_text=policy)
    with pytest.raises(ValueError, match="does not match jwks.sha256"):
        with client:
            pass


WORKLOAD_POLICY = OPEN_POLICY.replace("agents:\n", f"""agents:
  oidc_issuers:
    - issuer: {ENTRA_ISS}
      audience: {AUDIENCE}
""")
MI = "0d9e8f7a-1111-4222-8333-444455556666"        # the agent's managed identity object id (token sub)


def workload_node(tmp_path):
    return agent_node(tmp_path, policy_text=WORKLOAD_POLICY, idp=Idp({"keys": [rsa_jwk()]}))


def register_oidc(client, sub_pattern=MI, **headers):
    return client.post("/api/agent/register", headers={**HDR, **headers}, json={
        "agent_id": AGENT, "registered_by": "local:" + "a" * 64,
        "oidc_binding": {"issuer": ENTRA_ISS, "sub_pattern": sub_pattern}})


def test_workload_token_opens_an_oidc_session_and_the_chain_passes(tmp_path):
    client, s = workload_node(tmp_path)
    with client:
        assert register_oidc(client).status_code == 200
        r = client.post("/api/agent/session", json={"oidc_token": jws(claims(sub=MI, jti="j-1"))}, headers=HDR)
        assert r.status_code == 200
        sess = r.json()
        assert (sess["agent_auth"], sess["principal_auth"]) == ("oidc", "oidc")
        assert sess["principal"] == f"oidc:login.microsoftonline.com:{MI}"
        start_task(client, sess)
    reg, task = rows(s.db_path)
    assert json.loads(reg["ext"]) == {"auth": "oidc", "oidc_binding": {"issuer": ENTRA_ISS, "sub_pattern": MI},
                                      "registered_by": "local:" + "a" * 64, "principal_auth": "key",
                                      "id_form": "spiffe"}
    assert json.loads(task["ext"])["agent_auth"] == "oidc" and task["principal"] == sess["principal"]
    code, line = verify(s.db_path, s.pubkey_path)
    assert code == 0 and "agent_auth=key:0,mtls:0,oidc:1,relay:0,none:0" in line


def test_workload_token_replay_and_unbound_sub_are_refused(tmp_path):
    client, s = workload_node(tmp_path)
    with client:
        register_oidc(client, sub_pattern="0d9e8f7a-*")
        token = jws(claims(sub=MI, uti="u-1"))
        assert client.post("/api/agent/session", json={"oidc_token": token}, headers=HDR).status_code == 200
        again = client.post("/api/agent/session", json={"oidc_token": token}, headers=HDR)
        assert again.status_code == 401 and again.json()["detail"].endswith("replayed")
        other = client.post("/api/agent/session", json={"oidc_token": jws(claims(sub="ffff", jti="j-2"))},
                            headers=HDR)
        assert other.status_code == 401
        no_jti = client.post("/api/agent/session", json={"oidc_token": jws(claims(sub=MI))}, headers=HDR)
        assert no_jti.status_code == 401


def test_oidc_registration_needs_the_admin_token_and_a_known_issuer(tmp_path):
    client, s = workload_node(tmp_path)
    with client:
        assert register_oidc(client, Authorization="Bearer nope").status_code == 401
        r = client.post("/api/agent/register", headers=HDR, json={
            "agent_id": AGENT, "registered_by": "local:" + "a" * 64,
            "oidc_binding": {"issuer": "https://token.actions.githubusercontent.com", "sub_pattern": "repo:*"}})
        assert r.status_code == 400
    assert rows(s.db_path) == []


def _raw(obj) -> str:
    return b64u(json.dumps(obj).encode())


@pytest.mark.parametrize("token", [
    12345, ["a", "b", "c"], "a.b", "a.b.c.d", "!!!.!!!.!!!", "e30.e30.%%%",
    f"{_raw({'alg': 'RS256', 'kid': 'rsa-1'})}.{_raw({'iss': ['x']})}.AAAA",              # unhashable iss
    f"{_raw({'alg': 'RS256'})}.{_raw({'iss': ENTRA_ISS})}.AAAA",                           # no kid
    f"{_raw({'alg': 'RS256', 'kid': ['rsa-1']})}.{_raw({'iss': ENTRA_ISS})}.AAAA",         # kid not a string
    f"{_raw([1])}.{_raw({})}.AAAA",
    jws({**claims(), "exp": float("nan")}), jws({**claims(), "exp": 10 ** 400}), jws({**claims(), "exp": "9"}),
])
def test_malformed_tokens_are_401_never_500(tmp_path, token):
    client, _ = workload_node(tmp_path)
    with client:
        register_oidc(client)
        r = client.post("/api/agent/session", json={"oidc_token": token}, headers=HDR)
        assert r.status_code == 401, r.text


def test_oidc_binding_with_a_non_string_issuer_is_400(tmp_path):
    client, _ = workload_node(tmp_path)
    with client:
        r = client.post("/api/agent/register", headers=HDR, json={
            "agent_id": AGENT, "registered_by": "local:" + "a" * 64,
            "oidc_binding": {"issuer": [ENTRA_ISS], "sub_pattern": "x"}})
        assert r.status_code == 400
