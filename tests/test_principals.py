"""Row 5d: human principal from Entra ID or a brokered OIDC IdP (spec §17.2), on chat completions and tasks."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest

import vectors_v2
from agentkit import AGENT, AGENT_KEY, HDR, OPEN_POLICY, agent_node, nonce, proof, pub, register, session
from conftest import rows, sqlite, verify
from jwtkit import AUDIENCE, ENTRA_ISS, TENANT, Idp, claims, jws, rsa_jwk
from sijill import agents, oidc, policy, record

HERE = Path(__file__).parent
FIXTURE_JWKS = HERE / "tokens" / "7178fa37eccd7fa82260bd6faaca752e357381418c594ac5f736df5b725df546.json"
OFFICER = "5f6e7d8c-1a2b-4c3d-8e9f-0a1b2c3d4e5f"
PRINCIPALS = f"""principals:
  require: true
  min_assurance: substantial
  issuers:
    - id: entra-moi
      profile: entra
      issuer: {ENTRA_ISS}
      tenant: {TENANT}
      audience: {AUDIENCE}
      assurance:
        - {{when: {{acrs_any: [c3]}}, level: high}}
        - {{when: {{amr_any: [mfa, ngcmfa]}}, level: substantial}}
        - {{level: low}}
      display_claim: preferred_username
"""
POLICY = OPEN_POLICY + PRINCIPALS
HUMAN = f"human:entra-moi:{record.sha256_hex(record.canonical_json({'iss': ENTRA_ISS, 'sub': OFFICER}))}"


def officer(life=3600, **over) -> str:
    return jws({**claims(life=life, sub="pairwise-officer", oid=OFFICER, scp="Case.ReadWrite", idtyp="user",
                         amr=["pwd", "mfa"], preferred_username="officer@moi.gov.ae"), **over})


class Model:
    """Upstream that records the headers it was sent."""

    def __init__(self):
        self.seen = []

    def __call__(self, request):
        self.seen.append(dict(request.headers))
        return httpx.Response(200, json={"id": "c", "model": "m", "choices": [
            {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}]})


def node(tmp_path, policy_text=POLICY, model=None, idp=None):
    return agent_node(tmp_path, model or Model(), policy_text=policy_text, idp=idp or Idp({"keys": [rsa_jwk()]}))


def chat(client, token=None, sess=None, **headers):
    h = {**({"X-Sijil-Principal-Token": token} if token else {}),
         **({"X-Sijil-Agent-Session": sess["agent_session"]} if sess else {}), **headers}
    return client.post("/v1/chat/completions", headers=h, json={
        "model": "llama-3.2-3b-instruct", "messages": [{"role": "user", "content": "status of my case?"}]})


def test_vector_70_claims_are_what_the_ledger_computes(tmp_path):
    """The M2a golden officer token, through the ledger's own code: same principal, same principal_claims."""
    pcfg = policy.load_principals({"min_assurance": "substantial", "issuers": [{
        "id": "entra-moi", "profile": "entra", "issuer": ENTRA_ISS, "tenant": TENANT, "audience": AUDIENCE,
        "algs": ["EdDSA"], "jwks": {"mode": "pinned", "path": str(FIXTURE_JWKS),
                                    "sha256": record.sha256_hex(FIXTURE_JWKS.read_bytes())},
        "assurance": [{"when": {"acrs_any": ["c3"]}, "level": "high"},
                      {"when": {"amr_any": ["mfa", "ngcmfa"]}, "level": "substantial"}, {"level": "low"}]}]})

    async def go():
        async with httpx.AsyncClient() as http:
            keys = oidc.build_jwks(pcfg.issuers, str(tmp_path), http)
            return await oidc.human(pcfg, keys, vectors_v2.OFFICER_JWT, vectors_v2.NBF + 60)
    h = asyncio.run(go())
    assert h["principal"] == vectors_v2.GOV_PRINCIPAL
    assert h["claims"] == json.loads(vectors_v2.out[70]["ext"])["principal_claims"]


def test_missing_token_is_refused_and_sealed_and_nothing_is_forwarded(tmp_path):
    model = Model()
    client, s = node(tmp_path, model=model)
    with client:
        r = chat(client)
    assert r.status_code == 401 and r.json()["sijill"]["rule_hits"] == ["principal-missing"]
    [rec] = rows(s.db_path)
    assert r.headers["x-sijill-seq"] == "1" and model.seen == []
    assert (rec["decision"], rec["mode"], rec["principal"], rec["task_seq"]) == ("block", "enforce", "", "")
    assert json.loads(rec["ext"]) == {"principal_error": "missing"}
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_valid_token_seals_a_pseudonymous_principal_and_its_claims(tmp_path):
    model = Model()
    client, s = node(tmp_path, model=model)
    token = officer()
    with client:
        assert chat(client, token).status_code == 200
    [rec] = rows(s.db_path)
    c = json.loads(rec["ext"])["principal_claims"]
    assert rec["principal"] == HUMAN
    assert (c["issuer_id"], c["profile"], c["validation"], c["tenant"], c["assurance"], c["assurance_rule"]) == \
        ("entra-moi", "entra", "jwt", TENANT, "substantial", 1)
    assert c["amr"] == ["mfa", "pwd"] and c["token_hash"] == record.sha256_hex(token.encode())
    assert OFFICER not in rec["ext"] and "officer@moi.gov.ae" not in rec["ext"]
    assert sqlite(s.db_path, "SELECT display FROM principal_index") == "officer@moi.gov.ae"
    assert not any(k.startswith("x-sijil") for k in model.seen[0])           # the token never goes upstream
    assert verify(s.db_path, s.pubkey_path)[0] == 0


@pytest.mark.parametrize("token, status, hit, code", [
    (officer(amr=["pwd"]), 403, "principal-assurance-low", "assurance"),
    (jws(claims(sub="app", oid=OFFICER, idtyp="app", roles=["x"])), 401, "principal-invalid", "not_delegated"),
    (officer(tid="ffffffff-0000-4000-8000-000000000000"), 401, "principal-invalid", "tenant"),
    (officer(ver="1.0"), 401, "principal-invalid", "issuer"),
    (officer(life=-5), 401, "principal-expired", "expired"),
    (officer(life=60), 401, "principal-expired", "expired"),     # would expire before the answer is sealed (U1)
    (officer(aud="api://other"), 401, "principal-invalid", "audience"),
])
def test_each_refusal_seals_its_reserved_hit(tmp_path, token, status, hit, code):
    client, s = node(tmp_path)
    with client:
        r = chat(client, token)
    assert r.status_code == status and r.json()["sijill"]["rule_hits"] == [hit]
    [rec] = rows(s.db_path)
    assert json.loads(rec["ext"]) == {"principal_error": code}
    assert rec["principal"] == (HUMAN if code == "assurance" else "")      # validated principal only when valid
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_unreachable_idp_is_503_jwks_unavailable(tmp_path):
    idp = Idp({"keys": [rsa_jwk()]})
    idp.down = True
    client, s = node(tmp_path, idp=idp)
    with client:
        r = chat(client, officer())
    assert r.status_code == 503 and r.json()["sijill"]["rule_hits"] == ["principal-jwks-unavailable"]


def test_bearer_authorization_is_read_only_when_accepted(tmp_path):
    client, s = node(tmp_path, POLICY.replace("require: true", "require: true\n  accept_authorization: true"))
    with client:
        assert chat(client, Authorization=f"Bearer {officer()}").status_code == 200
    assert rows(s.db_path)[0]["principal"] == HUMAN


def test_task_binds_the_principal_and_refusals_land_outside_it(tmp_path):
    client, s = node(tmp_path)
    token = officer()
    with client:
        register(client)
        sess = session(client)
        r = client.post("/api/agent/task/start", headers={"X-Sijil-Agent-Session": sess["agent_session"]},
                        json={"intent_hash": "f" * 64, "harness": "http-agent", "session_id": "conv-1"})
        assert r.status_code == 401 and r.json()["detail"]["rule_hits"] == ["principal-missing"]
        task = client.post("/api/agent/task/start", json={"intent_hash": "f" * 64, "harness": "http-agent",
                                                          "session_id": "conv-1"},
                           headers={"X-Sijil-Agent-Session": sess["agent_session"],
                                    "X-Sijil-Principal-Token": token}).json()["seq"]
        assert chat(client, token, sess).status_code == 200                      # same token: claims not repeated
        assert chat(client, officer(jti="refreshed"), sess).status_code == 200   # refreshed token: claims sealed
        assert chat(client, None, sess).status_code == 401                       # principal-missing
        other = jws(claims(sub="p2", oid="99999999-0000-4000-8000-000000000000", scp="x", amr=["mfa"]))
        assert chat(client, other, sess).status_code == 409                      # principal-task-mismatch
        end = client.post("/api/agent/task/end", json={"task_seq": str(task), "outcome": "completed"},
                          headers={"X-Sijil-Agent-Session": sess["agent_session"]}).json()
    start, same, refreshed, missing, mismatch, task_end = rows(s.db_path)[1:]
    x = json.loads(start["ext"])
    assert (start["principal"], x["principal_auth"], x["principal_claims"]["assurance"]) == (HUMAN, "oidc", "substantial")
    assert same["task_seq"] == str(task) and "principal_claims" not in json.loads(same["ext"] or "{}")
    assert json.loads(refreshed["ext"])["principal_claims"]["token_hash"] != x["principal_claims"]["token_hash"]
    assert (missing["task_seq"], missing["agent_id"], missing["principal"]) == ("", AGENT, "")
    assert (mismatch["task_seq"], json.loads(mismatch["rule_hits"])) == ("", ["principal-task-mismatch"])
    assert mismatch["principal"].startswith("human:entra-moi:") and mismatch["principal"] != HUMAN
    assert (end["inference"], end["blocked"]) == (2, 0)                         # refusals are outside the task
    code, line = verify(s.db_path, s.pubkey_path)
    assert code == 0 and "agent_auth=key:1," in line


def test_principal_oidc_register_policy_takes_registered_by_from_the_token(tmp_path):
    client, s = node(tmp_path, POLICY.replace("register_policy: open", "register_policy: principal_oidc"))
    with client:
        assert register(client).status_code == 401
        n = nonce(client, purpose="register")
        msg = {"agent_id": AGENT, "agent_pubkey": pub(AGENT_KEY), "nonce": n, "registered_by": HUMAN}
        r = client.post("/api/agent/register", json={**msg, "registered_by": "local:" + "0" * 64,
                                                     "self_proof": proof(AGENT_KEY, msg)},
                        headers={**HDR, "X-Sijil-Principal-Token": officer()})
        assert r.status_code == 200
    rec = rows(s.db_path)[-1]
    assert (rec["principal"], json.loads(rec["ext"])["principal_auth"]) == (HUMAN, "oidc")
    assert verify(s.db_path, s.pubkey_path)[0] == 0


@pytest.mark.parametrize("change, match", [
    (("profile: entra", "profile: uaepass"), "profile"),
    (("profile: entra", "profile: oidc\n      mode: userinfo"), "userinfo"),
    ((f"tenant: {TENANT}", "tenant: moi"), "tenant"),
    (("{level: low}", "{level: medium}"), "assurance"),
])
def test_policy_refuses_what_m2b_does_not_build(tmp_path, change, match):
    (tmp_path / "p.yaml").write_text(POLICY.replace(*change))
    with pytest.raises(ValueError, match=match):
        policy.load(tmp_path / "p.yaml")


def test_principal_oidc_needs_a_principals_block(tmp_path):
    (tmp_path / "p.yaml").write_text(OPEN_POLICY.replace("register_policy: open", "register_policy: principal_oidc"))
    with pytest.raises(ValueError, match="principal_oidc"):
        policy.load(tmp_path / "p.yaml")


def test_pinned_pretty_printed_jwks_still_has_a_snapshot_for_the_sealed_hash(tmp_path):
    """jwks_hash is canonical; a pinned file that is not canonical must not leave U2 without a file."""
    pinned = tmp_path / "pinned.json"
    pinned.write_text(json.dumps({"keys": [rsa_jwk()]}, indent=4))
    text = POLICY.replace("      audience:", f"      jwks: {{mode: pinned, path: {pinned}, "
                          f"sha256: {record.sha256_hex(pinned.read_bytes())}}}\n      audience:")
    client, s = node(tmp_path, text)
    with client:
        assert chat(client, officer()).status_code == 200
    jwks_hash = json.loads(rows(s.db_path)[0]["ext"])["principal_claims"]["jwks_hash"]
    snap = tmp_path / "jwks" / f"{jwks_hash}.json"
    assert snap.exists() and record.sha256_hex(snap.read_bytes()) == jwks_hash
    assert jwks_hash != record.sha256_hex(pinned.read_bytes())


@pytest.mark.parametrize("change", [
    ("display_claim: preferred_username", "display_claim: [a]"),
    ("{when: {amr_any: [mfa, ngcmfa]}", "{when: {amr_any: mfa}"),
    ("{when: {acrs_any: [c3]}", "{when: {claim_equals: [x]}"),
])
def test_policy_refuses_malformed_principal_claims_config(tmp_path, change):
    (tmp_path / "p.yaml").write_text(POLICY.replace(*change))
    with pytest.raises(ValueError):
        policy.load(tmp_path / "p.yaml")


def test_task_ended_mid_call_keeps_the_validated_human_and_claims(tmp_path):
    client, s = node(tmp_path)
    token = officer()
    with client:
        n = client.app.state.node
        register(client)
        sess = session(client)
        h = {"X-Sijil-Agent-Session": sess["agent_session"], "X-Sijil-Principal-Token": token}
        t = client.post("/api/agent/task/start", json={"intent_hash": "f" * 64, "harness": "http-agent",
                                                       "session_id": "conv-1"}, headers=h).json()["seq"]
        loop = client.portal.call(asyncio.get_running_loop)
        real = n.resolver.resolve

        def resolve_then_end(model):
            n.resolver.resolve = real
            asyncio.run_coroutine_threadsafe(agents.end_task(n, n.store.get(t), "timeout"), loop).result()
            return real(model)
        n.resolver.resolve = resolve_then_end
        assert chat(client, token, sess).status_code == 200
    inf = rows(s.db_path)[-1]
    assert (inf["type"], inf["task_seq"], inf["agent_id"], inf["principal"]) == ("inference", "", AGENT, HUMAN)
    c = json.loads(inf["ext"])["principal_claims"]
    assert c["token_hash"] == record.sha256_hex(token.encode()) and c["assurance"] == "substantial"
    assert verify(s.db_path, s.pubkey_path)[0] == 0
