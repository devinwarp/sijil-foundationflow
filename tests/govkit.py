"""The government profile's side of the tests (spec §17): an Entra officer and a supervisor, a policy with their
issuer, the case pack with a named-approval route, and a model that asks for case-API tools."""

import json

import httpx

from agentkit import OPEN_POLICY, agent_node
from jwtkit import AUDIENCE, ENTRA_ISS, TENANT, Idp, claims, jws, rsa_jwk
from sijill import record

OFFICER = "5f6e7d8c-1a2b-4c3d-8e9f-0a1b2c3d4e5f"
SUPERVISOR = "7a8b9c0d-2e3f-4a5b-9c6d-1e2f3a4b5c6d"
APPROVALS = "api://sijil-approvals"
CLOSER = "Sijil.Approver.CaseClosure"
POLICY = OPEN_POLICY + f"""principals:
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
PACK = """rulepack_id: moi-case-pack
version: 0.1.0
rules:
  - id: case-closure-needs-approval
    description: Closing a case is a consequential action and needs a named approver
    on: tool_call
    match: { tool: ["http:case-api:closeCase"] }
    action: confirm
hitl:
  channel: entra
  entra: {issuer_id: entra-moi, audience: "api://sijil-approvals"}
  separation_of_duties: true
  routes:
    - id: case-closure
      rules: ["case-closure-*"]
      approvers: {role: Sijil.Approver.CaseClosure}
      min_assurance: high
      timeout_seconds: 900
  notify: {teams_webhook_env: SIJIL_TEST_TEAMS_WEBHOOK}
"""
CASE = "MOI-2026-004211"
NOTE = {"caseId": CASE, "note": "Applicant uploaded the missing salary certificate."}
CLOSE = {"caseId": CASE, "resolution": "approved"}
CALLS = {"close": ("closeCase", CLOSE), "note": ("addCaseNote", NOTE), "get": ("getCase", {"caseId": CASE})}


def human(oid: str) -> str:
    return f"human:entra-moi:{record.sha256_hex(record.canonical_json({'iss': ENTRA_ISS, 'sub': oid}))}"


def officer(**over) -> str:
    """The case officer's token for the agent's audience (assurance substantial)."""
    return jws({**claims(sub="pairwise-officer", oid=OFFICER, scp="Case.ReadWrite", idtyp="user", amr=["pwd", "mfa"],
                         preferred_username="officer@moi.gov.ae", roles=[CLOSER]), **over})


def supervisor(roles=(CLOSER,), acrs=("c3",), oid=SUPERVISOR, **over) -> str:
    """The supervisor's token for the approvals app (assurance high with acrs c3)."""
    return jws({**claims(aud=APPROVALS, sub="pairwise-supervisor", oid=oid, scp="Approvals.Decide", idtyp="user",
                         amr=["mfa", "rsa"], acrs=list(acrs), roles=list(roles),
                         preferred_username="supervisor@moi.gov.ae"), **over})


def model(request: httpx.Request) -> httpx.Response:
    """Asks for the case-API tool named by a keyword of the prompt, with a call id derived from the prompt."""
    body = json.loads(request.content)
    prompt = body["messages"][-1]["content"]
    word = next((w for w in CALLS if w in prompt), None)
    message = {"role": "assistant", "content": "Done."}
    if word:
        name, args = CALLS[word]
        message = {"role": "assistant", "content": None, "tool_calls": [{
            "id": "call_" + record.sha256_hex(prompt.encode())[:12], "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}]}
    return httpx.Response(200, json={"id": "c", "model": body.get("model", "m"), "choices": [
        {"index": 0, "message": message, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1840,
                                                                             "completion_tokens": 96}})


def gov_node(tmp_path, pack=PACK, handler=model, idp=None, policy=POLICY, **overrides):
    """A ledger with the government policy and the case pack at tmp_path/starter.yaml, where guardkit's guard
    config points; (TestClient, Settings, Idp)."""
    (tmp_path / "starter.yaml").write_text(pack)
    idp = idp or Idp({"keys": [rsa_jwk()]})
    client, s = agent_node(tmp_path, handler, policy, idp=idp, rulepack_path=str(tmp_path / "starter.yaml"),
                           **overrides)
    return client, s, idp
