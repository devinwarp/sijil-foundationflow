"""A test Entra issuer for rehearsals: no tenant, no network. Never use it on a live ledger.

  python test_issuer.py init DIR      RSA key (DIR/issuer.key), its JWKS (DIR/jwks.json) and the policy snippet
  python test_issuer.py officer DIR   a case officer's token for the agent's audience (assurance substantial)
  python test_issuer.py supervisor DIR   a supervisor's token for the approvals app (CaseClosure role, acrs c3)

The tokens carry the claims Entra ID v2.0 issues (iss, tid, ver, oid, scp, idtyp, amr, acrs, roles) and are signed
RS256 under kid test-1, so the ledger validates them exactly as it would a real Entra token.
"""
import base64
import hashlib
import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

TENANT = "1b2c3d4e-0000-4000-8000-00000000abcd"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
AGENT_AUDIENCE, APPROVALS_AUDIENCE = "api://sijil-moi-pilot", "api://sijil-approvals"
ROLE = "Sijil.Approver.CaseClosure"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def init(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (d / "issuer.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
    n = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "RSA", "kid": "test-1", "use": "sig", "alg": "RS256",
                      "n": b64u(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")), "e": b64u(n.e.to_bytes(3, "big"))}]}
    raw = json.dumps(jwks).encode()
    (d / "jwks.json").write_bytes(raw)
    print(f"""principals:
  require: true
  min_assurance: substantial
  issuers:
    - id: entra-moi
      profile: entra
      issuer: {ISSUER}
      tenant: {TENANT}
      audience: {AGENT_AUDIENCE}
      jwks: {{mode: pinned, path: /config/jwks.json, sha256: {hashlib.sha256(raw).hexdigest()}}}
      assurance:
        - {{when: {{acrs_any: [c3]}}, level: high}}
        - {{when: {{amr_any: [mfa, ngcmfa]}}, level: substantial}}
        - {{level: low}}
      display_claim: preferred_username""")


def token(d: Path, **claims) -> str:
    key = serialization.load_pem_private_key((d / "issuer.key").read_bytes(), password=None)
    now = int(time.time())
    body = {"iss": ISSUER, "iat": now, "nbf": now, "exp": now + 3600, "tid": TENANT, "ver": "2.0", "idtyp": "user",
            **claims}
    signing = f"{b64u(json.dumps({'alg': 'RS256', 'kid': 'test-1', 'typ': 'JWT'}).encode())}." \
              f"{b64u(json.dumps(body).encode())}".encode()
    return f"{signing.decode()}.{b64u(key.sign(signing, padding.PKCS1v15(), hashes.SHA256()))}"


if __name__ == "__main__":
    cmd, d = sys.argv[1], Path(sys.argv[2])
    if cmd == "init":
        init(d)
    elif cmd == "officer":
        print(token(d, aud=AGENT_AUDIENCE, sub="pairwise-officer", oid="5f6e7d8c-1a2b-4c3d-8e9f-0a1b2c3d4e5f",
                    scp="Case.ReadWrite", amr=["pwd", "mfa"], preferred_username="officer@moi.gov.ae"))
    elif cmd == "supervisor":
        print(token(d, aud=APPROVALS_AUDIENCE, sub="pairwise-supervisor", oid="7a8b9c0d-2e3f-4a5b-9c6d-1e2f3a4b5c6d",
                    scp="Approvals.Decide", amr=["mfa", "rsa"], acrs=["c3"], roles=[ROLE],
                    preferred_username="supervisor@moi.gov.ae"))
    else:
        sys.exit(__doc__)
