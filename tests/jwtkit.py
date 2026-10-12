"""Test identity provider: RS256 and EdDSA compact JWS, JWKS documents, discovery (spec §17.2.3, §17.2.6)."""

import base64
import json
import time

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TENANT = "1b2c3d4e-0000-4000-8000-00000000abcd"
ENTRA_ISS = f"https://login.microsoftonline.com/{TENANT}/v2.0"
AUDIENCE = "api://sijil-moi-pilot"
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ED_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(128, 160)))    # the §17.8 fixture issuer key


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def rsa_jwk(key=RSA_KEY, kid="rsa-1") -> dict:
    n = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": b64u(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")), "e": b64u(n.e.to_bytes(3, "big"))}


def jws(claims: dict, kid="rsa-1", alg="RS256", key=None, **header) -> str:
    head = b64u(json.dumps({"alg": alg, "kid": kid, "typ": "JWT", **header}).encode())
    signing_input = f"{head}.{b64u(json.dumps(claims).encode())}".encode()
    if alg == "RS256":
        sig = (key or RSA_KEY).sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "EdDSA":
        sig = (key or ED_KEY).sign(signing_input)
    else:
        sig = b"x"
    return f"{signing_input.decode()}.{b64u(sig)}"


def claims(iss=ENTRA_ISS, aud=AUDIENCE, life=3600, **extra) -> dict:
    now = int(time.time())
    return {"iss": iss, "aud": aud, "iat": now, "nbf": now, "exp": now + life, "tid": TENANT, "ver": "2.0", **extra}


class Idp:
    """Answers <issuer>/.well-known/openid-configuration and its jwks_uri; counts requests; can fail."""

    def __init__(self, jwks: dict, issuer=ENTRA_ISS):
        self.jwks, self.issuer, self.calls, self.down = jwks, issuer, [], False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(str(request.url))
        if self.down:
            return httpx.Response(503)
        if str(request.url) == self.issuer + "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": self.issuer, "jwks_uri": "https://keys.test/jwks"})
        if str(request.url) == "https://keys.test/jwks":
            return httpx.Response(200, json=self.jwks)
        return httpx.Response(404)
