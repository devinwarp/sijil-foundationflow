"""OIDC token validation for the ledger (spec §5.8.5, §17.2.3, §17.2.6): compact JWS over RS256 or EdDSA,
JWKS fetched through discovery or pinned in the policy, snapshots by hash. Built on `cryptography` only.

Error codes are the §17.2.7 `principal_error` values; the status is the HTTP status the caller returns.
"""

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import record

ALGS = ("RS256", "EdDSA")      # never none, never HMAC (§17.2.3 step 1). ponytail: ES256 when an IdP needs it
MAX_TOKEN = 16384              # characters; longer is refused before any decoding
SKEW_S = 60                    # on nbf only
FORCED_REFRESH_S = 300         # unknown kid: at most one forced refresh per issuer per 300 s
JWKS_DEFAULT = {"mode": "fetch", "refresh_s": 3600, "max_stale_s": 86400}


def ts_at(epoch: float) -> str:
    """record.now_ts() form for any instant."""
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class OidcError(Exception):
    def __init__(self, code: str, status: int = 401):
        super().__init__(code)
        self.code, self.status = code, status


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issuer_cfg(d, where: str) -> dict:
    """Shape of one issuer entry, defaults filled in. Pinned files are read by Jwks, at startup."""
    if not isinstance(d, dict) or not isinstance(d.get("issuer"), str) or not d["issuer"].startswith("https://"):
        raise ValueError(f"{where}: issuer must be an https:// URL")
    if not isinstance(d.get("audience"), str) or not d["audience"]:
        raise ValueError(f"{where}: audience is required")
    algs = d.get("algs", ["RS256"])
    if not isinstance(algs, list) or not algs or not set(algs) <= set(ALGS):
        raise ValueError(f"{where}: algs must be a non-empty subset of {ALGS}")
    jwks = {**JWKS_DEFAULT, **(d.get("jwks") or {})}
    if jwks["mode"] == "pinned":
        if not isinstance(jwks.get("path"), str) or not isinstance(jwks.get("sha256"), str):
            raise ValueError(f"{where}: jwks mode pinned needs path and sha256")
    elif jwks["mode"] != "fetch" or not all(type(jwks[k]) is int and jwks[k] > 0 for k in ("refresh_s", "max_stale_s")):
        raise ValueError(f"{where}: jwks.mode must be fetch (refresh_s, max_stale_s > 0) or pinned")
    return {**d, "algs": algs, "jwks": jwks}


def jwk_key(jwk: dict):
    if jwk.get("kty") == "RSA":
        n, e = (int.from_bytes(b64d(jwk[k]), "big") for k in ("n", "e"))
        return rsa.RSAPublicNumbers(e, n).public_key()
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        return Ed25519PublicKey.from_public_bytes(b64d(jwk["x"]))
    raise ValueError(f"unsupported key {jwk.get('kty')}/{jwk.get('crv')}")


def check_jwks(doc) -> dict:
    """Shape check: every key has kty and kid, and n/e (RSA) or crv/x (OKP)."""
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, list) or not keys:
        raise ValueError("JWKS has no keys")
    for k in keys:
        need = {"RSA": ("n", "e"), "OKP": ("crv", "x")}.get(k.get("kty") if isinstance(k, dict) else None)
        if need is None or not isinstance(k.get("kid"), str) or not all(isinstance(k.get(f), str) for f in need):
            raise ValueError(f"JWKS key malformed: {k!r}")
    return doc


def jwks_hash(doc: dict) -> str:
    return record.sha256_hex(record.canonical_json(doc))


class Jwks:
    """The key set in force for one issuer (spec §17.2.6)."""

    def __init__(self, cfg: dict, snapshot_dir: str, http: httpx.AsyncClient):
        self.issuer, self.cfg, self.dir, self.http = cfg["issuer"], cfg["jwks"], Path(snapshot_dir), http
        self.doc, self.fetched, self.forced = None, None, None
        if self.cfg["mode"] == "pinned":
            raw = Path(self.cfg["path"]).read_bytes()
            if record.sha256_hex(raw) != self.cfg["sha256"]:
                raise ValueError(f"pinned JWKS {self.cfg['path']} does not match jwks.sha256 in the policy")
            self.doc = check_jwks(json.loads(raw))

    async def refresh(self, now: float) -> None:
        try:
            conf = (await self.http.get(self.issuer.rstrip("/") + "/.well-known/openid-configuration"))
            doc = check_jwks((await self.http.get(conf.raise_for_status().json()["jwks_uri"])).raise_for_status().json())
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
            return                                    # keep the last snapshot until max_stale_s
        self.doc, self.fetched = doc, now
        self.dir.mkdir(parents=True, exist_ok=True)
        snap = self.dir / f"{jwks_hash(doc)}.json"
        if not snap.exists():
            snap.write_bytes(record.canonical_json(doc))

    async def key(self, kid, now: float):
        """(jwks document, public key) for `kid`, refreshing as §17.2.6 says."""
        fetch = self.cfg["mode"] == "fetch"
        if fetch and (self.fetched is None or now - self.fetched >= self.cfg["refresh_s"]):
            await self.refresh(now)
        if fetch and (self.fetched is None or now - self.fetched >= self.cfg["max_stale_s"]):
            raise OidcError("jwks_stale", 503)
        found = self.find(kid)
        if found is None and fetch and (self.forced is None or now - self.forced >= FORCED_REFRESH_S):
            self.forced = now
            await self.refresh(now)
            found = self.find(kid)
        if found is None:
            raise OidcError("kid")
        return self.doc, found

    def find(self, kid):
        for k in self.doc["keys"] if self.doc else []:
            if k["kid"] == kid:
                try:
                    return jwk_key(k)
                except (ValueError, KeyError):
                    return None
        return None


@dataclass
class Verified:
    cfg: dict
    header: dict
    claims: dict
    jwks_hash: str


def decode(token):
    if isinstance(token, str) and len(token) > MAX_TOKEN:
        raise OidcError("malformed")
    try:
        head, body, sig = token.split(".")
        header, claims = json.loads(b64d(head)), json.loads(b64d(body))
        signature = b64d(sig)
    except (AttributeError, ValueError, TypeError, RecursionError):
        raise OidcError("malformed")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise OidcError("malformed")
    return header, claims, f"{head}.{body}".encode(), signature


async def validate(token, issuers: dict, jwks: dict, now: float) -> Verified:
    """§17.2.3 steps 1-4: alg, issuer by exact iss, kid and signature, aud, nbf/exp."""
    header, claims, signing_input, signature = decode(token)
    if header.get("alg") not in ALGS:
        raise OidcError("alg")
    if header.get("typ", "JWT") != "JWT":
        raise OidcError("malformed")
    iss = claims.get("iss")
    cfg = issuers.get(iss) if isinstance(iss, str) else None
    if cfg is None:
        raise OidcError("issuer")
    if header["alg"] not in cfg["algs"]:
        raise OidcError("alg")
    kid = header.get("kid")
    if not isinstance(kid, str):
        raise OidcError("kid")
    doc, key = await jwks[cfg["issuer"]].key(kid, now)
    try:
        if header["alg"] == "RS256" and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        elif header["alg"] == "EdDSA" and isinstance(key, Ed25519PublicKey):
            key.verify(signature, signing_input)
        else:
            raise OidcError("alg")
    except InvalidSignature:
        raise OidcError("signature")
    aud = claims.get("aud")
    if not (aud == cfg["audience"] or (isinstance(aud, list) and cfg["audience"] in aud)):
        raise OidcError("audience")
    exp, nbf = claims.get("exp"), claims.get("nbf", claims.get("iat"))
    if not all(type(v) in (int, float) and abs(v) < 1e18 for v in (exp, nbf)):
        raise OidcError("malformed")
    if now >= exp:
        raise OidcError("expired")
    if now < nbf - SKEW_S:
        raise OidcError("not_yet_valid")
    return Verified(cfg, header, claims, jwks_hash(doc))


def build_jwks(cfgs, snapshot_dir: str, http: httpx.AsyncClient) -> dict:
    """One Jwks per issuer URL (the first entry naming it wins)."""
    out = {}
    for cfg in cfgs:
        out.setdefault(cfg["issuer"], Jwks(cfg, snapshot_dir, http))
    return out
