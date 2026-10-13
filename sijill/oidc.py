"""OIDC token validation for the ledger (spec §5.8.5, §17.2.3, §17.2.6): compact JWS over RS256 or EdDSA,
JWKS fetched through discovery or pinned in the policy, snapshots by hash. Built on `cryptography` only.

Error codes are the §17.2.7 `principal_error` values; the status is the HTTP status the caller returns.
"""

import base64
import json
import re
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
    """`principal` is the validated principal when the token was valid but refused (assurance, task)."""

    def __init__(self, code: str, status: int = 401, principal: str = ""):
        super().__init__(code)
        self.code, self.status, self.principal = code, status, principal


# §17.2.7: principal_error code -> the reserved rule id sealed in rule_hits (everything else is principal-invalid)
HITS = {"missing": "principal-missing", "expired": "principal-expired", "not_yet_valid": "principal-expired",
        "jwks_stale": "principal-jwks-unavailable", "assurance": "principal-assurance-low",
        "task_principal": "principal-task-mismatch"}


def hit(code: str) -> str:
    return HITS.get(code, "principal-invalid")


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
    usable = 0
    for k in keys:
        if not isinstance(k, dict):
            raise ValueError(f"JWKS key malformed: {k!r}")
        need = {"RSA": ("n", "e"), "OKP": ("crv", "x")}.get(k.get("kty"))
        if need is None:
            continue                                  # an IdP may publish other key types (EC); we never select them
        if not isinstance(k.get("kid"), str) or not all(isinstance(k.get(f), str) for f in need):
            raise ValueError(f"JWKS key malformed: {k!r}")
        usable += 1
    if not usable:
        raise ValueError("JWKS has no RSA or OKP key")
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
            try:
                self.snapshot(self.doc)               # jwks_hash is the canonical hash, so its file must exist (U2)
            except OSError as e:
                raise ValueError(f"cannot write JWKS snapshot to {self.dir} (set SIJILL_JWKS_DIR to a writable "
                                 f"directory): {e}") from e

    async def refresh(self, now: float) -> None:
        try:
            conf = (await self.http.get(self.issuer.rstrip("/") + "/.well-known/openid-configuration"))
            doc = check_jwks((await self.http.get(conf.raise_for_status().json()["jwks_uri"])).raise_for_status().json())
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
            return                                    # keep the last snapshot until max_stale_s
        try:
            self.snapshot(doc)                        # before the cache changes: no hash is sealed without its file
        except OSError:
            raise OidcError("jwks_stale", 503)
        self.doc, self.fetched = doc, now

    def snapshot(self, doc: dict) -> None:
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


async def validate(token, issuers: dict, jwks: dict, now: float, margin: float = 0.0) -> Verified:
    """§17.2.3 steps 1-4: alg, issuer by exact iss, kid and signature, aud, nbf/exp. A token that expires within
    `margin` seconds counts as expired: the record it authorises is sealed up to that long after now (U1)."""
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
    if now + margin >= exp:
        raise OidcError("expired")
    if now < nbf - SKEW_S:
        raise OidcError("not_yet_valid")
    return Verified(cfg, header, claims, jwks_hash(doc))


PROFILES = ("entra", "oidc")   # uaepass: userinfo only today (§17.2.4); brokered UAE PASS is profile oidc
ISSUER_ID = re.compile(r"[a-z0-9-]{1,32}")
GUID = re.compile(r"[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}")
LEVELS = record.PRINCIPAL_ASSURANCE
CONDITIONS = ("acrs_any", "amr_any", "claim_equals")


def principal_issuer(d, where: str) -> dict:
    """One principals.issuers entry (spec §17.2.2), defaults filled in."""
    if not isinstance(d, dict) or not isinstance(d.get("id"), str) or not ISSUER_ID.fullmatch(d["id"]):
        raise ValueError(f"{where}: id must match [a-z0-9-]{{1,32}}")
    if d.get("profile") not in PROFILES or d.get("mode", "jwt") != "jwt":
        raise ValueError(f"{where}: profile must be one of {PROFILES} with mode jwt (userinfo is not built)")
    cfg = issuer_cfg(d, where)
    entra = d["profile"] == "entra"
    if entra and not (isinstance(d.get("tenant"), str) and GUID.fullmatch(d["tenant"])):
        raise ValueError(f"{where}: an entra issuer needs tenant (the tid GUID)")
    rules = d.get("assurance")
    if (not isinstance(rules, list) or not rules
            or any(not isinstance(r, dict) or r.get("level") not in LEVELS or set(r) - {"when", "level"}
                   or not set(r.get("when") or {}) <= set(CONDITIONS) for r in rules)):
        raise ValueError(f"{where}: assurance must be a list of {{when?, level}} rules, level in {LEVELS}")
    for r in rules:
        w = r.get("when") or {}
        if (not isinstance(w, dict) or not all(isinstance(w.get(k, []), list) for k in ("acrs_any", "amr_any"))
                or not isinstance(w.get("claim_equals", {}), dict)):
            raise ValueError(f"{where}: assurance `when` needs acrs_any/amr_any lists and a claim_equals map")
    if not all(isinstance(d.get(k, ""), str) for k in ("display_claim", "subject_claim")):
        raise ValueError(f"{where}: display_claim and subject_claim are claim names")
    return {**cfg, "subject_claim": d.get("subject_claim", "oid" if entra else "sub"),
            "require_delegated": d.get("require_delegated", entra), "tenant": d.get("tenant", "")}


def assurance(rules: list, claims: dict) -> tuple[str, int]:
    """First matching rule wins (§17.2.2); a rule with no `when` always matches."""
    def has(name, wanted):
        got = claims.get(name)
        return bool(set(got if isinstance(got, list) else [got]) & set(wanted))
    for i, r in enumerate(rules):
        w = r.get("when") or {}
        if (("acrs_any" not in w or has("acrs", w["acrs_any"])) and ("amr_any" not in w or has("amr", w["amr_any"]))
                and all(claims.get(k) == v for k, v in (w.get("claim_equals") or {}).items())):
            return r["level"], i
    raise OidcError("assurance", 403)


def token_of(pcfg, headers) -> str | None:
    """The principal token: the configured header, else (accept_authorization) a Bearer Authorization."""
    token = headers.get(pcfg.header)
    auth = headers.get("authorization", "")
    if token is None and pcfg.accept_authorization and auth.startswith("Bearer "):
        token = auth[7:]
    return token


async def human(pcfg, jwks: dict, token, now: float, margin: float = 0.0) -> dict:
    """§17.2.3 steps 1-8 for validation: jwt. Returns {principal, claims, display}; raises OidcError."""
    if token is None:
        raise OidcError("missing")
    v = await validate(token, {i["issuer"]: i for i in pcfg.issuers}, jwks, now, margin)
    c, i = v.claims, v.cfg
    if i["profile"] == "entra" and c.get("ver") != "2.0":
        raise OidcError("issuer")                      # v1.0 tokens carry another iss (§17.2.3 step 2)
    if i["profile"] == "entra" and c.get("tid") != i["tenant"]:
        raise OidcError("tenant")
    delegated = "scp" in c and c.get("idtyp") != "app"
    if i["require_delegated"] and not delegated:
        raise OidcError("not_delegated")
    subject = c.get(i["subject_claim"])
    if not isinstance(subject, str) or not subject:
        raise OidcError("malformed")
    level, rule = assurance(i["assurance"], c)
    principal = f"human:{i['id']}:{record.sha256_hex(record.canonical_json({'iss': c['iss'], 'sub': subject}))}"
    claims = {"issuer_id": i["id"], "profile": i["profile"], "validation": "jwt", "iss": c["iss"],
              "aud": i["audience"], "tenant": c["tid"] if i["profile"] == "entra" else "", "assurance": level,
              "assurance_rule": rule, "delegated": delegated, "token_hash": record.sha256_hex(token.encode()),
              "kid": v.header["kid"], "alg": v.header["alg"], "jwks_hash": v.jwks_hash,
              "nbf": ts_at(c.get("nbf", c.get("iat"))), "exp": ts_at(c["exp"])}
    if isinstance(c.get("amr"), list) and all(isinstance(a, str) for a in c["amr"]):
        claims["amr"] = sorted(set(c["amr"]))
    if LEVELS.index(level) < LEVELS.index(pcfg.min_assurance):
        raise OidcError("assurance", 403, principal)
    display = c.get(i["display_claim"]) if i.get("display_claim") else None
    return {"principal": principal, "claims": claims, "display": display if isinstance(display, str) else None}


def build_jwks(cfgs, snapshot_dir: str, http: httpx.AsyncClient) -> dict:
    """One Jwks per issuer URL (the first entry naming it wins)."""
    out = {}
    for cfg in cfgs:
        out.setdefault(cfg["issuer"], Jwks(cfg, snapshot_dir, http))
    return out
