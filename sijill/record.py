"""Record schema, canonicalisation, hashing and signing. FROZEN at H1.

Implements "Record schema" and "Canonicalisation and hashing — exact" from
docs/README.md. Any change here changes every hash; the independent verifier
in verifier/sijill_verify.py must keep agreeing with this module.
"""

import hashlib
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FIELDS = (
    "seq", "type", "ts", "model_id", "model_digest", "node_id", "node_region",
    "policy_id", "policy_hash", "approval_ref", "mode", "decision", "rule_hits",
    "input_hash", "output_hash", "prev_hash", "record_hash", "signature",
)
SEALED_FIELDS = FIELDS[:-2]
BODY_FIELDS = tuple(f for f in SEALED_FIELDS if f not in ("seq", "prev_hash"))
GENESIS_HASH = "0" * 64

TYPES = ("inference", "policy_change")
MODES = ("record", "enforce")
DECISIONS = ("allow", "flag", "block")


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_ts() -> str:
    """ISO 8601 UTC, millisecond precision, e.g. 2026-09-25T10:00:00.123Z."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def input_hash(messages) -> str:
    return sha256_hex(canonical_json(messages))


def output_hash(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))


def compute_record_hash(record: dict) -> str:
    return sha256_hex(canonical_json({k: v for k, v in record.items() if k not in ("record_hash", "signature")}))


def _validate(body: dict) -> None:
    if set(body) != set(BODY_FIELDS):
        missing, extra = set(BODY_FIELDS) - set(body), set(body) - set(BODY_FIELDS)
        raise ValueError(f"record fields mismatch: missing={sorted(missing)} extra={sorted(extra)}")
    bad = [k for k, v in body.items() if not isinstance(v, str)]
    if bad:
        raise TypeError(f"fields must be strings: {bad}")
    if body["type"] not in TYPES or body["mode"] not in MODES or body["decision"] not in DECISIONS:
        raise ValueError(f"invalid type/mode/decision: {body['type']}/{body['mode']}/{body['decision']}")
    hits = json.loads(body["rule_hits"])
    if not isinstance(hits, list) or not all(isinstance(h, str) for h in hits):
        raise ValueError("rule_hits must be a JSON array of strings")


def seal(body: dict, seq: int, prev_hash: str, key: Ed25519PrivateKey) -> dict:
    """Return a complete, signed record: body + seq + prev_hash + record_hash + signature."""
    _validate(body)
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise ValueError("seq must be a positive integer")
    record = {**body, "seq": seq, "prev_hash": prev_hash}
    record["record_hash"] = compute_record_hash(record)
    record["signature"] = key.sign(bytes.fromhex(record["record_hash"])).hex()
    return {f: record[f] for f in FIELDS}
