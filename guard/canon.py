"""canonical_json and SHA-256: the same bytes as the ledger's record.py (spec §0). Re-implemented here because the
guard never imports sijill/ (spec §10); tests/test_guard_unicode.py checks the two agree."""

import hashlib
import json


def canonical_json(obj) -> bytes:
    """ValueError on NaN or an infinity, as the ledger (§2.2): callers fail closed.
    surrogatepass: a lone surrogate (a JSON "\ud800" escape) hashes instead of raising."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8", "surrogatepass")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def args_hash(args) -> str:
    """input_hash of a tool_call and args_hash of a tool use (spec §2.4.1, §5.4)."""
    return sha256_hex(canonical_json(args))
