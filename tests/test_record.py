"""Freezes record.py: a fixed key and a fixed record must always produce the same hash and signature."""

import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sijill import record

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
BODY = dict(type="inference", ts="2026-09-25T10:00:00.000Z", model_id="llama-3.2-3b-instruct",
            model_digest="sha256:" + "0" * 64, node_id="auh-node-01", node_region="AE-AZ",
            policy_id="gov-assistant", policy_hash="a" * 64, approval_ref="APR-0147", mode="record",
            decision="flag", rule_hits='["sensitive_terms"]', input_hash="b" * 64, output_hash="c" * 64)


def test_canonical_form():
    rec = record.seal(BODY, 1, record.GENESIS_HASH, KEY)
    canon = record.canonical_json({k: v for k, v in rec.items() if k not in ("record_hash", "signature")})
    assert canon.startswith(b'{"approval_ref":"APR-0147","decision":"flag",')
    assert b'"seq":1,' in canon and b" " not in canon


def test_golden_vector():
    rec = record.seal(BODY, 1, record.GENESIS_HASH, KEY)
    assert rec["record_hash"] == GOLDEN_HASH
    assert rec["signature"] == GOLDEN_SIGNATURE
    assert list(rec) == list(record.FIELDS)


def test_non_ascii_preserved():
    assert record.canonical_json({"q": "هوية"}) == '{"q":"هوية"}'.encode("utf-8")


def test_ts_format():
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", record.now_ts())


@pytest.mark.parametrize("change", [{"seq": 1}, {"decision": "maybe"}, {"rule_hits": "{}"}, {"mode": 1}])
def test_seal_rejects_bad_bodies(change):
    with pytest.raises((ValueError, TypeError)):
        record.seal({**BODY, **change}, 1, record.GENESIS_HASH, KEY)


def test_seal_rejects_bad_seq():
    with pytest.raises(ValueError):
        record.seal(BODY, 0, record.GENESIS_HASH, KEY)


# Computed with verifier/sijill_verify.py's independent canonicalisation, not with record.py.
GOLDEN_HASH = "2a01c58193be1f9101ac25f20772cd166b0d91e7f3f4a53c081db300f77e980d"
GOLDEN_SIGNATURE = ("fc924f542aeed7df0dab7d9ecd199696db8acc4e4153408dddea4ef77d83500e"
                    "d34cf1c59d37300645e572f6f9ed20b425d2309970db99801282193764ccec02")
