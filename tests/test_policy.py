"""policy.load() validation and Settings.from_env."""

from pathlib import Path

import pytest
import yaml

from sijill import policy
from sijill.proxy import Settings

ROOT = Path(__file__).resolve().parent.parent

BASE = {"policy_id": "gov-assistant", "approval_ref": "APR-0147",
        "node": {"id": "auh-node-01", "region": "AE-AZ"}}


def write(tmp_path, rules) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump({**BASE, "rules": rules}))
    return p


def test_load_rejects_reserved_upstream_error_id(tmp_path):
    rules = [{"id": policy.UPSTREAM_ERROR_HIT, "type": "keyword_flag", "terms": ["x"], "mode": "record"}]
    with pytest.raises(ValueError, match=policy.UPSTREAM_ERROR_HIT):
        policy.load(write(tmp_path, rules))


@pytest.mark.parametrize("rule", [
    {"id": "residency", "type": "region_allowlist", "mode": "enforce"},
    {"id": "residency", "type": "region_allowlist", "allow": "AE-AZ", "mode": "enforce"},
    {"id": "approved", "type": "model_allowlist", "mode": "enforce"},
    {"id": "approved", "type": "model_allowlist", "allow_digests": [1, 2], "mode": "enforce"},
    {"id": "terms", "type": "keyword_flag", "mode": "record"},
    {"id": "terms", "type": "keyword_flag", "terms": [], "mode": "record"},
])
def test_load_rejects_missing_or_bad_required_keys(tmp_path, rule):
    with pytest.raises(ValueError, match=rule["id"]):
        policy.load(write(tmp_path, [rule]))


def test_load_accepts_repo_policy():
    pol = policy.load(ROOT / "policy.yaml")
    assert [r["id"] for r in pol.rules] == ["residency", "approved_models", "sensitive_terms"]


def test_upstream_timeout_from_env(monkeypatch):
    monkeypatch.setenv("UPSTREAM_TIMEOUT", "7.5")
    assert Settings.from_env().upstream_timeout == 7.5
