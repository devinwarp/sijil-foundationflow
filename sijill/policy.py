"""Policy YAML loading and rule evaluation."""

import json
from dataclasses import dataclass
from pathlib import Path

import yaml

from .record import MODES, sha256_hex

RULE_TYPES = ("region_allowlist", "model_allowlist", "keyword_flag")

# Reserved pseudo-rule id written to rule_hits when the model runtime failed.
UPSTREAM_ERROR_HIT = "upstream_error"

# Reserved pseudo-rule ids for the operator halt switch.
HALT_HIT = "halted"
RESUME_HIT = "resumed"
# v2.4 (spec §17.1): rule ids the ledger and guard seal themselves; a rule pack may not reuse them.
GOV_HITS = ("principal-missing", "principal-invalid", "principal-expired", "principal-assurance-low",
            "principal-task-mismatch", "principal-jwks-unavailable", "http-operation-unknown",
            "http-task-ambiguous", "approval-timeout")
RESERVED_IDS = (UPSTREAM_ERROR_HIT, HALT_HIT, RESUME_HIT, *GOV_HITS)
RESERVED_PREFIXES = ("budget:",)
ATTESTATION_MODES = ("weights", "api")    # spec §3.1
REGISTER_POLICIES = ("open", "closed")   # spec §5.6; principal_oidc needs principals: (row 5d)


@dataclass(frozen=True)
class AgentsConfig:
    """policy.yaml `agents:` (spec §5.8.5). Absent block: registrations need the admin token (secure default)."""
    register_policy: str = "closed"
    session_ttl_s: int = 28800


def load_agents(doc) -> AgentsConfig:
    if doc is None:
        return AgentsConfig()
    if not isinstance(doc, dict) or doc.get("register_policy", "closed") not in REGISTER_POLICIES:
        raise ValueError(f"agents.register_policy must be one of {REGISTER_POLICIES}")
    ttl = doc.get("session_ttl_s", 28800)
    if type(ttl) is not int or not 60 <= ttl <= 86400:
        raise ValueError("agents.session_ttl_s must be an integer from 60 to 86400")
    return AgentsConfig(register_policy=doc.get("register_policy", "closed"), session_ttl_s=ttl)

# Each rule type must carry one list-of-strings key; keyword terms must be non-empty.
REQUIRED_KEYS = {
    "region_allowlist": ("allow", False),
    "model_allowlist": ("allow_digests", False),
    "keyword_flag": ("terms", True),
}


@dataclass(frozen=True)
class Policy:
    policy_id: str
    version_label: str
    approval_ref: str
    node_id: str
    node_region: str
    rules: tuple[dict, ...]
    hash: str
    attestation: str = "weights"
    agents: AgentsConfig = AgentsConfig()

    def modes(self) -> dict[str, str]:
        return {r["id"]: r["mode"] for r in self.rules}

    def region_allowed(self, region: str) -> bool:
        return all(region in r["allow"] for r in self.rules if r["type"] == "region_allowlist")


def load(path: str | Path) -> Policy:
    raw = Path(path).read_bytes()
    doc = yaml.safe_load(raw)
    rules = tuple(doc.get("rules") or ())
    for r in rules:
        if r.get("type") not in RULE_TYPES or r.get("mode") not in MODES or not r.get("id"):
            raise ValueError(f"invalid rule in {path}: {r}")
        if r["id"] in RESERVED_IDS or str(r["id"]).startswith(RESERVED_PREFIXES):
            raise ValueError(f"rule id {r['id']!r} is reserved in {path}")
        key, non_empty = REQUIRED_KEYS[r["type"]]
        vals = r.get(key)
        if (not isinstance(vals, list) or not all(isinstance(v, str) for v in vals)
                or (non_empty and not vals)):
            raise ValueError(
                f"rule {r['id']!r} in {path}: {key} must be a "
                f"{'non-empty ' if non_empty else ''}list of strings")
    ids = [r["id"] for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError(f"duplicate rule ids in {path}")
    attestation = doc.get("attestation", "weights")
    if attestation not in ATTESTATION_MODES:
        raise ValueError(f"attestation must be one of {ATTESTATION_MODES} in {path}")
    return Policy(
        policy_id=str(doc["policy_id"]),
        version_label=str(doc.get("version_label", "")),
        approval_ref=str(doc["approval_ref"]),
        node_id=str(doc["node"]["id"]),
        node_region=str(doc["node"]["region"]),
        rules=rules,
        hash=sha256_hex(raw),
        attestation=attestation,
        agents=load_agents(doc.get("agents")),
    )


def message_text(messages) -> str:
    """All textual content of OpenAI-style messages, for keyword matching."""
    parts = []
    for m in messages or ():
        content = m.get("content") if isinstance(m, dict) else None
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts += [p.get("text", "") for p in content if isinstance(p, dict)]
    return "\n".join(parts)


def _fires(rule: dict, region: str, model_digest: str, text: str) -> bool:
    if rule["type"] == "region_allowlist":
        return region not in rule["allow"]
    if rule["type"] == "model_allowlist":
        return model_digest not in rule["allow_digests"]
    return any(term.lower() in text for term in rule["terms"])


def evaluate(policy: Policy, region: str, model_digest: str, messages,
             skip: tuple[str, ...] = ()) -> tuple[str, str, list[str]]:
    """Returns (decision, mode, rule_hits). Rules whose type is in `skip` are not evaluated."""
    text = message_text(messages).lower()
    fired = [r for r in policy.rules if r["type"] not in skip and _fires(r, region, model_digest, text)]
    hits = [r["id"] for r in fired]
    if any(r["mode"] == "enforce" for r in fired):
        return "block", "enforce", hits
    if fired:
        return "flag", "record", hits
    return "allow", "record", hits


def mode_changes(old: Policy, new: Policy) -> list[str]:
    """Rule ids whose mode differs between two policies (added or removed rules count)."""
    a, b = old.modes(), new.modes()
    return sorted(rid for rid in set(a) | set(b) if a.get(rid) != b.get(rid))


def rule_hits_json(hits: list[str]) -> str:
    return json.dumps(hits, separators=(",", ":"))
