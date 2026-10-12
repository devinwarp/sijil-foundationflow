"""Rule pack loading and hashing (spec §8.1, §2.4.6). Matching rules against tool calls is row 6 (M2c);
the ledger only needs the pack's identity, its hash and which rule actions changed."""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .policy import RESERVED_IDS, RESERVED_PREFIXES
from .record import sha256_hex

ON = ("tool_call", "tool_result", "egress", "integrity")
ACTIONS = ("allow", "record", "confirm", "block")
RULE_ID = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")


class Mismatch(Exception):
    """A body sealed under a rule pack hash that is no longer the one in force (spec §5.6: 409)."""


@dataclass(frozen=True)
class RulePack:
    rulepack_id: str
    version: str
    path: str
    rules: tuple[dict, ...]
    hash: str

    def actions(self) -> dict[str, str]:
        return {r["id"]: r["action"] for r in self.rules}


def load(path: str) -> RulePack:
    raw = Path(path).read_bytes()
    doc = yaml.safe_load(raw)
    if not isinstance(doc, dict) or not doc.get("rulepack_id") or not doc.get("version"):
        raise ValueError(f"{path}: rulepack_id and version are required")
    rules = doc.get("rules") or []
    if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
        raise ValueError(f"{path}: rules must be a list of mappings")
    # PyYAML reads the spec's `on:` key as YAML 1.1 boolean True; give it back its name.
    rules = [{("on" if k is True else k): v for k, v in r.items()} for r in rules]
    for r in rules:
        if not isinstance(r.get("id"), str) or not RULE_ID.fullmatch(r["id"]):
            raise ValueError(f"{path}: rule id must be kebab-case: {r!r}")
        if r["id"] in RESERVED_IDS or r["id"].startswith(RESERVED_PREFIXES):
            raise ValueError(f"{path}: rule id {r['id']!r} is reserved")
        if r.get("on") not in ON or r.get("action") not in ACTIONS:
            raise ValueError(f"{path}: rule {r['id']!r} needs on in {ON} and action in {ACTIONS}")
    ids = [r["id"] for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{path}: duplicate rule ids")
    return RulePack(rulepack_id=str(doc["rulepack_id"]), version=str(doc["version"]), path=str(path),
                    rules=tuple(rules), hash=sha256_hex(raw))


def changed(old: RulePack | None, new: RulePack) -> list[str]:
    """Rule ids added, removed or whose action changed (mirrors policy.mode_changes). None = no old pack."""
    a, b = (old.actions() if old else {}), new.actions()
    return sorted(rid for rid in set(a) | set(b) if a.get(rid) != b.get(rid))
