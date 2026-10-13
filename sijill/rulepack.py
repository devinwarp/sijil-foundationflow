"""Rule pack loading and hashing (spec §8.1, §2.4.6). Matching rules against tool calls is row 6 (M2c);
the ledger needs the pack's identity, its hash, which rule actions changed, and the blocks it acts on itself:
`hitl:` routes for named approval (§17.5.1), `budgets:` and `pricing:` (§17.6.1)."""

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .policy import RESERVED_IDS, RESERVED_PREFIXES
from .record import sha256_hex

ON = ("tool_call", "tool_result", "egress", "integrity")
ACTIONS = ("allow", "record", "confirm", "block")
RULE_ID = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
BLOCK_ID = re.compile(r"[a-z0-9-]{1,32}")                 # hitl.routes[].id, budgets[].id
GUID = re.compile(r"[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}", re.I)
MAX_TIMEOUT = 7 * 86400                                   # seconds; deadlines are ts + this
MAX_COUNT = 2 ** 53                                       # budget limits and prices: exact in a JSON number
LEVELS = ("low", "substantial", "high")
HITL_KEYS = {"timeout_seconds", "on_timeout", "mode", "channel", "entra", "separation_of_duties",
             "routes", "notify"}
BUDGET_MATCH = ("harness", "agent_id", "logical_agent_id", "principal_issuer")
METRICS = ("tool_calls", "tool_calls_by", "egress_hosts", "model_spend_micro")
PRICE_INTS = ("input_per_mtok_micro", "output_per_mtok_micro", "missing_usage_cost_micro")


class Mismatch(Exception):
    """A body sealed under a rule pack hash that is no longer the one in force (spec §5.6: 409)."""


@dataclass(frozen=True)
class Route:
    id: str
    rules: tuple[str, ...]        # globs over the confirm rule ids (and budget: hits) that fired
    role: str                     # Entra app role in the approver token's `roles`, or ""
    oids: tuple[str, ...]         # or approver object ids
    min_assurance: str
    timeout_seconds: int


@dataclass(frozen=True)
class Hitl:
    channel: str                  # self | entra
    timeout_seconds: int
    separation_of_duties: bool
    issuer_id: str                # entra: policy.yaml principals.issuers[].id that signs approver tokens
    audience: str                 # entra: the approval app's audience
    routes: tuple[Route, ...]
    teams_webhook_env: str        # delivery only, never evidence


@dataclass(frozen=True)
class Budget:
    id: str
    match: dict                   # task fact -> allowed values; {} matches every task
    limits: dict                  # tool_calls, tool_calls_by {glob: int}, egress_hosts, model_spend_micro
    currency: str
    on_exceed: str                # block | confirm


@dataclass(frozen=True)
class RulePack:
    rulepack_id: str
    version: str
    path: str
    rules: tuple[dict, ...]
    hash: str
    hitl: Hitl | None = None
    budgets: tuple[Budget, ...] = ()
    pricing: tuple[dict, ...] = ()

    def actions(self) -> dict[str, str]:
        return {r["id"]: r["action"] for r in self.rules}

    def confirm_hits(self, hits: list[str]) -> list[str]:
        """The hits a named approver answers: confirm rules of this pack, and excesses of its confirm budgets."""
        actions, budgets = self.actions(), {b.id for b in self.budgets if b.on_exceed == "confirm"}
        return [h for h in hits if actions.get(h) == "confirm" or (h.startswith("budget:") and h.split(":")[1] in budgets)]

    def route(self, hits: list[str]) -> Route | None:
        """The first hitl route with a glob matching any of the hits (spec §17.5.1)."""
        routes = self.hitl.routes if self.hitl else ()
        return next((r for r in routes if any(fnmatch.fnmatchcase(h, g) for h in hits for g in r.rules)), None)

    def price(self, model_digest: str) -> dict | None:
        """The first pricing entry whose model glob matches (spec §17.6.1)."""
        return next((p for p in self.pricing if fnmatch.fnmatchcase(model_digest, p["model"])), None)


def _count(v, where: str, hi: int = MAX_COUNT) -> int:
    if type(v) is not int or not 0 <= v <= hi:
        raise ValueError(f"{where} must be a non-negative integer of at most {hi}")
    return v


def _block(v, where: str) -> dict:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ValueError(f"{where} must be a mapping")
    return v


def _strings(v, where: str) -> tuple[str, ...]:
    if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
        raise ValueError(f"{where} must be a non-empty list of strings")
    return tuple(v)


def _hitl(d, path: str) -> Hitl | None:
    """hitl: (spec §17.5.1). Named approval needs channel entra; mode monitor and allow-on-timeout are row 18's."""
    if d is None:
        return None
    if isinstance(d, dict) and "approvers" in d:
        raise ValueError(f"{path}: hitl.approvers is the v1 form; name approvers per route in hitl.routes[].approvers")
    if not isinstance(d, dict) or set(d) - HITL_KEYS:
        raise ValueError(f"{path}: hitl keys must be among {sorted(HITL_KEYS)}")
    channel, timeout = d.get("channel", "self"), _count(d.get("timeout_seconds", 300), f"{path}: hitl.timeout_seconds",
                                                        MAX_TIMEOUT)
    if timeout < 1:
        raise ValueError(f"{path}: hitl.timeout_seconds must be at least 1")
    if channel not in ("self", "entra") or d.get("mode", "enforce") != "enforce" or d.get("on_timeout", "deny") != "deny":
        raise ValueError(f"{path}: hitl needs channel self|entra, mode enforce and on_timeout deny")
    entra = _block(d.get("entra"), f"{path}: hitl.entra")
    if channel == "entra" and not (isinstance(entra.get("issuer_id"), str) and BLOCK_ID.fullmatch(entra["issuer_id"])
                                   and isinstance(entra.get("audience"), str) and entra["audience"]):
        raise ValueError(f"{path}: hitl channel entra needs entra.issuer_id and entra.audience")
    if type(d.get("separation_of_duties", True)) is not bool:
        raise ValueError(f"{path}: hitl.separation_of_duties must be true or false")
    routes = []
    for r in d.get("routes") or []:
        a = r.get("approvers") if isinstance(r, dict) else None
        if not isinstance(r, dict) or not isinstance(r.get("id"), str) or not BLOCK_ID.fullmatch(r["id"]) \
                or not isinstance(a, dict) or len(a) != 1 or set(a) - {"role", "oids"}:
            raise ValueError(f"{path}: hitl route needs an id and approvers {{role}} or {{oids}}: {r!r}")
        oids = _strings(a["oids"], f"{path}: hitl route {r['id']} oids") if "oids" in a else ()
        oids = tuple(o.lower() for o in oids)
        if not all(GUID.fullmatch(o) for o in oids) or ("role" in a and not (isinstance(a["role"], str) and a["role"])):
            raise ValueError(f"{path}: hitl route {r['id']}: role is a name, oids are object id GUIDs")
        routes.append(Route(r["id"], _strings(r.get("rules"), f"{path}: hitl route {r['id']} rules"), a.get("role", ""),
                            oids, r.get("min_assurance", "substantial"),
                            _count(r.get("timeout_seconds", timeout), f"{path}: hitl route {r['id']} timeout_seconds",
                                   MAX_TIMEOUT)))
        if routes[-1].min_assurance not in LEVELS or routes[-1].timeout_seconds < 1:
            raise ValueError(f"{path}: hitl route {r['id']}: min_assurance in {LEVELS}, timeout_seconds at least 1")
    if routes and channel != "entra" or len({r.id for r in routes}) != len(routes):
        raise ValueError(f"{path}: hitl routes need channel entra and unique ids")
    notify = _block(d.get("notify"), f"{path}: hitl.notify")
    if set(notify) - {"teams_webhook_env"} or not isinstance(notify.get("teams_webhook_env", ""), str):
        raise ValueError(f"{path}: hitl.notify takes teams_webhook_env only")
    return Hitl(channel, timeout, d.get("separation_of_duties", True), entra.get("issuer_id", ""),
                entra.get("audience", ""), tuple(routes), notify.get("teams_webhook_env", ""))


def _budgets(items, hitl: Hitl | None, path: str) -> tuple[Budget, ...]:
    """budgets: (spec §17.6.1). Limits are integers; on_exceed confirm needs a hitl route for its hits."""
    out = []
    for b in items or []:
        limits = b.get("limits") if isinstance(b, dict) else None
        if not isinstance(b, dict) or not isinstance(b.get("id"), str) or not BLOCK_ID.fullmatch(b["id"]) \
                or not isinstance(limits, dict) or not limits or set(limits) - set(METRICS):
            raise ValueError(f"{path}: budget needs an id and limits among {METRICS}: {b!r}")
        match = b.get("match") or {}
        if not isinstance(match, dict) or set(match) - set(BUDGET_MATCH):
            raise ValueError(f"{path}: budget {b['id']} match keys must be among {BUDGET_MATCH}")
        match = {k: _strings(v, f"{path}: budget {b['id']} match.{k}") for k, v in match.items()}
        by = limits.get("tool_calls_by", {})
        if not isinstance(by, dict) or not all(isinstance(g, str) and g for g in by):
            raise ValueError(f"{path}: budget {b['id']} tool_calls_by maps qualified-name globs to integers")
        lim = {k: _count(v, f"{path}: budget {b['id']} {k}") for k, v in limits.items() if k != "tool_calls_by"}
        if by:
            lim["tool_calls_by"] = {g: _count(n, f"{path}: budget {b['id']} tool_calls_by") for g, n in by.items()}
        if not lim:
            raise ValueError(f"{path}: budget {b['id']} has no limits")
        on_exceed = b.get("on_exceed", "block")
        if on_exceed not in ("block", "confirm") or not isinstance(b.get("currency", ""), str):
            raise ValueError(f"{path}: budget {b['id']} on_exceed must be block or confirm")
        pack = RulePack("", "", "", (), "", hitl)
        # the ledger's hit names (spec §17.6.2): tool_calls_by hits carry the glob that was exceeded
        hits = [f"budget:{b['id']}:{m}" for m in lim if m != "tool_calls_by"] + \
            [f"budget:{b['id']}:tool_calls_by:{g}" for g in lim.get("tool_calls_by", {})]
        if on_exceed == "confirm" and any(pack.route([h]) is None for h in hits):
            raise ValueError(f"{path}: budget {b['id']} on_exceed confirm needs a hitl route matching every hit "
                             f"({hits[0]} ...)")
        out.append(Budget(b["id"], match, lim, b.get("currency", ""), on_exceed))
    if len({b.id for b in out}) != len(out):
        raise ValueError(f"{path}: duplicate budget ids")
    return tuple(out)


def _pricing(items, path: str) -> tuple[dict, ...]:
    out = []
    for p in items or []:
        if not isinstance(p, dict) or not isinstance(p.get("id"), str) or not p["id"] \
                or not isinstance(p.get("model"), str) or not p["model"] \
                or set(p) - {"currency"} != {"id", "model", *PRICE_INTS} or not isinstance(p.get("currency", ""), str):
            raise ValueError(f"{path}: pricing entry needs id, a non-empty model, {PRICE_INTS} and optionally "
                             f"currency: {p!r}")
        # ponytail: textual shadow test (the earlier glob matches the later glob's text); misses partial overlaps
        if any(fnmatch.fnmatchcase(p["model"], q["model"]) for q in out):
            raise ValueError(f"{path}: pricing {p['id']} is shadowed by an earlier model glob (first match wins)")
        out.append({**p, **{k: _count(p[k], f"{path}: pricing {p['id']} {k}") for k in PRICE_INTS}})
    if len({p["id"] for p in out}) != len(out):
        raise ValueError(f"{path}: duplicate pricing ids")
    return tuple(out)


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
    hitl = _hitl(doc.get("hitl"), path)
    budgets, pricing = _budgets(doc.get("budgets"), hitl, path), _pricing(doc.get("pricing"), path)
    cur = {b.currency for b in budgets if b.currency} | {p["currency"] for p in pricing if p.get("currency")}
    if len(cur) > 1:    # a spend limit in one currency priced in another would compare unlike units
        raise ValueError(f"{path}: budgets and pricing disagree on currency: {sorted(cur)}")
    return RulePack(rulepack_id=str(doc["rulepack_id"]), version=str(doc["version"]), path=str(path),
                    rules=tuple(rules), hash=sha256_hex(raw), hitl=hitl, budgets=budgets, pricing=pricing)


def check_policy(pack: RulePack | None, pol) -> None:
    """Named approval validates approver tokens against a policy.yaml principals issuer (spec §17.5.1)."""
    h = pack.hitl if pack else None
    if h and h.channel == "entra" and not any(
            i["id"] == h.issuer_id for i in (pol.principals.issuers if pol.principals else ())):
        raise ValueError(f"hitl.entra.issuer_id {h.issuer_id!r} is not in policy.yaml principals.issuers")


def changed(old: RulePack | None, new: RulePack) -> list[str]:
    """Rule ids added, removed or whose action changed (mirrors policy.mode_changes). None = no old pack."""
    a, b = (old.actions() if old else {}), new.actions()
    return sorted(rid for rid in set(a) | set(b) if a.get(rid) != b.get(rid))
