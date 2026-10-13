"""The rule engine (spec §8.1, §2.5, §17.3.4): load a rule pack, match it against the facts of one record.

Every rule whose `on` is the record type and whose every `match` key matches fires; `rule_hits` lists them
in pack order and the strictest action wins (block > confirm > record > allow). No ordering, no early exit.
"""

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .canon import sha256_hex
from .cmdparse import URL, Parsed, Roots, Segment, host_of, normalise, parse

ON = ("tool_call", "tool_result", "egress", "integrity")
ACTIONS = ("allow", "record", "confirm", "block")
RULE_ID = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
# The ledger's reserved ids (sijill/policy.py RESERVED_IDS, RESERVED_PREFIXES): the node seals those itself.
RESERVED_IDS = ("upstream_error", "halted", "resumed", "principal-missing", "principal-invalid",
                "principal-expired", "principal-assurance-low", "principal-task-mismatch",
                "principal-jwks-unavailable", "http-operation-unknown", "http-task-ambiguous", "approval-timeout")
RESERVED_PREFIXES = ("budget:",)
NOT_ALLOWLISTED = "tool-not-allowlisted"       # written by the guard's tools.allow/deny filter (spec §5.2)
MATCH_KEYS = {
    "tool_call": {"tool", "harness", "command_regex", "argv0", "path_glob", "path_mode", "arg_regex", "env_refs_any",
                  "context_labels_any", "context_exec_hints", "egress_host_not_pinned", "http_method", "http_path"},
    "tool_result": {"tool", "harness", "source_label", "invisible_unicode", "exec_hints_any"},
    "egress": {"tool", "egress_host_not_pinned", "egress_host_regex"},
    "integrity": {"drift_kind", "invisible_unicode"},
}
REGEX_KEYS = ("command_regex", "egress_host_regex")
LIST_KEYS = ("tool", "harness", "argv0", "path_glob", "env_refs_any", "context_labels_any", "source_label",
             "exec_hints_any", "drift_kind", "http_method", "http_path")
BOOL_KEYS = ("context_exec_hints", "egress_host_not_pinned", "invisible_unicode")
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit", "write_file", "edit_file", "create_file", "move_file",
               "create_directory", "delete_file"}
PATH_ARGS = ("path", "paths", "file_path", "filename", "file", "source", "destination", "target", "dir",
             "directory", "notebook_path")


def glob_re(pattern: str) -> re.Pattern:
    """Path glob: `*` and `?` stay inside one segment, `**/` is zero or more directories, `**` anything."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        else:
            out += {"*": "[^/]*", "?": "[^/]"}.get(pattern[i], re.escape(pattern[i]))
            i += 1
    return re.compile(out + r"\Z", re.S)


@dataclass(frozen=True)
class Rule:
    id: str
    on: str
    action: str
    match: dict
    reserved: bool = False
    description: str = ""


@dataclass(frozen=True)
class RulePack:
    rulepack_id: str
    version: str
    path: str
    hash: str                     # sha256 of the file bytes, as the ledger computes it (sijill/rulepack.py)
    rules: tuple[Rule, ...]
    approval: str = "self"        # hitl.channel: self (elicitation) or entra (named approval through the ledger)

    def rule(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)


def _re(rule_id: str, key: str, rx) -> re.Pattern:
    try:
        return re.compile(rx)
    except (re.error, TypeError) as e:
        raise ValueError(f"rule {rule_id!r}: {key} is not a regex: {e}")


def _compile(rule_id: str, on: str, match) -> dict:
    if not isinstance(match, dict) or not match:
        raise ValueError(f"rule {rule_id!r}: match must be a non-empty mapping")
    unknown = set(match) - MATCH_KEYS[on]
    if unknown:   # a typo must not turn a block rule into one that never fires
        raise ValueError(f"rule {rule_id!r}: match keys {sorted(unknown)} not allowed on {on}")
    out = {}
    for k, v in match.items():
        if k in REGEX_KEYS:
            out[k] = _re(rule_id, k, v)
        elif k in LIST_KEYS:
            if not isinstance(v, list) or not v or not all(isinstance(x, str) for x in v):
                raise ValueError(f"rule {rule_id!r}: {k} must be a non-empty list of strings")
            out[k] = [glob_re(p) for p in v] if k in ("path_glob", "http_path") else v
        elif k in BOOL_KEYS:
            if not isinstance(v, bool):
                raise ValueError(f"rule {rule_id!r}: {k} must be true or false")
            out[k] = v
        elif k == "path_mode":
            if v not in ("read", "write", "any"):
                raise ValueError(f"rule {rule_id!r}: path_mode must be read, write or any")
            out[k] = v
        elif k == "arg_regex":
            if not isinstance(v, dict) or not v:
                raise ValueError(f"rule {rule_id!r}: arg_regex must map argument keys to regexes")
            out[k] = {key: _re(rule_id, f"arg_regex.{key}", rx) for key, rx in v.items()}
    if "path_mode" in out and "path_glob" not in out:
        raise ValueError(f"rule {rule_id!r}: path_mode needs path_glob")
    return out


def load(path: str) -> RulePack:
    raw = Path(path).read_bytes()
    doc = yaml.safe_load(raw)
    if not isinstance(doc, dict) or not doc.get("rulepack_id") or not doc.get("version"):
        raise ValueError(f"{path}: rulepack_id and version are required")
    unknown = set(doc) - {"rulepack_id", "version", "description", "defaults", "rules", "hitl", "budgets", "pricing"}
    if unknown:    # dlp:, mode: and arg_max_length are row 18. hitl routes, budgets and pricing are the ledger's
        raise ValueError(f"{path}: top-level keys {sorted(unknown)} are not supported")
    approval = (doc.get("hitl") or {}).get("channel", "self") if isinstance(doc.get("hitl") or {}, dict) else None
    if approval not in ("self", "entra"):
        raise ValueError(f"{path}: hitl.channel must be self or entra")
    if (doc.get("defaults") or {"action": "allow"}) != {"action": "allow"}:
        raise ValueError(f"{path}: defaults.action must be allow (a rule fires or the call proceeds)")
    rules, seen = [], set()
    for r in doc.get("rules") or []:
        r = {("on" if k is True else k): v for k, v in r.items()} if isinstance(r, dict) else {}
        rid = r.get("id")
        if not isinstance(rid, str) or not RULE_ID.fullmatch(rid) or rid in seen:
            raise ValueError(f"{path}: rule id must be kebab-case and unique: {rid!r}")
        if rid in RESERVED_IDS or rid.startswith(RESERVED_PREFIXES):
            raise ValueError(f"{path}: rule id {rid!r} is reserved")
        if r.get("on") not in ON or r.get("action") not in ACTIONS:
            raise ValueError(f"{path}: rule {rid!r} needs on in {ON} and action in {ACTIONS}")
        seen.add(rid)
        if r.get("match") == {"reserved": True}:
            if rid != NOT_ALLOWLISTED:
                raise ValueError(f"{path}: only {NOT_ALLOWLISTED} may be reserved")
            rules.append(Rule(rid, r["on"], r["action"], {}, True, str(r.get("description", ""))))
            continue
        if rid == NOT_ALLOWLISTED:
            raise ValueError(f"{path}: {NOT_ALLOWLISTED} is written by the guard; its match must be {{reserved: true}}")
        rules.append(Rule(rid, r["on"], r["action"], _compile(rid, r["on"], r.get("match")), False,
                          str(r.get("description", ""))))
    return RulePack(str(doc["rulepack_id"]), str(doc["version"]), str(path), sha256_hex(raw), tuple(rules), approval)


@dataclass(frozen=True)
class Pins:
    """.sijil/egress.yaml `hosts:`; a glob is allowed only as a leading `*.` (spec §8.2 notes)."""
    path: str = ""
    hosts: frozenset = frozenset()
    suffixes: tuple = ()

    def pinned(self, host: str) -> bool:
        return host in self.hosts or any(host.endswith("." + s) for s in self.suffixes)


def load_pins(path: str | None) -> Pins:
    if not path:
        return Pins()                         # no pins file: every host is unpinned
    hosts = (yaml.safe_load(Path(path).read_bytes()) or {}).get("hosts") or []
    if not isinstance(hosts, list) or not all(isinstance(h, str) and h for h in hosts):
        raise ValueError(f"{path}: hosts must be a list of host names")
    bad = [h for h in hosts if "*" in h[2:] or ("*" in h and not h.startswith("*."))]
    if bad:
        raise ValueError(f"{path}: only a leading *. is allowed in a pinned host: {bad}")
    return Pins(path, frozenset(h.lower() for h in hosts if not h.startswith("*.")),
                tuple(h[2:].lower() for h in hosts if h.startswith("*.")))


@dataclass
class Facts:
    """What one record says, as the rules see it."""
    type: str
    tool: str = ""                # rule name: built-in, mcp:<server>:<tool> or http:<server>:<operation>
    harness: str = ""
    command: str | None = None
    segments: list[Segment] = field(default_factory=list)
    env_refs: list[str] = field(default_factory=list)
    args: dict = field(default_factory=dict)
    hosts: list[str] = field(default_factory=list)
    context_labels: list[str] = field(default_factory=list)
    context_exec_hints: bool = False
    source_label: str = ""
    invisible_unicode: bool = False
    exec_hints: list[str] = field(default_factory=list)
    drift_kinds: list[str] = field(default_factory=list)
    method: str = ""
    path_template: str = ""


def call_facts(tool: str, bare: str, args: dict, roots: Roots, harness: str, command_arg: str = "command",
               **context) -> tuple[Facts, Parsed | None]:
    """Facts for a tool_call. A shell-like tool carries its command in `command_arg`; any other tool's paths
    come from its path-like arguments, written when the tool is a write tool."""
    command = args.get(command_arg) if command_arg else None
    if tool == "Bash":
        command = args.get("command")
    if isinstance(command, str):
        parsed = parse(command, roots)
        hosts = sorted({h for s in parsed.segments for h in s.hosts})
        return Facts("tool_call", tool, harness, command, parsed.segments, parsed.env_refs, args, hosts,
                     **context), parsed
    raw = [v for k in PATH_ARGS for v in (args.get(k) if isinstance(args.get(k), list) else [args.get(k)])
           if isinstance(v, str) and v]
    paths = [n for p in raw for n in normalise(p, roots)]
    write = bare in WRITE_TOOLS
    hosts = sorted({h for v in args.values() if isinstance(v, str) for m in URL.findall(v) if (h := host_of(m))})
    seg = Segment(argv0="", args=[], reads=[] if write else paths, writes=paths if write else [], hosts=hosts)
    return Facts("tool_call", tool, harness, None, [seg], [], args, hosts, **context), None


def _any_glob(values, patterns) -> bool:
    return any(fnmatch.fnmatchcase(v, p) for v in values for p in patterns)


def _segment_ok(m: dict, seg: Segment) -> bool:
    if "argv0" in m and seg.argv0 not in m["argv0"]:
        return False
    if "path_glob" in m:
        mode = m.get("path_mode", "any")
        paths = seg.reads if mode == "read" else seg.writes if mode == "write" else seg.reads + seg.writes
        if not any(rx.match(p) for p in paths for rx in m["path_glob"]):
            return False
    return True


def matches(rule: Rule, f: Facts, pins: Pins) -> bool:
    m = rule.match
    if rule.reserved or rule.on != f.type:
        return False
    if "tool" in m and not _any_glob([f.tool], m["tool"]):
        return False
    if "harness" in m and f.harness not in m["harness"]:
        return False
    if "command_regex" in m:   # the whole command, and each segment on its own (bash -c 'npx x' is a segment)
        texts = [f.command or ""] + [" ".join([s.argv0, *s.args]) for s in f.segments if s.argv0]
        if f.command is None or not any(m["command_regex"].search(t) for t in texts):
            return False
    if ("argv0" in m or "path_glob" in m) and not any(_segment_ok(m, s) for s in f.segments):
        return False
    if "arg_regex" in m:
        for key, rx in m["arg_regex"].items():
            v = f.args.get(key)
            if v is None or not rx.search(v if isinstance(v, str) else json.dumps(v, sort_keys=True)):
                return False
    if "env_refs_any" in m and not _any_glob(f.env_refs, m["env_refs_any"]):
        return False
    if "context_labels_any" in m and not _any_glob(f.context_labels, m["context_labels_any"]):
        return False
    if "context_exec_hints" in m and f.context_exec_hints != m["context_exec_hints"]:
        return False
    if "egress_host_not_pinned" in m and any(not pins.pinned(h) for h in f.hosts) != m["egress_host_not_pinned"]:
        return False
    if "egress_host_regex" in m and not any(m["egress_host_regex"].search(h) for h in f.hosts):
        return False
    if "source_label" in m and not _any_glob([f.source_label], m["source_label"]):
        return False
    if "invisible_unicode" in m and f.invisible_unicode != m["invisible_unicode"]:
        return False
    if "exec_hints_any" in m and not set(f.exec_hints) & set(m["exec_hints_any"]):
        return False
    if "drift_kind" in m and not set(f.drift_kinds) & set(m["drift_kind"]):
        return False
    if "http_method" in m and f.method.upper() not in [x.upper() for x in m["http_method"]]:
        return False
    if "http_path" in m and not any(rx.match(f.path_template) for rx in m["http_path"]):
        return False
    return True


@dataclass(frozen=True)
class Verdict:
    hits: list[str]
    action: str                   # the strictest action among the fired rules; allow when none fired
    fired: tuple[Rule, ...] = ()


def evaluate(pack: RulePack, facts: Facts, pins: Pins) -> Verdict:
    fired = tuple(r for r in pack.rules if matches(r, facts, pins))
    action = max((r.action for r in fired), key=ACTIONS.index, default="allow")
    return Verdict([r.id for r in fired], action, fired)


def outcome(action: str, confirmation: str | None = None) -> tuple[str, str]:
    """(decision, mode) for the strictest action (spec §2.5). confirm needs the confirmation answer."""
    if action == "allow":
        return "allow", "record"
    if action == "record" or (action == "confirm" and confirmation == "granted"):
        return "flag", "record"
    return "block", "enforce"
