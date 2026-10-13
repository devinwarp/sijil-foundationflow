"""Tool definitions pinned in the lockfile, and their drift (spec §7.1, §7.3, §7.4, §2.4.4-2.4.5).

This build pins `mcp:<server>/<tool>` entries only, in a version 1 lockfile (no sha256_norm or config_digest);
`sijil-lock` (row 10) adds the files and upgrades it. A tool's hash covers the whole definition the harness
receives (name, description, inputSchema, annotations, title, outputSchema, _meta, anything else), so drift in
any relayed field is drift.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import rules, unicode
from .canon import canonical_json, sha256_hex

TOOL = "sijil-guard/0.1.0"
MAX_CHANGED = 200


def tool_hash(t: dict) -> str:
    return sha256_hex(canonical_json(t))


def strings(obj) -> list[str]:
    """Every string in a JSON value, keys included, in order (iterative: a deep value cannot overflow the stack)."""
    out, todo = [], [obj]
    while todo:
        v = todo.pop()
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            todo += [x for kv in reversed(list(v.items())) for x in reversed(kv)]
        elif isinstance(v, list):
            todo += reversed(v)
    return out


def scan(tools: list[dict]) -> dict:
    """The invisible-Unicode scan over every string of these tool definitions."""
    return unicode.scan("\n".join(s for t in tools for s in strings(t)))


def key(server: str, name: str) -> str:
    return f"mcp:{server}/{name}"


def _hashes(server: str, tools: list[dict]) -> dict[str, str]:
    """key -> hash. Two tools with one name (the harness would get both) pin as one entry over all of them."""
    by: dict[str, list[dict]] = {}
    for t in tools:
        by.setdefault(key(server, t["name"]), []).append(t)
    return {k: tool_hash(v[0] if len(v) == 1 else v) for k, v in by.items()}


def render(doc: dict) -> bytes:
    """Sorted keys, two-space indent, trailing newline: two runs give the same bytes (spec §7.4)."""
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def validate(doc) -> None:
    """ValueError unless doc is a lockfile this guard can compare against: an object whose entries map names to
    objects with a string sha256."""
    entries = doc.get("entries", {}) if isinstance(doc, dict) else None
    if not isinstance(entries, dict) or not all(isinstance(v, dict) and isinstance(v.get("sha256"), str)
                                                for v in entries.values()):
        raise ValueError("entries must map names to objects with a sha256")


def read(path: str) -> dict | None:
    try:
        return json.loads(Path(path).read_bytes())
    except FileNotFoundError:
        return None


def with_server(doc: dict | None, server: str, tools: list[dict]) -> dict:
    """The lockfile with this server's entries replaced by `tools`; other servers' entries kept."""
    doc = doc or {"version": 1, "tool": TOOL, "roots": {},
                  "created": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")}
    entries = {k: v for k, v in doc.get("entries", {}).items() if not k.startswith(f"mcp:{server}/")}
    entries.update({k: {"sha256": h} for k, h in _hashes(server, tools).items()})
    return {**doc, "entries": entries}


def pin(path: str, server: str, tools: list[dict]) -> tuple[bytes, dict]:
    """Write the lockfile with this server's tools; refuses a description carrying flagged code points."""
    flagged = sorted(t["name"] for t in tools if scan([t])["found"])
    if flagged:
        raise ValueError(f"tool definitions carry invisible or suspicious Unicode, not pinned: {flagged}")
    data = render(with_server(read(path), server, tools))
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=Path(path).parent, prefix=Path(path).name + ".", suffix=".tmp")    # as task.save
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return data, json.loads(data)


def changes(doc: dict | None, server: str, tools: list[dict]) -> list[dict]:
    """Drift of this server's tools against the lockfile, sorted by path (spec §2.4.5). Without a lockfile
    only invisible Unicode in a description counts."""
    pinned = {k: v["sha256"] for k, v in (doc or {}).get("entries", {}).items() if k.startswith(f"mcp:{server}/")}
    now, out = _hashes(server, tools), []
    for k, h in now.items():
        found = scan([t for t in tools if key(server, t["name"]) == k])
        if found["found"]:
            out.append({"path": k, "kind": "invisible_unicode", "before": pinned.get(k, ""), "after": h,
                        "codepoints": found["codepoints"], "count": found["count"]})
        elif doc is not None and k not in pinned:
            out.append({"path": k, "kind": "added", "before": "", "after": h})
        elif doc is not None and pinned[k] != h:
            out.append({"path": k, "kind": "tool_description", "before": pinned[k], "after": h})
    out += [{"path": k, "kind": "removed", "before": v, "after": ""} for k, v in pinned.items() if k not in now]
    return sorted(out, key=lambda c: c["path"])


def removed(pack: rules.RulePack, pins: rules.Pins, changed: list[dict], gone: bool = False) -> dict[str, list[str]]:
    """tool name -> the integrity rules (block or confirm, which has no channel here) that take it away. A tool
    that is no longer listed is in it only with `gone`: the guard refuses a call to it, though it cannot be listed."""
    out = {}
    for c in changed:
        v = rules.evaluate(pack, rules.Facts("integrity", drift_kinds=[c["kind"]],
                                             invisible_unicode=c["kind"] == "invisible_unicode"), pins)
        if v.action in ("block", "confirm") and (gone or c["kind"] != "removed"):
            out[c["path"].split("/", 1)[1]] = v.hits
    return out
