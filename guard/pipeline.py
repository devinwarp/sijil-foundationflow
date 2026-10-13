"""One tool call through Sijil (spec §5.3, §5.4, §5.5, §2.4.1-2.4.3), shared by the MCP guard and the HTTP
adapter: find the parent inference, read the context window, evaluate the rule pack, seal the tool_call;
after the tool ran, scan its result and seal the tool_result. The adapters only translate their protocol.
"""

import re
from dataclasses import dataclass, field
from typing import Callable

from . import rules, unicode
from .canon import args_hash, sha256_hex
from .cmdparse import Roots
from .ledger import Ledger, Refused

EXEC_HINTS = ("npx", "npm exec", "pnpm dlx", "bunx", "curl", "wget", "pip install", "sh -c", "bash -c",
              "powershell", "base64 -d")
_HINT_RE = {h: re.compile(r"(?<![\w-])" + re.escape(h).replace(r"\ ", r"\s+") + r"(?![\w-])") for h in EXEC_HINTS}
NO_PARENT = 2 ** 62               # before_seq for an orphan: every result in the task is context


def exec_hints(text: str) -> list[str]:
    """Sorted distinct tokens of the fixed §2.4.2 list found in the text: a lexical scan, not a classifier."""
    return sorted(h for h, rx in _HINT_RE.items() if rx.search(text))


class Refusal(Exception):
    """The call does not proceed. `seq` is the sealed record that says why, or None when nothing could be
    sealed (no parent under require_parent, an ambiguous task, an unreachable ledger)."""

    def __init__(self, message: str, seq: int | None = None, hits: list | None = None):
        super().__init__(message)
        self.seq, self.hits = seq, hits or []


@dataclass
class Call:
    """One tool call as an adapter saw it."""
    rule_tool: str                # mcp:<server>:<tool> or http:<server>:<operation>: what tool: globs match
    tool: str                     # ext.tool
    server: str
    args: dict
    harness: str
    session_id: str
    observed_by: str              # mcp_guard | http_adapter
    parent_names: list[str] = field(default_factory=list)   # tool_uses names that may have requested it
    tool_use_id: str = ""
    command_arg: str = "command"
    summary: dict | None = None   # set by the HTTP adapter (method, host, path_template, arg_keys)
    method: str = ""
    path_template: str = ""
    task_seq: int | str | None = None      # None: the session's only open task


@dataclass
class Sealed:
    seq: int
    decision: str
    hits: list[str]
    parent_seq: str
    qualified: str


@dataclass
class Result:
    seq: int
    text: str                     # what the agent receives: stripped or truncated per config
    blocked: bool
    hits: list[str]


class Pipeline:
    def __init__(self, ledger: Ledger, session: str, cfg, roots: Roots | None = None,
                 pins: rules.Pins | None = None):
        self.ledger, self.session, self.cfg = ledger, session, cfg
        self.roots = roots or Roots(cwd=cfg.repo, repo=cfg.repo, home=Roots.here().home)
        self.pins = pins if pins is not None else rules.load_pins(cfg.egress_pins)
        self.pack = rules.load(cfg.rulepack)

    def seal(self, task_seq, build: Callable[[], dict]) -> dict:
        """Seal; on 409 rulepack mismatch reload the pack from disk and rebuild once (spec §5.6)."""
        try:
            return self.ledger.seal(self.session, build(), task_seq)
        except Refused as e:
            if e.status != 409 or e.detail != "rulepack mismatch":
                raise
            self.pack = rules.load(self.cfg.rulepack)
            return self.ledger.seal(self.session, build(), task_seq)

    def _parent(self, call: Call, h: str) -> tuple[str, str, str, str]:
        """(parent_seq, correlation, tool_use_id, matched name). A tool_use_id hit whose arguments differ
        from what is executed is no parent: B2 would fail it, so it is sealed as none (spec §5.4)."""
        if call.tool_use_id:
            hit = self.ledger.parent(self.session, call.task_seq, tool_use_id=call.tool_use_id)
            if hit and hit["args_hash"] == h:
                return str(hit["seq"]), "tool_use_id", call.tool_use_id, hit["name"]
        for name in call.parent_names:
            hit = self.ledger.parent(self.session, call.task_seq, name=name, args_hash=h)
            if hit:
                return str(hit["seq"]), "args_hash", hit["tool_use_id"], name
        return "", "none", "", ""

    def check(self, call: Call, confirm: Callable[[rules.Rule], str] | None = None,
              forced: list[str] | None = None) -> Sealed:
        """Seal the tool_call. Raises Refusal when the call must not run (blocked, denied, or unsealable);
        returns the sealed call otherwise. `forced` hits (a filter's) block without evaluating the pack."""
        h = args_hash(call.args)
        parent, correlation, tool_use_id, name = self._parent(call, h)
        if not parent and self.cfg.require_parent:
            raise Refusal("Sijil: no parent inference requested this call (correlation.require_parent)")
        ctx = self.ledger.context(self.session, call.task_seq, int(parent) if parent else NO_PARENT,
                                  self.cfg.context_window)
        facts, parsed = rules.call_facts(call.rule_tool, call.tool, call.args, self.roots, call.harness,
                                         call.command_arg, context_labels=ctx["labels"],
                                         context_exec_hints=bool(ctx.get("exec_hints")), method=call.method,
                                         path_template=call.path_template)
        summary = call.summary or (parsed.summary() if parsed else {"arg_keys": sorted(call.args)})
        answer, body = {}, {}

        def build() -> dict:
            if forced:
                hits, action = forced, "block"
            else:
                v = rules.evaluate(self.pack, facts, self.pins)
                hits, action = v.hits, v.action
                if action == "confirm" and "c" not in answer:
                    rule = next(r for r in v.fired if r.action == "confirm")
                    answer["c"] = confirm(rule) if confirm else "unavailable"
            decision, mode = rules.outcome(action, answer.get("c"))
            ext = {"harness": call.harness, "session_id": call.session_id, "tool": call.tool,
                   "server": call.server, "qualified": name or call.rule_tool, "correlation": correlation,
                   "observed_by": call.observed_by, "summary": summary, "context_labels": ctx["labels"],
                   "context_seqs": ctx["seqs"], **({"tool_use_id": tool_use_id} if tool_use_id else {}),
                   **({"confirmation": answer["c"]} if action == "confirm" else {})}
            body.update({"type": "tool_call", "parent_seq": parent, "mode": mode, "decision": decision,
                         "rule_hits": hits, "input_hash": h, "rulepack_hash": self.pack.hash, "ext": ext})
            return body
        r = self.seal(call.task_seq, build)
        sealed = Sealed(r["seq"], r["decision"], body["rule_hits"], parent, body["ext"]["qualified"])
        if r["decision"] == "block":
            why = ", ".join(sealed.hits) or "halted"
            raise Refusal(f"Blocked by Sijil rule {why}; seq={r['seq']}", r["seq"], sealed.hits)
        return sealed

    def result(self, call: Call, sealed: Sealed, text: str, status: str, content_types: list[str],
               source_label: str, raw: bytes | None = None, http_status: int | None = None,
               truncate: bool = True) -> Result:
        """Seal the tool_result. output_hash and bytes commit to what arrived, before any stripping (§2.4.2)."""
        data = raw if raw is not None else text.encode("utf-8", "surrogatepass")
        scan = unicode.scan(text)
        mode_u = self.cfg.invisible_unicode if scan["found"] else "none"
        out = unicode.strip(text) if mode_u == "strip" else text
        truncated = truncate and len(out.encode("utf-8", "surrogatepass")) > self.cfg.max_result_bytes
        if truncated:
            out = out.encode("utf-8", "surrogatepass")[:self.cfg.max_result_bytes].decode("utf-8", "ignore")
        hints = exec_hints(text)
        facts = rules.Facts("tool_result", tool=call.rule_tool, harness=call.harness, source_label=source_label,
                            invisible_unicode=scan["found"], exec_hints=hints)
        iu = {"found": scan["found"], "count": scan["count"],
              "action": {"strip": "stripped", "block": "blocked"}.get(mode_u, "none"),
              **({"codepoints": scan["codepoints"]} if scan["found"] else {})}
        ext = {"tool": call.tool, "server": call.server, "status": status, "bytes": len(data),
               "content_types": sorted(set(content_types)), "invisible_unicode": iu,
               **({"exec_hints": hints} if hints else {}), **({"truncated": True} if truncated else {}),
               **({"http_status": http_status} if http_status is not None else {})}
        body = {}

        def build() -> dict:
            v = rules.evaluate(self.pack, facts, self.pins)
            # confirm has no channel on a result: it blocks, as an unanswered confirm does (spec §2.5)
            action = "block" if mode_u == "block" else v.action
            decision, mode = rules.outcome(action)
            body.update({"type": "tool_result", "parent_seq": str(sealed.seq), "source_label": source_label,
                         "mode": mode, "decision": decision, "rule_hits": v.hits, "input_hash": "",
                         "output_hash": sha256_hex(data), "rulepack_hash": self.pack.hash, "ext": ext})
            return body
        r = self.seal(call.task_seq, build)
        return Result(r["seq"], out, r["decision"] == "block", body["rule_hits"])

    def egress(self, call: Call, sealed: Sealed, host: str, port: int, proto: str, method: str = "",
               pins: rules.Pins | None = None) -> int:
        """Seal the connection the adapter itself makes upstream (spec §17.3.3); Refusal when it is blocked."""
        pins = pins or self.pins
        facts = rules.Facts("egress", tool=call.rule_tool, hosts=[host])
        body = {}

        def build() -> dict:
            v = rules.evaluate(self.pack, facts, pins)
            decision, mode = rules.outcome(v.action)
            ext = {"host": host, "port": port, "proto": proto, "observed_by": call.observed_by,
                   "allowed_by": "none" if decision == "block" else "rulepack",
                   **({"method": method} if method else {}),
                   **({"pin_source": pins.path} if pins.pinned(host) and pins.path else {})}
            body.update({"type": "egress", "parent_seq": str(sealed.seq), "mode": mode, "decision": decision,
                         "rule_hits": v.hits, "rulepack_hash": self.pack.hash, "ext": ext})
            return body
        r = self.seal(call.task_seq, build)
        if r["decision"] == "block":
            raise Refusal(f"Blocked by Sijil rule {', '.join(body['rule_hits']) or 'halted'}; seq={r['seq']}",
                          r["seq"], body["rule_hits"])
        return r["seq"]
