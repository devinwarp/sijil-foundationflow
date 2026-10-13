"""The MCP guard (spec §5.1-5.7): one wrapped server per process; the harness sees it as that server.

initialize joins a task or starts one (§5.9); tools/list is filtered by tools.allow/deny; every tools/call goes
through the pipeline before and after the wrapped server runs it. resources/* and prompts/* are not proxied:
they would be a content channel the ledger never sees.
"""

import asyncio
import base64
import binascii
import json
import os
import re
import sys
import threading
import time
import uuid
from pathlib import Path

import uvicorn

from . import identity, integrity, mcp, rules, task, unicode
from .canon import sha256_hex
from .config import Config, Server, mcp_listen
from .ledger import Ledger, Refused, Unreachable
from .pipeline import Call, Pipeline, Refusal
from .rules import NOT_ALLOWLISTED

MAX_PAGES = 64      # tools/list pages read from the wrapped server before it is refused
MAX_TOOLS = 1024    # tools, and bytes of their definitions as JSON, taken from the wrapped server in one listing
MAX_TOOLS_BYTES = 4 * 2 ** 20
ELICIT_SCHEMA = {"type": "object", "properties": {"allow": {"type": "boolean"}}, "required": ["allow"]}


BASE64 = re.compile(r"[A-Za-z0-9+/=\s]*")
# content item fields that reach the harness, per type: strings are sealed, stripped and truncated; `binary`
# is base64 (it cannot carry invisible characters) and bounded by the result budget; nothing else is relayed
ITEMS = {"text": (("text",), ()), "image": (("mimeType",), ("data",)), "audio": (("mimeType",), ("data",)),
         "resource_link": (("uri", "name", "description", "mimeType"), ())}
RESOURCE = (("uri", "mimeType", "text"), ("blob",))
REQUIRED = {"text": "text", "image": "data", "audio": "data"}
MAX_ITEMS = 256      # content items relayed per result; the rest collapse into one note
CODES = {-32700, -32600, -32601, -32602, -32603}


def _code(code) -> int:
    """A wrapped server's error code is relayed only when it is a JSON-RPC standard or server-error code."""
    ok = type(code) is int and (code in CODES or -32099 <= code <= -32000)
    return code if ok else mcp.INTERNAL


def _decode(data: str) -> bytes | None:
    """The bytes of a base64 payload, or None when it is not base64. Its size is bounded by mcp.MAX_LINE."""
    if not BASE64.fullmatch(data):
        return None
    try:
        return base64.b64decode("".join(data.split()), validate=True)
    except (binascii.Error, ValueError):
        return None


def _wire(value) -> int:
    """Bytes `value` takes in the JSON the harness gets (json.dumps, ensure_ascii=False, as mcp.py writes it)."""
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8", "surrogatepass"))


def _fit(t: str, room: int) -> str:
    """The longest prefix of `t` whose JSON string, quotes included, takes at most `room` bytes."""
    if _wire(t) <= room:
        return t
    lo, hi = 0, min(len(t), max(room, 0))      # every character takes at least one byte
    while lo < hi:
        mid = (lo + hi + 1) // 2
        lo, hi = (mid, hi) if _wire(t[:mid]) <= room else (lo, mid - 1)
    return t[:lo]


def _note(why: str) -> dict:
    """The text item that replaces a content item the guard does not relay."""
    return {"type": "text", "text": f"sijil-guard: {why}"}


def _ledger_error(e: Exception) -> "mcp.RpcError":
    if isinstance(e, Unreachable):
        return mcp.RpcError(mcp.SIJIL, "Sijil ledger unreachable")
    return mcp.RpcError(mcp.SIJIL, f"Sijil ledger refused the record: {getattr(e, 'detail', e)}")


class Guard:
    def __init__(self, cfg: Config, server: Server, ledger: Ledger, open_session=None):
        self.cfg, self.server, self.ledger = cfg, server, ledger
        self.open_session = open_session or (lambda: identity.open_session(ledger, cfg))
        self.sessions: set = set()
        self.upstream = None
        self.init: dict = {}
        self.drift_lock, self.state_lock = threading.Lock(), threading.Lock()
        self.lock_state = (None, None, None)          # (doc, bytes, stamp), swapped as one
        self.lock()
        self._base = None
        self.removed: dict[str, list[str]] = {}      # tool -> the integrity rules that took it away
        self.changed: list[dict] = []                # drift found by the last applied check
        self.seen: list[dict] = []                   # the tools that check read
        self.snap = (None, None)                     # the lockfile (doc, bytes) the last applied check used
        self.unchecked, self.checked_at = True, 0.0  # no applied check yet, or the last one failed
        self.gen = self.applied = self.floor = 0     # a check clears `unchecked` only if it began after `floor`
        self.sealed_drift: set[tuple] = set()

    async def start(self) -> None:
        s = self.server
        if s.transport == "stdio":
            if os.path.realpath(s.command) != s.real:      # retargeted since the config was checked
                raise ValueError(f"server {s.name}: {s.command} no longer resolves to {s.real}")
            self.upstream = mcp.StdioUpstream(s.command, list(s.args), s.env, self.upstream_note)
        else:
            self.upstream = mcp.HttpUpstream(s.url, s.headers, self.upstream_note)
        await self.upstream.start()
        self.init = await self.upstream.request("initialize", {
            "protocolVersion": mcp.PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "sijil-guard", "version": "0.1.0"}})
        await self.upstream.notify("notifications/initialized")

    @property
    def base(self) -> Pipeline:
        """The rule pack and pins, for a check made before any session."""
        if self._base is None:
            self._base = Pipeline(self.ledger, "", self.cfg)
        return self._base

    @property
    def lock_doc(self):
        return self.lock_state[0]

    @property
    def lock_bytes(self):
        return self.lock_state[1]

    def lock(self) -> tuple:
        """The lockfile as (doc, bytes), re-read when its mtime or size changed (`tools pin` ran, or someone
        edited it) and swapped in as one. A lockfile that was there and is gone, does not parse, or has a
        malformed entry is an error: drift cannot be measured."""
        path = self.cfg.lockfile
        if not path:
            return (None, None)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            if self.lock_state[2] is not None:
                raise mcp.RpcError(mcp.SIJIL, f"Sijil: lockfile {path} is gone; tools cannot be checked")
            return self.lock_state[:2]
        stamp = (st.st_mtime_ns, st.st_size)
        if stamp != self.lock_state[2]:
            try:
                data = Path(path).read_bytes()
                doc = json.loads(data)
                integrity.validate(doc)
            except (OSError, ValueError) as e:
                raise mcp.RpcError(mcp.SIJIL, f"Sijil: lockfile {path} is unreadable or malformed: {e}")
            with self.state_lock:
                self.lock_state = (doc, data, stamp)
        return self.lock_state[:2]

    async def tools(self) -> list[dict]:
        """The tools the harness would get (allow/deny applied), all pages: the set that is pinned, checked and
        relayed. Bounded by pages, tools and bytes; a repeated cursor is refused."""
        out, cursor, seen, size = [], None, set(), 0
        for _ in range(MAX_PAGES):
            try:
                result = await self.upstream.request("tools/list", {"cursor": cursor} if cursor else None)
            except mcp.RpcError as e:      # its message and data are not relayed
                raise mcp.RpcError(_code(e.code), "wrapped server failed tools/list")
            raw = result.get("tools")
            for t in raw if isinstance(raw, list) else []:
                if isinstance(t, dict) and isinstance(t.get("name"), str):
                    size += _wire(t)
                    if len(out) >= MAX_TOOLS or size > MAX_TOOLS_BYTES:
                        raise mcp.RpcError(mcp.INTERNAL, "wrapped server lists more tools than sijil-guard relays")
                    if self.server.allowed(t["name"]):
                        out.append(t)
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str) or not cursor:
                return out
            if cursor in seen:
                raise mcp.RpcError(mcp.INTERNAL, "wrapped server repeated a tools/list cursor")
            seen.add(cursor)
        raise mcp.RpcError(mcp.INTERNAL, f"wrapped server listed more than {MAX_PAGES} pages of tools")

    async def check_tools(self, session: "GuardSession | None" = None) -> list[dict]:
        """The wrapped server's tools, their drift against the lockfile, and the removed set. With a live session
        the drift is also sealed, once per new state (spec §5.3, §7.3); without one it is left pending and the
        next session's check seals it. A check that fails leaves the state unchecked, and calls are refused until
        one succeeds. Results are applied in the order the checks began: an older never overwrites a newer."""
        self.gen += 1
        gen = self.gen
        try:
            snap = self.lock()
            tools = await self.tools()
            changed = integrity.changes(snap[0], self.server.name, tools)
            p = session.pipeline if session else self.base
            removed = integrity.removed(p.pack, p.pins, changed, gone=True)
            if session and changed and snap[0] is not None:
                await asyncio.to_thread(self.seal_drift, session, changed, tools, snap)
        except Exception:
            with self.state_lock:
                if gen > self.applied:
                    self.applied, self.unchecked = gen, True
            raise
        with self.state_lock:
            if gen > self.applied:
                self.applied, self.checked_at = gen, time.monotonic()
                self.unchecked = self.unchecked and gen <= self.floor      # a list_changed since: not yet checked
                self.removed, self.changed, self.seen, self.snap = removed, changed, tools, snap
                if not changed:
                    self.sealed_drift.clear()      # back at the baseline: a later drift to any state is new
        return tools

    async def fresh(self, session: "GuardSession") -> None:
        """Before a call: the last check must be recent, or it is redone (spec §5.3). Raises when it cannot be."""
        if self.unchecked or time.monotonic() - self.checked_at >= self.cfg.recheck_seconds:
            await self.check_tools(session)

    def seal_drift(self, session: "GuardSession", changed: list[dict], tools: list[dict], snap: tuple) -> None:
        """Seal under the lockfile snapshot (doc, bytes) the check used, never a fresher read."""
        doc, data = snap
        with self.drift_lock:
            before = sha256_hex(data)
            after = sha256_hex(integrity.render(integrity.with_server(doc, self.server.name, tools)))
            if (before, after) in self.sealed_drift:
                return
            try:
                base = self.ledger.call("GET", "/api/agent/baseline", session.agent_session, session.task_seq,
                                        params={"lockfile_hash": before})["seq"]
            except Refused as e:
                if e.status != 404:
                    raise
                print(f"sijil-guard: {self.cfg.lockfile} has no sealed baseline; drift enforced, not sealed",
                      file=sys.stderr)
                return
            p = session.pipeline

            def build() -> dict:
                v = rules.evaluate(p.pack, rules.Facts(
                    "integrity", drift_kinds=sorted({c["kind"] for c in changed}),
                    invisible_unicode=any(c["kind"] == "invisible_unicode" for c in changed)), p.pins)
                decision, mode = rules.outcome(v.action)       # confirm has no channel at tools/list: it blocks
                ext = {"lockfile_hash_before": before, "lockfile_hash_after": after, "trigger": "tools_list",
                       "changed": changed[:integrity.MAX_CHANGED],
                       **({"truncated": True} if len(changed) > integrity.MAX_CHANGED else {})}
                return {"type": "integrity_drift", "parent_seq": str(base), "mode": mode, "decision": decision,
                        "rule_hits": v.hits, "input_hash": before, "output_hash": after,
                        "rulepack_hash": p.pack.hash, "ext": ext}
            p.seal(session.task_seq, build)
            self.sealed_drift.add((before, after))

    async def upstream_note(self, method: str, params: dict) -> None:
        if method == "notifications/tools/list_changed":
            # a rug-pull mid-session is caught before the next call: checked under a live session whose task is
            # open (the first that works); with none, or when the check fails, calls are refused until one succeeds
            with self.state_lock:      # a check already under way may have read the list before the change
                self.gen += 1
                self.floor, self.unchecked = self.gen, True
            for s in [s for s in self.sessions if s.pipeline and not s.closed]:
                try:
                    await self.check_tools(s)
                    break
                except Exception as e:      # any failure is a failed check: closed, logged, notification forwarded
                    print(f"sijil-guard: tool check after list_changed failed: {e}", file=sys.stderr)
            for s in list(self.sessions):
                try:
                    await s.client.notify(method, params)
                except mcp.RpcError:      # one harness that went away must not silence the others
                    pass

    def state(self) -> task.State:
        return task.shared(task.state_path(self.cfg), self.cfg.agent_id, self.open_session)

    async def new_session(self, client: mcp.Client, headers: dict) -> "GuardSession":
        s = GuardSession(self, client, {k.lower(): v for k, v in headers.items()})
        self.sessions.add(s)
        return s

    async def aclose(self) -> None:
        for s in list(self.sessions):
            await s.close()
        if self.upstream:
            await self.upstream.close()


class GuardSession(mcp.Session):
    def __init__(self, guard: Guard, client: mcp.Client, headers: dict):
        self.guard, self.client, self.headers = guard, client, headers
        self.stdio = isinstance(client, mcp.StdioClient)
        self.elicit, self.owned, self.task_seq, self.pipeline = False, False, None, None
        self.session_id, self.last_blocked, self.closed = str(uuid.uuid4()), False, False
        self.loop = asyncio.get_running_loop()

    async def handle(self, method: str, params: dict) -> dict:
        if method == "initialize":
            return await self.initialize(params)
        if method == "ping":
            return {}
        if self.pipeline is None:
            raise mcp.RpcError(-32002, "initialize first")
        if method == "tools/list":
            return await self.tools_list(params)
        if method == "tools/call":
            return await self.tools_call(params)
        raise mcp.RpcError(mcp.METHOD_NOT_FOUND, f"{method} is not proxied by sijil-guard")

    def _join_or_start(self) -> tuple[task.State, int, bool]:
        """(state, task_seq, owned). A task named by X-Sijil-Task-Seq, or (stdio) the state file's open task,
        is joined; otherwise this session starts one and ends it at close (spec §5.9, MCP-only harness)."""
        g, cfg = self.guard, self.guard.cfg
        named = self.headers.get("x-sijil-task-seq")

        def join(state: task.State):
            if named:
                return state, int(named), False
            if self.stdio and state.task_seq:
                return state, state.task_seq, False
            token = self.headers.get(cfg.principal_header.lower()) or os.environ.get("SIJIL_PRINCIPAL_TOKEN")
            seq = task.start_task(g.ledger, state.agent_session, cfg.intent, cfg.harness, self.session_id,
                                  principal_token=token or None, principal_header=cfg.principal_header)
            if self.stdio:      # the harness's other guards and its model calls join this task
                state.tasks = [seq]
            return state, seq, True
        return task.update(task.state_path(cfg), cfg.agent_id, g.open_session, join)

    async def initialize(self, params: dict) -> dict:
        self.elicit = "elicitation" in (params.get("capabilities") or {}) and self.client.can_request
        g = self.guard
        try:      # before any task is started or joined: a server that cannot be checked leaves nothing behind
            await g.check_tools()
        except (Unreachable, Refused) as e:
            raise _ledger_error(e)
        try:
            state, self.task_seq, self.owned = await asyncio.to_thread(self._join_or_start)
        except (Unreachable, Refused, ValueError, OSError) as e:
            raise mcp.RpcError(mcp.SIJIL, f"Sijil: no agent session or task: {e}")
        self.agent_session = state.agent_session
        self.pipeline = Pipeline(self.guard.ledger, state.agent_session, self.guard.cfg)
        if g.changed and g.snap[0] is not None:
            try:
                await asyncio.to_thread(g.seal_drift, self, g.changed, g.seen, g.snap)
            except (Unreachable, Refused) as e:
                await self.close()
                raise _ledger_error(e)
        return {"protocolVersion": self.guard.init.get("protocolVersion", mcp.PROTOCOL),
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": self.guard.init.get("serverInfo", {"name": self.guard.server.name, "version": "0"}),
                "_meta": {"sijil": {"agent_session": state.agent_session, "task_seq": self.task_seq}}}

    async def tools_list(self, params: dict) -> dict:
        g = self.guard
        try:      # the tools checked are the tools relayed: all pages in one answer, no cursor
            tools = await g.check_tools(self)
        except (Unreachable, Refused) as e:
            raise _ledger_error(e)
        return {"tools": [t for t in tools if t["name"] not in g.removed]}

    def _confirm(self, rule) -> str:
        """Elicitation for a confirm rule (spec §5.7); runs on the pipeline's worker thread."""
        msg = {"message": f"Sijil rule {rule.id}: {rule.description}. Allow?", "requestedSchema": ELICIT_SCHEMA}
        fut = asyncio.run_coroutine_threadsafe(self.client.request("elicitation/create", msg), self.loop)
        try:
            answer = fut.result(timeout=300)
        except Exception:
            fut.cancel()                  # a timed-out ask must not stay pending on the harness
            return "denied"
        ok = answer.get("action") == "accept" and (answer.get("content") or {}).get("allow") is True
        return "granted" if ok else "denied"

    async def tools_call(self, params: dict) -> dict:
        s, cfg = self.guard.server, self.guard.cfg
        name, args = params.get("name"), params.get("arguments")
        args = {} if args is None else args
        if not isinstance(name, str) or not isinstance(args, dict):
            raise mcp.RpcError(mcp.INVALID_PARAMS, "tools/call needs a name and an arguments object")
        call = Call(rule_tool=f"mcp:{s.name}:{name}", tool=name, server=s.name, args=args, harness=cfg.harness,
                    session_id=self.session_id, observed_by="mcp_guard", parent_names=[name, f"mcp__{s.name}__{name}"],
                    command_arg=s.command_arg, task_seq=self.task_seq)
        try:      # a call is never made on an old approval: the tools are re-checked when the last check is stale
            await self.guard.fresh(self)
        except (Unreachable, Refused) as e:
            raise _ledger_error(e)
        except mcp.RpcError as e:
            raise mcp.RpcError(mcp.SIJIL, f"Sijil: tool integrity could not be checked: {e.message}")
        # a tool the integrity check took away is refused with its rule; one outside the set that check read
        # (filtered, or never listed by the wrapped server) is refused as the adapter refuses an operation its spec
        # does not declare, so a server cannot skip the check by answering for a tool it does not list
        listed = s.allowed(name) and any(t["name"] == name for t in self.guard.seen)
        forced = (s.allowed(name) and self.guard.removed.get(name)) or (None if listed else [NOT_ALLOWLISTED])
        try:
            sealed = await asyncio.to_thread(self.pipeline.check, call, self._confirm if self.elicit else None, forced)
        except Refusal as r:
            self.last_blocked = r.seq is not None
            sealed_filter = forced == [NOT_ALLOWLISTED] and r.seq is not None
            raise mcp.RpcError(mcp.METHOD_NOT_FOUND if sealed_filter else mcp.SIJIL, str(r),
                               {"sijil": {"seq": r.seq, "rule_hits": r.hits}})
        except (Unreachable, Refused) as e:      # fail closed: a ledger that cannot seal the call stops it
            raise _ledger_error(e)
        self.last_blocked, failed = False, None
        try:
            result = await self.guard.upstream.request("tools/call", {**params, "arguments": args})
        except mcp.RpcError as e:      # the call reached the wrapped server: its failure is still a result
            result, failed = {"content": [{"type": "text", "text": e.message}], "isError": True}, e
        try:      # the call ran: whatever fails from here on, its result is sealed (an error over a guard note)
            content, replaced, arrived = self._items(result.get("content"))
            text = "".join(d[k] for _, _, d, k, binary in self._parts(content) if not binary)      # scanned
            structured = result.get("structuredContent")
            # part of the result: hashed, scanned and bounded like the text
            extra = "" if structured is None else json.dumps(structured, ensure_ascii=False, sort_keys=True)
            text += extra
            raw, size = self._raw(arrived, extra)
            is_error = result.get("isError") is True
            types = [c["type"] for c in content]
            # what the harness gets, cleaned before the seal so the record says whether the budget cut anything
            content, left, cut = self._rewrite(content)
            clean, dropped = self._clean(structured, left) if structured is not None else (None, False)
            cut = replaced or cut or dropped
        except Exception as e:      # a structuredContent nested past the recursion limit, or a guard bug
            print(f"sijil-guard: result of {name} could not be processed: {type(e).__name__}", file=sys.stderr)
            content = [_note("the result could not be processed")]
            clean, text, raw, size, is_error, types, cut = None, content[0]["text"], None, None, True, ["text"], True
        try:
            r = await asyncio.to_thread(self.pipeline.result, call, sealed, text, "error" if is_error else "ok",
                                        types, s.label, raw, size=size, cut=cut)
        except (Unreachable, Refused, Refusal) as e:      # fail closed: the result is withheld unsealed
            raise _ledger_error(e)
        if r.blocked:
            self.last_blocked = True
            raise mcp.RpcError(mcp.SIJIL, f"Result withheld by Sijil rule {', '.join(r.hits) or 'halted'}; seq={r.seq}",
                               {"sijil": {"seq": r.seq, "rule_hits": r.hits}})
        if failed:      # message only, as sealed (stripped, truncated); the server's `data` is not relayed
            raise mcp.RpcError(_code(failed.code), r.text)
        out = {"content": content}      # only these keys reach the harness; upstream _meta and the rest are dropped
        if clean is not None:
            out["structuredContent"] = clean
        if is_error:
            out["isError"] = True
        return {**out, "_meta": {"sijil": {"seq": r.seq, "parent_seq": sealed.seq}}}

    def _clean(self, value, budget: int) -> tuple:
        """structuredContent after the same treatment as the text: stripped, or dropped when over what is left of
        the result budget after the content. (value or None, dropped for the budget)."""
        raw = json.dumps(value, ensure_ascii=False)
        if self.guard.cfg.invisible_unicode == "strip":
            raw = unicode.strip(raw)
        raw = raw.encode("utf-8", "replace").decode("utf-8")
        if len(raw.encode("utf-8", "surrogatepass")) > budget:
            return None, True
        try:
            return json.loads(raw), False
        except ValueError:
            return None, False

    def _items(self, raw) -> tuple[list, bool, list]:
        """Each content item rebuilt from the allowlist for its type; _meta, annotations and unknown keys are
        dropped. Every upstream value is shape-checked: a `content` that is not a list, an item that is not an
        object, a type that is not a known string, an allowlisted field that is not a string, a text item
        without text, an image or audio item without data, or a payload that is not base64 becomes a text item
        saying so. Items past MAX_ITEMS collapse into one note. A binary item that would take the relayed items
        (as JSON, before stripping) past the result budget becomes a note. A payload is relayed re-encoded, so
        the harness gets exactly the bytes that are hashed. (items, whether a limit replaced any, what arrived:
        (index, type, string fields, payloads) of every well-formed item, all of them, before any note).
        Items past MAX_ITEMS are hashed (bounded by mcp.MAX_LINE), not relayed."""
        limit, used, out, replaced, arrived = self.guard.cfg.max_result_bytes, 0, [], False, []
        raw = raw if isinstance(raw, list) else [] if raw is None else [None]
        for n, c in enumerate(raw):
            c = c if isinstance(c, dict) else {}
            kind = c.get("type") if isinstance(c.get("type"), str) else None
            holder = c.get("resource") if kind == "resource" else c
            holder = holder if isinstance(holder, dict) else {}
            strs, binary = RESOURCE if kind == "resource" else ITEMS.get(kind, ((), ()))
            known = kind in ITEMS or kind == "resource" and isinstance(c.get("resource"), dict)
            typed = all(isinstance(holder[k], str) for k in (*strs, *binary) if k in holder)
            fields = {k: holder[k] for k in strs if k in holder} if typed else {}
            blobs = {k: _decode(holder[k]) for k in binary if k in holder} if typed else {}
            missing = kind in REQUIRED and REQUIRED[kind] not in holder
            ok = known and typed and not missing and None not in blobs.values()
            if ok:
                arrived.append((n, kind, list(fields.values()), list(blobs.values())))
            if n >= MAX_ITEMS:
                continue
            if not ok:
                item = _note(f"unsupported content type {str(kind)[:40]}")
            else:
                fields.update({k: base64.b64encode(b).decode("ascii") for k, b in blobs.items()})
                item = {"type": kind, "resource": fields} if kind == "resource" else {"type": kind, **fields}
                if blobs and used + _wire(item) + 2 > limit:
                    item, replaced = _note(f"{kind} over the result budget"), True
            used += _wire(item) + 2      # ", " between items
            out.append(item)
        if len(raw) > MAX_ITEMS:
            out.append(_note(f"{len(raw) - MAX_ITEMS} more items over the item limit"))
            replaced = True
        return out, replaced, arrived

    @staticmethod
    def _raw(arrived: list, structured: str) -> tuple[bytes, int]:
        """The MCP door's hash input and byte count (the definition both doors follow is Pipeline.result's).
        T is utf8 of the result text as it arrived: every string field of the well-formed items, in item order
        (for a text item, its text), then `structured`, the structuredContent as sorted-key JSON. A text-only
        result therefore hashes sha256(utf8(concatenated text)) and counts its length (§2.4.2). With an image,
        audio or blob payload, P the decoded payload of a binary part, n the index of its content item, t that
        item's type, and u64 an 8-byte big-endian length or index:
            output_hash = sha256(0xFF || u64(len T) || T || for each binary part, in item order:
                                 u64(n) || u64(len t) || t || u64(len P) || P)
            bytes = len T + the sum of len P (no framing)
        Every part is length-prefixed, and 0xFF never occurs in UTF-8, so no other result hashes the same."""
        t = ("".join(x for _, _, strs, _ in arrived for x in strs) + structured).encode("utf-8", "surrogatepass")
        parts = [(n, kind.encode("ascii"), p) for n, kind, _, payloads in arrived for p in payloads]
        if not parts:
            return t, len(t)
        u64 = lambda v: v.to_bytes(8, "big")
        framed = [b"\xff", u64(len(t)), t]
        for n, kind, p in parts:
            framed += [u64(n), u64(len(kind)), kind, u64(len(p)), p]
        return b"".join(framed), len(t) + sum(len(p) for _, _, p in parts)

    @staticmethod
    def _parts(content: list) -> list:
        """(index, item, container, key, binary) for every field of the items that reaches the harness, in order:
        strings (sealed and cleaned), then the base64 payload."""
        found = []
        for n, c in enumerate(content):
            if c["type"] == "resource":
                holder, (strs, binary) = c["resource"], RESOURCE
            else:
                holder, (strs, binary) = c, ITEMS[c["type"]]
            found += [(n, c, holder, k, False) for k in strs if k in holder]
            found += [(n, c, holder, k, True) for k in binary if k in holder]
        return found

    def _rewrite(self, content: list) -> tuple[list, int, bool]:
        """Strip every sealed string, then keep the items, as JSON, within the result budget in order: an item
        that does not fit has its strings cut to fit; when not even its keys fit, or it carries a payload, it
        and every later item collapse into one note. (content, budget left, cut)."""
        cfg, budget, cut, out = self.guard.cfg, self.guard.cfg.max_result_bytes, False, []
        for n, c in enumerate(content):
            strings = [(d, k) for _, _, d, k, binary in self._parts([c]) if not binary]
            for d, k in strings:      # a lone surrogate cannot be written as UTF-8: it becomes "?"
                t = unicode.strip(d[k]) if cfg.invisible_unicode == "strip" else d[k]
                d[k] = t.encode("utf-8", "replace").decode("utf-8")
            if _wire(c) + 2 > budget:
                cut, whole = True, [d[k] for d, k in strings]
                for d, k in strings:
                    d[k] = ""
                room = budget - _wire(c) - 2
                if room < 0 or len(strings) < len(self._parts([c])):
                    out.append(_note(f"{len(content) - n} more items over the result budget"))
                    return out, 0, cut
                for (d, k), t in zip(strings, whole):
                    d[k] = _fit(t, room + 2) if room > 0 else ""
                    room -= _wire(d[k]) - 2
            budget -= _wire(c) + 2
            out.append(c)
        return out, budget, cut

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.guard.sessions.discard(self)
        if self.owned:
            outcome = "blocked" if self.last_blocked else "completed"
            try:
                await asyncio.to_thread(task.end_task, self.guard.ledger, self.agent_session, self.task_seq, outcome)
            except (Unreachable, Refused):
                pass                  # the ledger closes the task as timeout when the session expires
            if self.stdio:
                await asyncio.to_thread(self._clear)

    def _clear(self) -> None:
        """Drop the ended task from the state file. Load-only: shutdown never opens a session. The sibling
        guards of a stdio owner that closes first fail closed at the ledger (the task is ended)."""
        cfg = self.guard.cfg
        path = task.state_path(cfg)
        try:
            with task.locked(path):
                st = task.load(path, cfg.agent_id)
                if st and st.task_seq == self.task_seq:
                    st.tasks = []
                    task.save(st, path)
        except OSError:
            pass


def server_named(cfg: Config, name: str) -> Server:
    server = next((s for s in cfg.servers if s.name == name), None)
    if server is None:
        raise ValueError(f"no server named {name!r} in {cfg.path}")
    return server


async def pin(cfg: Config, server_name: str, ledger: Ledger) -> tuple[int, int]:
    """`tools pin`: write this server's tools into the lockfile and seal integrity_baseline (spec §2.4.4).
    Returns (seq, tools pinned)."""
    if not cfg.lockfile:
        raise ValueError(f"{cfg.path}: set lockfile: to pin tools")
    guard = Guard(cfg, server_named(cfg, server_name), ledger)
    await guard.start()
    try:
        tools = await guard.tools()
    except mcp.RpcError as e:
        raise ValueError(f"cannot list the tools of {server_name}: {e.message}") from None
    finally:
        await guard.aclose()
    old = Path(cfg.lockfile).read_bytes() if Path(cfg.lockfile).exists() else None
    data, doc = integrity.pin(cfg.lockfile, server_name, tools)
    h = sha256_hex(data)
    ext = {"lockfile": os.path.relpath(os.path.realpath(cfg.lockfile), cfg.repo), "lockfile_hash": h,
           "entries": len(doc["entries"]), "files": 0, "mcp_tools": len(doc["entries"]), "roots": [],
           "tool": integrity.TOOL, "invisible_unicode_entries": 0}
    try:
        state = await asyncio.to_thread(guard.state)
        p = Pipeline(ledger, state.agent_session, cfg)
        r = await asyncio.to_thread(p.seal, None, lambda: {"type": "integrity_baseline", "input_hash": h,
                                                           "rulepack_hash": p.pack.hash, "ext": ext})
    except BaseException:      # no baseline was sealed: the lockfile goes back to what it was
        if old is None:
            Path(cfg.lockfile).unlink(missing_ok=True)
        else:
            Path(cfg.lockfile).write_bytes(old)
        raise
    return r["seq"], len(tools)


async def run(cfg: Config, server_name: str, ledger: Ledger, http_listen: str = "") -> None:
    server = server_named(cfg, server_name)
    host, port, tls = mcp_listen(cfg, http_listen) if http_listen else ("", 0, {})
    guard = Guard(cfg, server, ledger)
    await guard.start()
    try:
        if http_listen:
            app = mcp.http_app(guard.new_session, cfg.allowed_origins, cfg.tools_token)
            await uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning",
                                                **tls)).serve()
        else:
            reader, write = await mcp.stdio_streams()
            await mcp.serve_stdio(guard.new_session, reader, write)
    finally:
        await guard.aclose()
