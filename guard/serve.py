"""The MCP guard (spec §5.1-5.7): one wrapped server per process; the harness sees it as that server.

initialize joins a task or starts one (§5.9); tools/list is filtered by tools.allow/deny; every tools/call goes
through the pipeline before and after the wrapped server runs it. resources/* and prompts/* are not proxied:
they would be a content channel the ledger never sees.
"""

import asyncio
import os
import uuid

import uvicorn

from . import identity, mcp, task, unicode
from .config import Config, Server
from .ledger import Ledger, Refused, Unreachable
from .pipeline import Call, Pipeline, Refusal
from .rules import NOT_ALLOWLISTED

ELICIT_SCHEMA = {"type": "object", "properties": {"allow": {"type": "boolean"}}, "required": ["allow"]}


class Guard:
    def __init__(self, cfg: Config, server: Server, ledger: Ledger, open_session=None):
        self.cfg, self.server, self.ledger = cfg, server, ledger
        self.open_session = open_session or (lambda: identity.open_session(ledger, cfg))
        self.sessions: set = set()
        self.upstream = None
        self.init: dict = {}

    async def start(self) -> None:
        s = self.server
        if s.transport == "stdio":
            self.upstream = mcp.StdioUpstream(s.command, list(s.args), s.env, self.upstream_note)
        else:
            self.upstream = mcp.HttpUpstream(s.url, s.headers, self.upstream_note)
        await self.upstream.start()
        self.init = await self.upstream.request("initialize", {
            "protocolVersion": mcp.PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "sijil-guard", "version": "0.1.0"}})
        await self.upstream.notify("notifications/initialized")

    async def upstream_note(self, method: str, params: dict) -> None:
        if method == "notifications/tools/list_changed":
            for s in list(self.sessions):
                await s.client.notify(method, params)

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
        state = g.state()
        named = self.headers.get("x-sijil-task-seq")
        if named:
            return state, int(named), False
        path = task.state_path(cfg)
        with task.locked(path):
            current = task.load(path, cfg.agent_id) if self.stdio else None
            if current and current.task_seq:
                return current, current.task_seq, False
            token = self.headers.get(cfg.principal_header.lower()) or os.environ.get("SIJIL_PRINCIPAL_TOKEN")
            seq = task.start_task(g.ledger, state.agent_session, cfg.intent, cfg.harness, self.session_id,
                                  principal_token=token or None, principal_header=cfg.principal_header)
            if self.stdio:      # the harness's other guards and its model calls join this task
                state.tasks = [seq]
                task.save(state, path)
            return state, seq, True

    async def initialize(self, params: dict) -> dict:
        self.elicit = "elicitation" in (params.get("capabilities") or {}) and self.client.can_request
        try:
            state, self.task_seq, self.owned = await asyncio.to_thread(self._join_or_start)
        except (Unreachable, Refused, ValueError, OSError) as e:
            raise mcp.RpcError(mcp.SIJIL, f"Sijil: no agent session or task: {e}")
        self.agent_session = state.agent_session
        self.pipeline = Pipeline(self.guard.ledger, state.agent_session, self.guard.cfg)
        return {"protocolVersion": self.guard.init.get("protocolVersion", mcp.PROTOCOL),
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": self.guard.init.get("serverInfo", {"name": self.guard.server.name, "version": "0"}),
                "_meta": {"sijil": {"agent_session": state.agent_session, "task_seq": self.task_seq}}}

    async def tools_list(self, params: dict) -> dict:
        result = await self.guard.upstream.request("tools/list", params or None)
        tools = [t for t in result.get("tools", []) if isinstance(t, dict) and self.guard.server.allowed(t.get("name", ""))]
        return {**result, "tools": tools}

    def _confirm(self, rule) -> str:
        """Elicitation for a confirm rule (spec §5.7); runs on the pipeline's worker thread."""
        msg = {"message": f"Sijil rule {rule.id}: {rule.description}. Allow?", "requestedSchema": ELICIT_SCHEMA}
        fut = asyncio.run_coroutine_threadsafe(self.client.request("elicitation/create", msg), self.loop)
        try:
            answer = fut.result(timeout=300)
        except Exception:
            return "denied"
        ok = answer.get("action") == "accept" and (answer.get("content") or {}).get("allow") is True
        return "granted" if ok else "denied"

    async def tools_call(self, params: dict) -> dict:
        s, cfg = self.guard.server, self.guard.cfg
        name, args = params.get("name"), params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(args, dict):
            raise mcp.RpcError(mcp.INVALID_PARAMS, "tools/call needs a name and an arguments object")
        call = Call(rule_tool=f"mcp:{s.name}:{name}", tool=name, server=s.name, args=args, harness=cfg.harness,
                    session_id=self.session_id, observed_by="mcp_guard", parent_names=[name, f"mcp__{s.name}__{name}"],
                    command_arg=s.command_arg, task_seq=self.task_seq)
        forced = None if s.allowed(name) else [NOT_ALLOWLISTED]
        try:
            sealed = await asyncio.to_thread(self.pipeline.check, call, self._confirm if self.elicit else None, forced)
        except Refusal as r:
            self.last_blocked = r.seq is not None
            code = mcp.METHOD_NOT_FOUND if forced else mcp.SIJIL
            raise mcp.RpcError(code, str(r), {"sijil": {"seq": r.seq, "rule_hits": r.hits}})
        except (Unreachable, Refused) as e:
            raise mcp.RpcError(mcp.SIJIL, f"Sijil ledger unreachable or refused the record: {e}")
        self.last_blocked, failed = False, None
        try:
            result = await self.guard.upstream.request("tools/call", params)
        except mcp.RpcError as e:      # the call reached the wrapped server: its failure is still a result
            result, failed = {"content": [{"type": "text", "text": e.message}], "isError": True}, e
        content = [c for c in result.get("content", []) if isinstance(c, dict)]
        text = "".join(c.get("text", "") for c in content if c.get("type") == "text" and isinstance(c.get("text"), str))
        status = "error" if result.get("isError") else "ok"
        try:
            r = await asyncio.to_thread(self.pipeline.result, call, sealed, text, status,
                                        [str(c.get("type")) for c in content], s.label)
        except (Unreachable, Refused) as e:
            raise mcp.RpcError(mcp.SIJIL, f"Sijil ledger unreachable or refused the record: {e}")
        if r.blocked:
            self.last_blocked = True
            raise mcp.RpcError(mcp.SIJIL, f"Result withheld by Sijil rule {', '.join(r.hits) or 'halted'}; seq={r.seq}",
                               {"sijil": {"seq": r.seq, "rule_hits": r.hits}})
        if failed:
            raise failed
        if r.text != text:
            content = self._rewrite(content)
        return {**result, "content": content,
                "_meta": {**(result.get("_meta") or {}), "sijil": {"seq": r.seq, "parent_seq": sealed.seq}}}

    def _rewrite(self, content: list) -> list:
        """Strip and truncate each text item as the pipeline did the whole text; other items pass."""
        cfg, budget, out = self.guard.cfg, self.guard.cfg.max_result_bytes, []
        for c in content:
            if c.get("type") == "text" and isinstance(c.get("text"), str):
                t = unicode.strip(c["text"]) if cfg.invisible_unicode == "strip" else c["text"]
                b = t.encode("utf-8", "surrogatepass")
                c, budget = {**c, "text": b[:max(budget, 0)].decode("utf-8", "ignore")}, budget - len(b)
            out.append(c)
        return out

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
                path = task.state_path(self.guard.cfg)
                with task.locked(path):
                    st = task.load(path, self.guard.cfg.agent_id)
                    if st and st.task_seq == self.task_seq:
                        st.tasks = []
                        task.save(st, path)


async def run(cfg: Config, server_name: str, ledger: Ledger, http_listen: str = "") -> None:
    server = next((s for s in cfg.servers if s.name == server_name), None)
    if server is None:
        raise ValueError(f"no server named {server_name!r} in {cfg.path}")
    guard = Guard(cfg, server, ledger)
    await guard.start()
    try:
        if http_listen:
            host, port = http_listen.rsplit(":", 1)
            await uvicorn.Server(uvicorn.Config(mcp.http_app(guard.new_session), host=host, port=int(port),
                                                log_level="warning")).serve()
        else:
            reader, write = await mcp.stdio_streams()
            await mcp.serve_stdio(guard.new_session, reader, write)
    finally:
        await guard.aclose()
