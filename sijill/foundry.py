"""The Azure AI Foundry Responses relay (spec §17.4): the model door for Foundry prompt agents. BSL.

`POST /v1/responses` is forwarded to the Foundry project under the ledger's own Entra token, never the user's.
Each Foundry conversation is one task of the relay agent (registered `auth: relay` at startup, §17.4.5) and each
round trip one `inference`. With `require_approval: always` Foundry asks before it calls an MCP tool: the relay is
that approval gate (rule pack, budgets, named approval) and answers Foundry itself with `mcp_approval_response`;
the portal never sees the round trip. Server-side tool calls that Foundry reports without asking are sealed after
the fact (§17.4.4): recorded, never enforced.
"""

import asyncio
import json
import os
import re
from collections import Counter
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from guard import rules as guard_rules, unicode    # Apache-2.0: the rule engine the guard runs
from guard.cmdparse import Roots
from guard.pipeline import exec_hints

from . import agents, approvals, budgets, chat, oidc, policy, record

API = "foundry_responses"
ALLOWED = ("agent", "conversation", "input", "previous_response_id", "metadata")   # the client fields forwarded
ITEMS = ("message", "function_call_output")   # the input item types a client may send, spelled exactly
# output item types the relay recognises, besides any *_call Foundry ran itself: pending ones (function_call,
# answered by the portal; mcp_approval_request, answered by the gate) and informational ones. Any other type may be
# a renamed request waiting for an answer, so the turn fails closed (§12 item 42).
KNOWN = ("message", "reasoning", "mcp_list_tools", "function_call", "mcp_approval_request")
# *_call items the client executes and answers, as it answers function_call: not run by Foundry, and the relay has
# no gate for them, so they fail closed like an unknown type
CLIENT_CALLS = ("computer_call", "local_shell_call", "custom_tool_call", "shell_call", "apply_patch_call")
UNKNOWN_HIT = "foundry-item-unknown"
ROUNDS = 8                                   # approval round trips per user turn
GRACE_S = 60                                 # past the deadline, as the guard: the timer has failed, do not hang
ROOTS = Roots("/", "/", "/")                 # a relay has no workspace: path rules see absolute paths only


def cj(obj) -> str:
    return record.canonical_json(obj).decode()


def server_label(item: dict) -> str:
    """Foundry's server_label as a source-label name: [a-z0-9_-]{1,32} (§17.1)."""
    name = re.sub(r"[^a-z0-9_-]", "-", str(item.get("server_label", "")).lower())[:32]
    return name or "foundry"


def tool_of(item: dict) -> tuple[str, str, str, str, dict]:
    """(tool, server, qualified, source_label, arguments) of a server-side tool item."""
    if item.get("type") in ("mcp_call", "mcp_approval_request"):
        label, name = server_label(item), str(item.get("name", ""))
        try:
            args = json.loads(item.get("arguments") or "{}")
        except ValueError:
            args = {"_raw": item.get("arguments")}
        return name, label, f"mcp:{label}:{name}", f"mcp:{label}", args if isinstance(args, dict) else {"body": args}
    kind = str(item.get("type"))
    action = item.get("action") if isinstance(item.get("action"), dict) else {}
    return kind, "foundry", f"foundry:{kind}", "web" if kind == "web_search_call" else "mcp:foundry", action


def ran(kind: str) -> bool:
    """A server-side call Foundry ran: any *_call but function_call and the client-executed ones."""
    return kind.endswith("_call") and kind not in CLIENT_CALLS and kind != "function_call"


def output_text(data: dict) -> str:
    return "".join(c.get("text", "") for item in data.get("output", []) if isinstance(item, dict) and
                   item.get("type") == "message" for c in item.get("content") or []
                   if isinstance(c, dict) and c.get("type") == "output_text" and isinstance(c.get("text"), str))


def guard_pack(n):
    """The rule pack in force, as the guard's engine reads it (same file, same hash)."""
    if n.rulepack is None:
        return None
    if getattr(n, "_guard_pack", None) is None or n._guard_pack.hash != n.rulepack.hash:
        n._guard_pack = guard_rules.load(n.rulepack.path)
    return n._guard_pack


def verdict(n, task: dict, tool: str, args: dict, before_seq: int) -> guard_rules.Verdict:
    pack = guard_pack(n)
    if pack is None:
        return guard_rules.Verdict([], "allow")
    labels = sorted({r["source_label"] for r in n.store.in_task(task["seq"])
                     if r["type"] == "tool_result" and r["seq"] < before_seq})
    facts, _ = guard_rules.call_facts(tool, tool.rsplit(":", 1)[-1], args, ROOTS, "foundry", context_labels=labels)
    return guard_rules.evaluate(pack, facts, guard_rules.Pins())


async def register(n) -> None:
    """Startup: the Foundry agent is registered once, auth relay (§17.4.5)."""
    cfg = n.policy.foundry
    if cfg is None or cfg.agent_id in n.agents.agents:
        return
    x = {"auth": "relay", "registered_by": cfg.registered_by, "principal_auth": "key", "id_form": "spiffe",
         "relay_binding": {"platform": "foundry", "endpoint_host": urlsplit(cfg.endpoint).hostname,
                           "agent_name": cfg.agent_name}}
    await agents.seal_agent(n, "agent_register", cfg.agent_id, cfg.registered_by, "", x,
                            check=lambda: n.agents.unregistered(cfg.agent_id))


async def seal_in(n, task: dict, body) -> dict:
    """Seal a record of the conversation's task; a task that ended meanwhile is not written into."""
    def build() -> dict:
        if n.store.task_ended(task["seq"]):
            raise HTTPException(409, "the conversation's task ended")
        return body() if callable(body) else body
    return await n.seal(build)


def in_task(n, task: dict, type_: str, **fields) -> dict:
    return n.body(n.policy, type_, agent_id=task["agent_id"], principal=task["principal"], task_seq=str(task["seq"]),
                  **fields)


async def round_trip(n, cfg, task: dict, req: dict, conv_hash: str, human: dict, gated=()):
    """One Responses round trip, sealed as one inference (§17.4.3). Returns (record, response) or a refusal."""
    pol, token = n.policy, os.environ.get(cfg.token_env, "")
    if not token:
        raise HTTPException(503, f"the relay's Entra token is not set ({cfg.token_env})")
    given = req.get("input")
    messages = [{"content": given}] if isinstance(given, str) else [i for i in given or [] if isinstance(i, dict)]
    decision, mode, hits = policy.evaluate(pol, n.region, "", messages, skip=("model_allowlist",))
    if n.halted:
        decision, mode, hits = "block", "enforce", [policy.HALT_HIT]
    else:
        exceeded = budgets.evaluate(n.rulepack, n.store, task, "inference")[1]
        if exceeded:
            decision, mode, hits = "block", "enforce", hits + exceeded
    # a refreshed token in the conversation is sealed once, as on the model door (§17.2.8)
    claims = {} if n.store.token_in_force(task["seq"]) == human["claims"]["token_hash"] else \
        {"principal_claims": human["claims"]}
    # until Foundry reports a valid model id, model_id is the agent name and model_digest follows it (§17.4.3)
    base = in_task(n, task, "inference", model_id=cfg.agent_name, model_digest=f"api:azure-foundry:{cfg.agent_name}",
                   mode=mode, decision=decision,
                   rule_hits=policy.rule_hits_json(hits), input_hash=record.sha256_hex(record.canonical_json(given)),
                   ext=cj({"api": API, "session_id": conv_hash, **claims}))

    def settled(b: dict):
        return lambda: b if policy.HALT_HIT in json.loads(b["rule_hits"]) else budgets.inference(n, task, b)

    def refused(rec: dict, status: int, kind: str) -> JSONResponse:
        return JSONResponse(status_code=status, headers={"X-Sijill-Seq": str(rec["seq"])}, content={
            "error": {"type": kind, "message": "Refused by Sijil"},
            "sijill": {"seq": rec["seq"], "decision": rec["decision"], "rule_hits": json.loads(rec["rule_hits"])}})
    if decision == "block":
        return refused(await seal_in(n, task, settled(base)), 403, "policy_block"), None
    # forwarded, so priced like any forwarded request: no usage reported means missing_usage_cost_micro
    failed = {**base, "rule_hits": policy.rule_hits_json(hits + [policy.UPSTREAM_ERROR_HIT]),
              "ext": cj({**json.loads(base["ext"]), **budgets.cost(n.rulepack, base["model_digest"], None)})}
    try:
        resp = await n.foundry.post("/responses", json=req, headers={"Authorization": f"Bearer {token}"})
        status, data = resp.status_code, resp.json() if resp.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        status, data = 502, None
    if not isinstance(data, dict) or not isinstance(data.get("output"), list):
        return refused(await seal_in(n, task, settled(failed)), 502, "upstream_error"), None
    u = data.get("usage") if isinstance(data.get("usage"), dict) else {}
    usage = {k: u[k] for k in ("input_tokens", "output_tokens")} if all(type(u.get(k)) is int for k in
                                                                        ("input_tokens", "output_tokens")) else None
    try:
        model = data["model"] if isinstance(data.get("model"), str) and chat.MODEL.fullmatch(data["model"]) \
            else cfg.agent_name
        digest = f"api:azure-foundry:{model}"
        post = policy.evaluate(pol, n.region, digest, messages)
        items = [i for i in data["output"] if isinstance(i, dict)]
        if any(not isinstance(i, dict) or str(i.get("type")) not in KNOWN and not ran(str(i.get("type")))
               for i in data["output"]):
            post = ("block", "enforce", [*post[2], UNKNOWN_HIT])
        uses = []
        for i in items:
            kind = str(i.get("type"))
            if kind == "function_call":              # executed by the portal; its call_id is what it sends back
                uses.append(chat.tool_use(i.get("call_id"), i.get("name"), i.get("arguments", "")))
            elif kind == "mcp_approval_request" or (ran(kind) and kind != "mcp_call") or \
                    (kind == "mcp_call" and i.get("approval_request_id") not in gated):
                # a gated request, or a call Foundry ran without asking: the parent of its tool_call (Ruling)
                tool, _, qualified, _, args = tool_of(i)
                uses.append({"id": str(i.get("id", "")), "name": qualified.split(":", 1)[1] if kind.startswith("mcp")
                             else tool, "args_hash": record.sha256_hex(record.canonical_json(args))})
        x = {"api": API, "attestation": "api", "request_hash": record.sha256_hex(record.canonical_json(req)),
             "system_hash": "", "response_hash": record.sha256_hex(resp.content), "provider_request_id": str(data.get("id", "")),
             "stop_reason": str(data.get("status", "")), "tool_uses": uses, "session_id": conv_hash,
             "foundry": {"endpoint_host": urlsplit(cfg.endpoint).hostname, "agent_name": cfg.agent_name,
                         "agent_version": str((data.get("agent") or {}).get("version", "")) if isinstance(data.get("agent"), dict) else "",
                         "response_id": str(data.get("id", "")), "previous_response_id": str(req.get("previous_response_id") or ""),
                         "conversation_hash": conv_hash, "items": dict(Counter(str(i.get("type")) for i in items))},
             **budgets.cost(n.rulepack, digest, usage)}
        sealed = {**base, "model_id": model, "model_digest": digest, "decision": post[0], "mode": post[1],
                  "rule_hits": policy.rule_hits_json(post[2]), "output_hash": record.output_hash(output_text(data)),
                  "ext": cj(x)}
        cj(sealed)                       # every field the seal will hash, model_digest included
    except (record.NotCanonical, UnicodeEncodeError):
        # NaN, an infinity or a lone surrogate in what Foundry answered (§2.2): it was billed, so the round trip is
        # sealed as a priced upstream_error with only its raw bytes hashed, and nothing in it is gated or relayed
        x = {**json.loads(failed["ext"]), "response_hash": record.sha256_hex(resp.content),
             **budgets.cost(n.rulepack, base["model_digest"], usage)}
        return refused(await seal_in(n, task, settled({**failed, "ext": cj(x)})), 502, "upstream_error"), None
    if post[0] == "block":         # Foundry answered, but not with an approved model: the answer is withheld
        return refused(await seal_in(n, task, settled({**sealed, "output_hash": ""})), 403, "policy_block"), None
    rec = await seal_in(n, task, settled(sealed))
    if rec["decision"] == "block":
        return refused(rec, 403, "policy_block"), None
    n.store.index_tool_uses(rec["seq"], uses)
    return rec, data


async def gate(n, task: dict, inference: dict, item: dict, conv_hash: str, deny: bool = False) -> tuple[int, bool]:
    """An mcp_approval_request: the model's tool request, evaluated as a tool_call before Foundry runs it
    (§17.4.2). Returns (tool_call seq, approve)."""
    tool, server, qualified, _, args = tool_of(item)
    args_hash = record.sha256_hex(record.canonical_json(args))
    v = verdict(n, task, qualified, args, inference["seq"])
    _, over, on_exceed = budgets.evaluate(n.rulepack, n.store, task, "tool_call", qualified)
    action = max([v.action, *([on_exceed] if over else [])], key=guard_rules.ACTIONS.index)
    if deny:                                       # the round limit: nothing more is relayed, so nothing is granted
        action = "block"
    confirmation, decided = None, {}
    if action == "confirm":
        try:
            p = await approvals.request_approval(n, None, task, {
                "parent_seq": str(inference["seq"]), "correlation": "tool_use_id", "tool": tool, "server": server,
                "qualified": qualified, "input_hash": args_hash, "arg_keys": sorted(args),
                "rule_hits": [r.id for r in v.fired if r.action == "confirm"] + over})
        except HTTPException:
            confirmation = "unavailable"
        else:
            remaining = (approvals.ts_ms(p.deadline) - approvals.ts_ms(record.now_ts())) / 1000
            try:                                   # the ledger's own timer seals the timeout
                await asyncio.wait_for(p.event.wait(), max(0, remaining) + GRACE_S)
            except asyncio.TimeoutError:
                confirmation = "unavailable"       # no decision to cite: the call is blocked
            else:
                confirmation = "granted" if p.outcome == "granted" else "denied"
                decided = {"approval_seq": p.decision_seq}
    decision, mode = guard_rules.outcome(action, confirmation)
    hits = [*v.hits, *over]
    ext = {"harness": "foundry", "session_id": conv_hash, "tool": tool, "server": server, "qualified": qualified,
           "tool_use_id": str(item.get("id")), "correlation": "tool_use_id", "observed_by": "foundry_relay",
           "foundry_item_id": str(item.get("id")), "summary": {"arg_keys": sorted(args)},
           **({"confirmation": confirmation} if confirmation else {}), **decided}
    body = in_task(n, task, "tool_call", parent_seq=str(inference["seq"]), mode=mode, decision=decision,
                   rule_hits=policy.rule_hits_json(hits), input_hash=args_hash, ext=cj(ext))
    def build() -> dict:
        if n.halted:                              # the operator halt stops the relay too; a blocked call consumes no grant
            halted = {k: v for k, v in ext.items() if k not in ("approval_seq", "budget")}
            return {**body, "mode": "enforce", "decision": "block", "rule_hits": policy.rule_hits_json(
                [*(h for h in hits if not h.startswith("budget:")), policy.HALT_HIT]),
                "ext": cj({**halted, **({"confirmation": "denied"} if "approval_seq" in ext else {})})}
        if "approval_seq" in ext:                 # what the verifier's V2 and V3 would refuse
            agents.check_approval(n.store, n.rulepack, body, ext)
        return budgets.stamp(n, task, body, ext, hits, confirmation == "granted")
    rec = await seal_in(n, task, build)
    return rec["seq"], rec["decision"] != "block"


async def after_the_fact(n, task: dict, inference: dict, item: dict, conv_hash: str) -> None:
    """A server-side tool call Foundry ran without asking: sealed as reported, at most flag (§17.4.4)."""
    tool, server, qualified, label, args = tool_of(item)
    v = verdict(n, task, qualified, args, inference["seq"])
    ext = {"harness": "foundry", "session_id": conv_hash, "tool": tool, "server": server, "qualified": qualified,
           "tool_use_id": str(item.get("id")), "correlation": "tool_use_id", "observed_by": "foundry_relay",
           "foundry_item_id": str(item.get("id")), "after_the_fact": True, "summary": {"arg_keys": sorted(args)}}
    rec = await seal_in(n, task, in_task(n, task, "tool_call", parent_seq=str(inference["seq"]),
                                         decision="flag" if v.hits else "allow", rule_hits=policy.rule_hits_json(v.hits),
                                         input_hash=record.sha256_hex(record.canonical_json(args)), ext=cj(ext)))
    await result(n, task, rec["seq"], item, qualified, tool, server, label)


async def result(n, task: dict, call_seq: int, item: dict, qualified: str, tool: str, server: str, label: str) -> None:
    """The output Foundry reports for a tool call. The model inside Foundry has already read it, so it is recorded
    and flagged, never withheld."""
    out = item.get("output")
    text = out if isinstance(out, str) else "" if out is None else json.dumps(out, sort_keys=True)
    scan, hints = unicode.scan(text), exec_hints(text)
    pack = guard_pack(n)
    v = guard_rules.evaluate(pack, guard_rules.Facts("tool_result", tool=qualified, harness="foundry", source_label=label,
                                                     invisible_unicode=scan["found"], exec_hints=hints),
                             guard_rules.Pins()) if pack else guard_rules.Verdict([], "allow")
    ext = {"tool": tool, "server": server, "status": "error" if item.get("error") else "ok",
           "bytes": len(text.encode("utf-8", "surrogatepass")), "content_types": ["text"],
           "invisible_unicode": {"found": scan["found"], "count": scan["count"], "action": "none",
                                 **({"codepoints": scan["codepoints"]} if scan["found"] else {})},
           **({"exec_hints": hints} if hints else {})}
    await seal_in(n, task, in_task(n, task, "tool_result", parent_seq=str(call_seq), source_label=label,
                                   decision="flag" if v.hits else "allow", rule_hits=policy.rule_hits_json(v.hits),
                                   output_hash=record.sha256_hex(text.encode("utf-8", "surrogatepass")), ext=cj(ext)))


class _Started(Exception):
    """The conversation's task was started meanwhile by a concurrent first request."""


def router() -> APIRouter:
    r = APIRouter()

    @r.post("/v1/responses")
    async def responses(request: Request):
        n = request.app.state.node
        cfg = n.policy.foundry
        if cfg is None:
            raise HTTPException(404, "the Foundry relay is not configured (policy.yaml foundry:)")
        try:
            payload = await request.json()
        except ValueError:
            payload = None
        conv = payload.get("conversation") if isinstance(payload, dict) else None
        conv = conv.get("id") if isinstance(conv, dict) else conv
        if not isinstance(conv, str) or not conv or "input" not in payload:
            raise HTTPException(400, "the body needs input and conversation: one task per Foundry conversation")
        agent = payload.get("agent")
        refused = [k for k in payload if k not in ALLOWED]
        if agent is not None and (agent.get("name") if isinstance(agent, dict) else agent) != cfg.agent_name:
            refused.append("agent")
        given = payload["input"]
        if not (isinstance(given, str) or (isinstance(given, list) and all(
                isinstance(i, dict) and i.get("type") in ITEMS and isinstance(i["type"], str) for i in given))):
            refused.append(f"input: a string or a list of items of type {list(ITEMS)}")
        if refused:
            raise HTTPException(400, f"not accepted by the relay (only the ledger's gate answers approvals): {refused}")
        input_hash = record.sha256_hex(record.canonical_json(given))   # NaN or a lone surrogate: 400, before any task
        conv_hash = record.sha256_hex(conv.encode())
        sid = "fr_" + conv_hash[:32]                 # the relay's agent session for this conversation (not evidence)
        sess = n.store.session(sid)
        if sess is not None and sess["expires_at"] <= oidc.ts_at(agents.clock()):
            raise HTTPException(409, "this conversation's relay session expired: start a new conversation")
        task = (n.store.open_tasks(sid) or [None])[0] if sess else None
        try:
            human = await n.human(request, task, n.settings.upstream_timeout)
            if human is None:
                raise oidc.OidcError("missing")
        except oidc.OidcError as e:              # sealed outside any task, like the model door (§17.2.7)
            hit = oidc.hit(e.code)
            rec = await n.seal(n.body(n.policy, "inference", model_id=cfg.agent_name, mode="enforce", decision="block",
                                      rule_hits=policy.rule_hits_json([hit]), agent_id=cfg.agent_id, principal=e.principal,
                                      input_hash=input_hash,
                                      ext=cj({"principal_error": e.code})))
            return JSONResponse(status_code=e.status, headers={"X-Sijill-Seq": str(rec["seq"])}, content={
                "error": {"type": "principal_refused", "code": hit}, "sijill": {"seq": rec["seq"], "rule_hits": [hit]}})
        if n.store.session(sid) is None:             # re-read: a concurrent first request may have created it
            n.store.add_session({"agent_session": sid, "agent_id": cfg.agent_id, "principal": human["principal"],
                                 "agent_auth": "relay", "principal_auth": "oidc", "remote_addr": "foundry-relay",
                                 "expires_at": oidc.ts_at(agents.clock() + n.policy.agents.session_ttl_s), "jti": ""})
        if task is None:
            x = {"intent_hash": conv_hash, "harness": "foundry", "session_id": conv_hash, "repo": "", "commit": "",
                 "lockfile_hash": "", "delegated_from": "", "agent_auth": "relay", "principal_auth": "oidc",
                 "agent_session": sid, "principal_claims": human["claims"]}

            def start() -> dict:
                if n.store.open_tasks(sid):
                    raise _Started
                n.agents.active(cfg.agent_id)
                return n.body(n.policy, "task_start", agent_id=cfg.agent_id, principal=human["principal"],
                              input_hash=conv_hash, ext=cj(x))
            try:
                task = await n.seal(start)
            except _Started:
                task = n.store.open_tasks(sid)[0]
        if task["principal"] != human["principal"]:
            raise HTTPException(403, "this conversation belongs to another principal")
        req, gated, data, rec = {k: v for k, v in payload.items() if k != "agent"}, {}, None, None
        req["agent"] = {"name": cfg.agent_name, "type": "agent_reference"}
        for turn in range(ROUNDS):
            last = turn == ROUNDS - 1
            rec, data = await round_trip(n, cfg, task, req, conv_hash, human, gated)
            if data is None:
                return rec
            answers = []
            for item in (i for i in data["output"] if isinstance(i, dict)):
                kind = str(item.get("type"))
                if kind == "mcp_call" and item.get("approval_request_id") in gated:
                    tool, server, qualified, label, _ = tool_of(item)
                    await result(n, task, gated.pop(item["approval_request_id"]), item, qualified, tool, server, label)
                elif kind == "mcp_approval_request":
                    seq, approve = await gate(n, task, rec, item, conv_hash, deny=last)
                    gated[item.get("id")] = seq
                    answers.append({"type": "mcp_approval_response", "approve": approve,
                                    "approval_request_id": item.get("id")})
                elif ran(kind):
                    await after_the_fact(n, task, rec, item, conv_hash)
            if not answers:
                break
            if last:                                 # the denials are sealed; Foundry's pending requests are never relayed
                return JSONResponse(status_code=502, headers={"X-Sijill-Seq": str(rec["seq"])}, content={
                    "error": {"type": "round_limit", "message": "Refused by Sijil: too many approval round trips"},
                    "sijill": {"seq": rec["seq"]}})
            req = {**{k: v for k, v in req.items() if k not in ("input", "conversation")},
                   "previous_response_id": data.get("id"), "input": answers}
        return JSONResponse(content=data, headers={"X-Sijill-Seq": str(rec["seq"])})

    return r
