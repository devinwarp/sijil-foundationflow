"""Autonomy budgets (spec §17.6): per-task ceilings counted by the ledger over the task's sealed records, prices
for model spend, and the `budget` object sealed on every record a budget evaluated, so that the verifier can
recount it (checks W-W2). BSL.

The ledger evaluates, because it holds the counters and the task's facts; the guard asks before a tool call
runs and enforces the answer, and `/seal` counts again under the seal lock.
"""

import fnmatch
import json

from fastapi import APIRouter, Depends, HTTPException, Request

from . import agents, policy

TYPES = ("tool_call", "egress", "inference")


def facts(task: dict) -> dict:
    """The task_start fields a budget's `match` may name (§17.6.1)."""
    x = json.loads(task["ext"]) if task["ext"] else {}
    p = task["principal"]
    return {"harness": x.get("harness", ""), "agent_id": task["agent_id"],
            "logical_agent_id": x.get("logical_agent_id", ""),
            "principal_issuer": p.split(":")[1] if p.startswith("human:") else ""}


def used(store, task_seq: int) -> tuple[list[str], set[str], int]:
    """(qualified names of executed tool calls, distinct allowed egress hosts, model spend) over the task so far."""
    calls, hosts, spend = [], set(), 0
    for r in store.in_task(task_seq):
        x = json.loads(r["ext"]) if r["ext"] else {}
        if r["type"] == "tool_call" and r["decision"] != "block":
            calls.append(x.get("qualified", ""))
        elif r["type"] == "egress" and r["decision"] != "block":
            hosts.add(str(x.get("host")).lower())
        elif r["type"] == "inference" and type(x.get("cost_micro")) is int:
            spend += x["cost_micro"]
    return calls, hosts, spend


def evaluate(pack, store, task: dict, type_: str, qualified: str = "", host: str = "") -> tuple[dict, list[str], str]:
    """(budget object for the record, budget:<id>:<metric> hits that fail admission, on_exceed of those hits:
    block when any failing budget says block, else confirm; "" when nothing fails). §17.6.2."""
    if pack is None or not pack.budgets or task is None:
        return {}, [], ""
    host = str(host).lower()
    f, (calls, hosts, spend) = facts(task), used(store, task["seq"])
    obj, hits, block = {}, [], False
    for b in pack.budgets:
        if not all(f[k] in v for k, v in b.match.items()):
            continue
        metrics = {}
        if type_ == "tool_call":
            if "tool_calls" in b.limits:
                metrics["tool_calls"] = (b.limits["tool_calls"], len(calls), True)
            for g, limit in b.limits.get("tool_calls_by", {}).items():
                if fnmatch.fnmatchcase(qualified, g):
                    metrics[f"tool_calls_by:{g}"] = (limit, sum(fnmatch.fnmatchcase(q, g) for q in calls), True)
        elif type_ == "egress" and "egress_hosts" in b.limits:
            metrics["egress_hosts"] = (b.limits["egress_hosts"], len(hosts), host not in hosts)
        elif type_ == "inference" and "model_spend_micro" in b.limits:
            metrics["model_spend_micro"] = (b.limits["model_spend_micro"], spend, False)
        for metric, (limit, n, counted) in metrics.items():
            admitted = n + 1 <= limit if counted else (n < limit if metric == "model_spend_micro" else True)
            if not admitted:
                hits.append(f"budget:{b.id}:{metric}")
                block = block or b.on_exceed == "block"
        if metrics:
            obj[b.id] = {m: {"limit": limit, "used": n} for m, (limit, n, _) in metrics.items()}
    return obj, hits, ("block" if block else "confirm") if hits else ""


def stamp(n, task: dict, body: dict, x: dict, hits: list[str], granted: bool) -> dict:
    """/seal, under the lock: the ledger's budget object replaces any sent, and the budget hits the guard sent
    must be exactly the failing ones, enforced by a block or a granted approval (W1). 409: count again."""
    obj, exceeded, _ = evaluate(n.rulepack, n.store, task, body["type"], x.get("qualified", ""), x.get("host", ""))
    if sorted(h for h in hits if h.startswith("budget:")) != sorted(exceeded) or (
            exceeded and body["decision"] != "block" and not granted):
        raise HTTPException(409, "budget changed: check the budget again")
    x = {k: v for k, v in x.items() if k != "budget"}
    return {**body, "ext": agents.cj({**x, **({"budget": obj} if obj else {})})}


def inference(n, task: dict, body: dict) -> dict:
    """The model door, under the lock: model spend is post-paid (used < limit), and an inference that no longer
    passes when it is sealed is sealed blocked (a concurrent call of the task spent first)."""
    obj, exceeded, _ = evaluate(n.rulepack, n.store, task, "inference")
    x = {k: v for k, v in (json.loads(body["ext"]) if body["ext"] else {}).items() if k != "budget"}
    hits = [h for h in json.loads(body["rule_hits"]) if not h.startswith("budget:")] + exceeded
    return {**body, "ext": agents.cj({**x, **({"budget": obj} if obj else {})}) if x or obj else "",
            "rule_hits": policy.rule_hits_json(hits), **({"decision": "block", "mode": "enforce"} if exceeded else {})}


def cost(pack, model_digest: str, usage) -> dict:
    """usage, cost_micro and price_rule for an answered inference (§17.6.2); {} for an unpriced model."""
    price = pack.price(model_digest) if pack else None
    if price is None:
        return {}
    if not (isinstance(usage, dict)
            and all(type(usage.get(k)) is int and usage[k] >= 0 for k in ("input_tokens", "output_tokens"))):
        return {"cost_micro": price["missing_usage_cost_micro"], "price_rule": price["id"]}
    return {"usage": usage, "price_rule": price["id"],
            "cost_micro": (usage["input_tokens"] * price["input_per_mtok_micro"]
                           + usage["output_tokens"] * price["output_per_mtok_micro"]) // 1_000_000}


def router() -> APIRouter:
    r = APIRouter()

    @r.get("/api/agent/budget")
    async def check(request: Request, type: str, qualified: str = "", host: str = "",
                    sess: dict = Depends(agents.require_session)):
        """The admission test for the record the guard is about to seal (§17.6.2)."""
        n = request.app.state.node
        if type not in TYPES[:2]:
            raise HTTPException(400, "type must be tool_call or egress")
        task = agents.task_for(n, sess, request.headers.get("x-sijil-task-seq"))
        obj, exceeded, on_exceed = evaluate(n.rulepack, n.store, task, type, qualified, host)
        return {"budget": obj, "exceeded": exceeded, "on_exceed": on_exceed}

    return r
