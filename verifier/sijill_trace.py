#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Shameer Thaha
"""
Sijill trace: who caused seq N? Answered from the database alone (spec §4.5).

    python verifier/sijill_trace.py --db sijill.db --pubkey node.pub <seq> [--json] [--no-verify]

Imports only sijill_verify.py from this directory, nothing from `sijill/`. Verifies the chain first
and refuses to trace a failing one unless --no-verify, which marks every output line UNVERIFIED.
Exit 0 when the record exists (and the chain verified), 1 when the chain failed, 2 when the seq does
not exist, 3 for I/O errors.
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sijill_verify import read_rows, verify_full  # noqa: E402

IO_CODES = ("database_not_found", "database_unreadable", "public_key_unreadable")
MAX_DELEGATION = 16
INDENT = " " * 26


def load(db_path):
    """Every record by seq, with its ext parsed into `_ext` ({} when empty or unparseable)."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        recs = {}
        for r in read_rows(conn) or []:
            try:
                x = json.loads(r["ext"]) if r["ext"] else {}
            except ValueError:
                x = {}
            r["_ext"] = x if isinstance(x, dict) else {}
            recs[r["seq"]] = r
        return recs
    finally:
        conn.close()


def ref(value):
    return int(value) if isinstance(value, str) and value.isdigit() else None


def short(h, head=8, tail=4):
    return f"{h[:head]}…{h[-tail:]}" if h else "-"


def short_principal(p, n=8):
    scheme, _, rest = p.rpartition(":")
    return f"{scheme}:{rest[:n]}…" if p.startswith(("email:", "local:", "human:")) else (p or "-")


def newest_before(recs, n, type_):
    return max((s for s, r in recs.items() if s < n and r["type"] == type_), default=None)


def trace(recs, n):
    """The §4.5 walk as data: task and delegation, agent registry, causal path, children, packs in force."""
    rec = recs[n]
    task_seq = n if rec["type"] == "task_start" else ref(rec["task_seq"])
    task = recs.get(task_seq) if task_seq else None
    delegation, cur = [], task
    while cur is not None and len(delegation) < MAX_DELEGATION:
        d = ref(cur["_ext"].get("delegated_from"))
        if d is None or d not in recs:
            break
        delegation.append(d)
        cur = recs[d]
    task_end = min((s for s, r in recs.items() if r["type"] == "task_end" and ref(r["task_seq"]) == task_seq),
                   default=None) if task_seq else None
    agent_id = (task or rec)["agent_id"]
    upto = task_seq or n
    reg = [s for s, r in recs.items() if r["agent_id"] == agent_id and s <= upto and r["type"] == "agent_register"]
    life = [s for s, r in recs.items() if r["agent_id"] == agent_id and s <= n
            and r["type"] in ("agent_rotate", "agent_revoke")]
    path, todo = set(), [n]
    while todo:                                   # upward: parent_seq, plus the tool_results a call saw
        s = todo.pop()
        if s in path or s not in recs:
            continue
        path.add(s)
        todo += [p for p in [ref(recs[s]["parent_seq"])] if p]
        todo += [c for c in recs[s]["_ext"].get("context_seqs", []) if isinstance(c, int)]
    children, frontier = [], [(n, 0)]
    while frontier:                               # downward, breadth-first
        parent, depth = frontier.pop(0)
        for s, r in recs.items():
            if ref(r["parent_seq"]) == parent:
                children.append((s, depth))
                frontier.append((s, depth + 1))
    return {"seq": n, "task": task_seq if task else None, "task_end": task_end, "delegation": delegation,
            "agent_id": agent_id, "registered": reg[0] if reg else None,
            "rotations": [s for s in life if recs[s]["type"] == "agent_rotate"],
            "revoked": next((s for s in life if recs[s]["type"] == "agent_revoke"), None),
            "causal_chain": sorted(path), "children": [s for s, _ in children], "depths": dict(children),
            "rulepack_change": newest_before(recs, n, "rulepack_change"),
            "policy_change": newest_before(recs, n, "policy_change")}


def row(r, marked=False, depth=0):
    """One record in the causal chain or children list (fixed columns, spec §4.5)."""
    x, t = r["_ext"], r["type"]
    decision = "BLOCK" if r["decision"] == "block" else r["decision"]
    hits = json.loads(r["rule_hits"] or "[]")
    extra = []
    if t == "inference":
        names = ",".join(u.get("name", "?") for u in x.get("tool_uses", []) if isinstance(u, dict))
        detail = f"{r['model_digest'] or r['model_id'] or '-'}  tool_uses=[{names}]"
    elif t == "tool_call":
        name = f"mcp:{x.get('server')} {x.get('tool')}" if x.get("server") else str(x.get("tool", "-"))
        summary = x.get("summary") if isinstance(x.get("summary"), dict) else {}
        shown = [f"{k}={fmt(summary[k])}" for k in ("argv0", "packages", "env_refs", "hosts", "method",
                                                    "path_template") if k in summary]
        detail = f"{name}  " + (" ".join(shown) if shown else f"correlation={x.get('correlation', '-')}")
        if "context_labels" in x or "context_seqs" in x:
            extra.append(f"context_labels={fmt(x.get('context_labels', []))} "
                         f"context_seqs={fmt(x.get('context_seqs', []))}")
        if isinstance(x.get("aip"), dict):
            meta = x.get("aip_meta", {})
            extra.append(f"agent_sig=unchecked (AIP, signer={meta.get('signer', '-')}, "
                         f"nonce={str(x['aip'].get('nonce', ''))[:8]}…)")
    elif t == "tool_result":
        detail = f"source={r['source_label']}  bytes={x.get('bytes', '-')}"
        if x.get("exec_hints"):
            detail += f"  exec_hints={fmt(x['exec_hints'])}"
        if hits:
            detail += f"  rules={fmt(hits)}"
    elif t == "egress":
        detail = f"{x.get('host', '-')}:{x.get('port', '-')}  {x.get('proto', '-')}  allowed_by={x.get('allowed_by', '-')}"
    else:
        detail = f"rules={fmt(hits)}" if hits else ""
    pad = "  " * depth
    lines = [f"{'> ' if marked else '  '}{pad}{r['seq']:<4}{t:<13}{decision:<7}{detail}".rstrip()]
    return lines + [INDENT + pad + e for e in extra]


def fmt(v):
    return "[" + ", ".join(str(i) for i in v) + "]" if isinstance(v, list) else str(v)


def render(recs, tr, chain):
    rec, n = recs[tr["seq"]], tr["seq"]
    hits = json.loads(rec["rule_hits"] or "[]")
    out = [f"SIJIL TRACE seq={n}  node={rec['node_id']}  chain={chain}",
           f"record    {rec['type']}  {rec['ts']}  decision={rec['decision']} mode={rec['mode']}",
           f"          rule_hits={', '.join(hits) or '-'}"]
    rc = recs.get(tr["rulepack_change"]) if tr["rulepack_change"] else None
    pack = f" (seq {rc['seq']}, {rc['_ext'].get('rulepack_id', '?')} {rc['_ext'].get('version', '?')})" if rc else ""
    out += [f"          rulepack={short(rec['rulepack_hash'])}{pack}  "
            f"policy={short(rec['policy_hash'])} ({rec['approval_ref'] or '-'})", ""]
    if tr["task"]:
        t, x = recs[tr["task"]], recs[tr["task"]]["_ext"]
        end = recs.get(tr["task_end"]) if tr["task_end"] else None
        outcome = f"outcome={end['_ext'].get('outcome', '?')} (task_end seq={end['seq']})" if end else "outcome=open"
        out += [f"task      seq={t['seq']}  started {t['ts']}  {outcome}",
                f"          intent_hash={str(x.get('intent_hash', ''))[:16]}…  repo={x.get('repo') or '-'}  "
                f"commit={str(x.get('commit') or '-')[:8]}",
                f"          harness={x.get('harness', '-')}  session={str(x.get('session_id', ''))[:8]}…  "
                f"lockfile={str(x.get('lockfile_hash') or '-')[:8]}…",
                f"          delegated_from={' > '.join(map(str, tr['delegation'])) or '-'}  "
                f"agent_auth={x.get('agent_auth', '-')}  principal_auth={x.get('principal_auth', '-')}"]
    else:
        out.append("task      -  (record is outside any task)")
    out.append(f"agent     {tr['agent_id'] or '-'}")
    if tr["registered"]:
        reg = recs[tr["registered"]]
        x = reg["_ext"]
        out.append(f"          registered seq={reg['seq']} ({reg['ts']}) by {short_principal(reg['principal'])}  "
                   f"key={short(x.get('agent_pubkey', ''))}")
        if x.get("logical_agent_id"):
            out.append(f"          logical={x['logical_agent_id']} responsible={x.get('responsible_entity', '-')} "
                       f"lifecycle={x.get('lifecycle_class', '-')}")
        revoked = f"yes (seq {tr['revoked']})" if tr["revoked"] else "no"
        out.append(f"          rotations={len(tr['rotations'])}  revoked={revoked} (at seq {n})")
    elif tr["agent_id"]:
        out.append(f"          no agent_register at or before seq {tr['task'] or n}")
    p = (recs[tr["task"]] if tr["task"] else rec)["principal"]
    if p.startswith(("email:", "local:", "human:")):
        out.append(f"principal {short_principal(p, 16)}  (hashed; display name available only from the ledger's "
                   f"principal_index)")
    else:
        out.append(f"principal {p or '-'}")
    out += ["", "causal chain (parent_seq, oldest first)"]
    for s in tr["causal_chain"]:
        out += row(recs[s], marked=s == n)
    if tr["children"]:
        out.append(f"children of {n}:")
        for s in tr["children"]:
            out += row(recs[s], depth=tr["depths"][s] + 1)
    else:
        out.append(f"children of {n}: none")
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description="Trace who caused a Sijill record.")
    parser.add_argument("--db", required=True)
    parser.add_argument("--pubkey", required=True)
    parser.add_argument("seq", type=int)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-verify", action="store_true", help="trace a chain that does not verify")
    args = parser.parse_args(argv)

    chain, verified = "UNVERIFIED", None
    if not args.no_verify:
        res = verify_full(args.db, args.pubkey)
        if res["code"] in IO_CODES:
            print(res["line"], file=sys.stderr)
            return 3
        if not res["ok"]:
            print(f"SIJIL TRACE refused: chain {res['line']} (use --no-verify to trace anyway)", file=sys.stderr)
            return 1
        chain, verified = " ".join(res["line"].split()[:2]), True
    try:
        recs = load(args.db)
    except (sqlite3.Error, OSError) as e:
        print(f"database unreadable: {e}", file=sys.stderr)
        return 3
    if args.seq not in recs:
        print(f"no record with seq {args.seq}", file=sys.stderr)
        return 2
    tr = trace(recs, args.seq)
    if args.json:
        involved = {args.seq, *tr["causal_chain"], *tr["children"], *tr["delegation"],
                    *(s for s in (tr["task"], tr["task_end"], tr["registered"], tr["revoked"],
                                  tr["rulepack_change"], tr["policy_change"]) if s), *tr["rotations"]}
        tr.pop("depths")
        print(json.dumps({**tr, "chain": chain, "verified": verified,
                          "records": {str(s): {k: v for k, v in recs[s].items() if k != "_ext"}
                                      for s in sorted(involved)}}, sort_keys=True, ensure_ascii=False))
    else:
        lines = render(recs, tr, chain)
        print("\n".join(("UNVERIFIED " + ln) if args.no_verify else ln for ln in lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
