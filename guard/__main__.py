"""sijil-guard command line: `python -m guard <command> --config .sijil/guard.yaml`.

  identity init [--repo DIR]        create the agent key (outside DIR) and register it
  session open                      prove the key (or present the OIDC token); write the state file
  task start --intent TEXT [--delegate] [--session-id ID]   print the task_seq
  task end --outcome OUTCOME
  serve --server NAME [--http HOST:PORT]   the MCP guard for one wrapped server (stdio unless --http)
  tools pin --server NAME           pin the server's tool definitions in the lockfile; seal the baseline
"""

import argparse
import asyncio
import os
import sys

from . import config, identity, serve, task
from .ledger import Ledger, Refused, Unreachable


def ledger_for(cfg) -> Ledger:
    return Ledger(cfg.url, cfg.token)


def update(cfg, ledger: Ledger, fn):
    """fn(state) on the shared state file under its lock (task.update)."""
    return task.update(task.state_path(cfg), cfg.agent_id, lambda: identity.open_session(ledger, cfg), fn)


def main(argv: list[str] | None = None, ledger: Ledger | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sijil-guard")
    ap.add_argument("command", nargs="+")
    ap.add_argument("--config", default=".sijil/guard.yaml")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--intent")
    ap.add_argument("--session-id", default="")
    ap.add_argument("--delegate", action="store_true")
    ap.add_argument("--outcome", default="completed")
    ap.add_argument("--admin-token-env", default="SIJILL_ADMIN_TOKEN")
    ap.add_argument("--principal-token-env", default="SIJIL_PRINCIPAL_TOKEN")
    ap.add_argument("--server")
    ap.add_argument("--http", default="")
    a = ap.parse_args(argv)
    cfg = config.load(a.config)
    ledger = ledger or ledger_for(cfg)
    cmd = " ".join(a.command)
    try:
        if cmd == "identity init":
            key = identity.ensure_key(cfg.key_path, a.repo)
            seq = identity.register(ledger, cfg.agent_id, key, cfg.registered_by or identity.local_principal(),
                                    cfg.display_name, os.environ.get(a.admin_token_env, ""))
            print(f"registered {cfg.agent_id} pubkey={identity.pubkey(key)} seq={seq}")
        elif cmd == "session open":
            state = update(cfg, ledger, lambda st: st)
            print(f"agent_session={state.agent_session} expires_at={state.expires_at}")
        elif cmd == "task start":
            seq = update(cfg, ledger, lambda st: task.start(
                ledger, st, a.intent if a.intent is not None else cfg.intent, cfg.harness, a.session_id,
                delegate=a.delegate, principal_token=os.environ.get(a.principal_token_env) or None,
                principal_header=cfg.principal_header))
            print(seq)
        elif cmd == "task end":
            r = update(cfg, ledger, lambda st: task.end(ledger, st, a.outcome))
            print(f"task_end seq={r['seq']} tool_calls={r['tool_calls']} blocked={r['blocked']}")
        elif cmd == "tools pin":
            seq, n = asyncio.run(serve.pin(cfg, a.server, ledger))
            print(f"pinned {n} tools of {a.server} in {cfg.lockfile}; integrity_baseline seq={seq}")
        elif cmd == "serve":
            asyncio.run(serve.run(cfg, a.server, ledger, a.http))
        else:
            ap.error(f"unknown command: {cmd}")
    except (Refused, Unreachable, ValueError, OSError) as e:
        print(f"sijil-guard: {e}", file=sys.stderr)
        return 3 if isinstance(e, Unreachable) else 1
    except (KeyError, TypeError) as e:                      # a 2xx body that is not what the ledger sends
        print(f"sijil-guard: unexpected reply from the Sijil ledger: {e!r}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
