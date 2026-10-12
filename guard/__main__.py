"""sijil-guard command line: `python -m guard <command> --config .sijil/guard.yaml`.

  identity init [--repo DIR]        create the agent key (outside DIR) and register it
  session open                      prove the key (or present the OIDC token); write the state file
  task start --intent TEXT [--delegate] [--session-id ID]   print the task_seq
  task end --outcome OUTCOME
"""

import argparse
import os
import sys

from . import config, identity, task
from .ledger import Ledger, Refused, Unreachable


def ledger_for(cfg) -> Ledger:
    return Ledger(cfg.url, cfg.token)


def session(cfg, ledger: Ledger) -> task.State:
    return task.shared(task.state_path(cfg), cfg.agent_id, lambda: identity.open_session(ledger, cfg))


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
    a = ap.parse_args(argv)
    cfg = config.load(a.config)
    ledger = ledger or ledger_for(cfg)
    cmd = " ".join(a.command)
    try:
        if cmd == "identity init":
            key = identity.create_key(cfg.key_path, a.repo)
            seq = identity.register(ledger, cfg.agent_id, key, cfg.registered_by or identity.local_principal(),
                                    cfg.display_name, os.environ.get(a.admin_token_env, ""))
            print(f"registered {cfg.agent_id} pubkey={identity.pubkey(key)} seq={seq}")
        elif cmd == "session open":
            state = session(cfg, ledger)
            print(f"agent_session={state.agent_session} expires_at={state.expires_at}")
        elif cmd == "task start":
            state = session(cfg, ledger)
            seq = task.start(ledger, state, a.intent if a.intent is not None else cfg.intent, cfg.harness,
                             a.session_id, delegate=a.delegate,
                             principal_token=os.environ.get(a.principal_token_env) or None,
                             principal_header=cfg.principal_header)
            task.save(state, task.state_path(cfg))
            print(seq)
        elif cmd == "task end":
            state = session(cfg, ledger)
            r = task.end(ledger, state, a.outcome)
            task.save(state, task.state_path(cfg))
            print(f"task_end seq={r['seq']} tool_calls={r['tool_calls']} blocked={r['blocked']}")
        else:
            ap.error(f"unknown command: {cmd}")
    except (Refused, Unreachable, ValueError, OSError) as e:
        print(f"sijil-guard: {e}", file=sys.stderr)
        return 3 if isinstance(e, Unreachable) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
