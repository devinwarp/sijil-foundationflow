"""The guard's side of the tests: a ledger on tmp_path with the starter pack, and a guard.yaml for it."""

import shutil
from pathlib import Path

from agentkit import AGENT, OPEN_POLICY, TOKEN, agent_node
from conftest import ROOT, stub_model
from guard import config, identity, task
from guard.ledger import Ledger


def ledger_node(tmp_path, handler=stub_model, policy_text=OPEN_POLICY, **overrides):
    """A ledger with the starter pack in force; (TestClient, Settings). Enter with `with client:`."""
    shutil.copy(ROOT / "rulepacks" / "starter.yaml", tmp_path / "starter.yaml")
    return agent_node(tmp_path, handler, policy_text, rulepack_path=str(tmp_path / "starter.yaml"), **overrides)


def guard_yaml(tmp_path, extra: str = "") -> Path:
    """repo/.sijil/guard.yaml; the agent key under home/, outside the repo; the state file under run/."""
    repo = tmp_path / "repo"
    (repo / ".sijil").mkdir(parents=True, exist_ok=True)
    path = repo / ".sijil" / "guard.yaml"
    path.write_text(f"""version: 1
sijil:
  url: http://testserver
  token_env: GUARD_TEST_TOKEN
identity:
  agent_id: {AGENT}
  auth: key
  key_path: {tmp_path}/home/.sijil/agent.key
  registered_by: local:{"a" * 64}
  display_name: Case agent
state_path: {tmp_path}/run/case-agent.json
task:
  intent: Case MOI-2026-004211
  harness: http-agent
""" + extra)
    return path


def ledger_of(client) -> Ledger:
    return Ledger("http://testserver", TOKEN, http=client)


def guard_session(tmp_path, client, extra: str = ""):
    """Register the agent, open its session and a task, as `sijil-guard task start` does: (cfg, State)."""
    cfg = config.load(str(guard_yaml(tmp_path, f"rulepack: {tmp_path}/starter.yaml\nrepo: {tmp_path}/repo\n" + extra)))
    ledger = ledger_of(client)
    key = identity.create_key(cfg.key_path, cfg.repo)
    identity.register(ledger, cfg.agent_id, key, cfg.registered_by)
    state = task.from_session(identity.open_session(ledger, cfg, key), cfg.agent_id)
    task.start(ledger, state, cfg.intent, cfg.harness, "conv-1")
    return cfg, state
