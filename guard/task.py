"""Tasks (spec §5.9) and the per-session state file that lets separate processes share one agent session.

The state file holds the session (a bearer credential for its lifetime) and the stack of open tasks, newest
last; a delegated task sits above the task it was delegated from. It is written 0600 outside the repo.
"""

import fcntl
import json
import os
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .canon import sha256_hex
from .ledger import Ledger


@dataclass
class State:
    agent_session: str
    agent_id: str
    principal: str
    expires_at: str
    tasks: list[int] = field(default_factory=list)

    @property
    def task_seq(self) -> int | None:
        return self.tasks[-1] if self.tasks else None

    def headers(self) -> dict:
        """What the agent puts on its model calls so they land in this task (spec §5.4, M2b chat binding)."""
        return {"X-Sijil-Agent-Session": self.agent_session,
                **({"X-Sijil-Task-Seq": str(self.task_seq)} if self.task_seq else {})}


def state_path(cfg) -> Path:
    if cfg.state_path:
        return Path(cfg.state_path)
    base = os.environ.get("XDG_RUNTIME_DIR")
    root = Path(base) / "sijil" if base else Path.home() / ".sijil" / "run"
    return root / (cfg.agent_id.rstrip("/").rsplit("/", 1)[-1] + ".json")


def save(state: State, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(asdict(state), f)
    os.replace(tmp, path)


def load(path: Path, agent_id: str) -> State | None:
    """The saved session, or None when there is none, it is another agent's, or it has expired."""
    try:
        s = State(**json.loads(path.read_text()))
    except (OSError, ValueError, TypeError):
        return None
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return s if s.agent_id == agent_id and s.expires_at > now else None


def from_session(sess: dict, agent_id: str) -> State:
    return State(sess["agent_session"], agent_id, sess["principal"], sess["expires_at"])


@contextmanager
def locked(path: Path):
    """An exclusive lock beside the state file, so every guard of one agent shares one agent session."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path.with_suffix(".lock"), "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def shared(path: Path, agent_id: str, open_session) -> State:
    """The saved session if it is still valid, else a new one from open_session() (saved for the others)."""
    with locked(path):
        state = load(path, agent_id)
        if state is None:
            state = from_session(open_session(), agent_id)
            save(state, path)
        return state


def start_task(ledger: Ledger, agent_session: str, intent: str, harness: str, session_id: str = "",
               delegated_from: str = "", principal_token: str | None = None,
               principal_header: str = "X-Sijil-Principal-Token", repo: str = "", commit: str = "") -> int:
    """Seal task_start; the ledger stamps identity and auth from the session (spec §5.8.1)."""
    body = {"intent_hash": sha256_hex(intent.encode()), "harness": harness, "session_id": session_id,
            "repo": repo, "commit": commit, "lockfile_hash": "", "delegated_from": delegated_from}
    headers = {principal_header: principal_token} if principal_token else {}
    return ledger.call("POST", "/api/agent/task/start", agent_session, json=body, headers=headers)["seq"]


def end_task(ledger: Ledger, agent_session: str, task_seq: int, outcome: str) -> dict:
    """Seal task_end; the ledger computes the counts (spec §2.4.11)."""
    return ledger.call("POST", "/api/agent/task/end", agent_session,
                       json={"task_seq": str(task_seq), "outcome": outcome})


def start(ledger: Ledger, state: State, intent: str, harness: str, session_id: str = "", delegate: bool = False,
          principal_token: str | None = None, principal_header: str = "X-Sijil-Principal-Token") -> int:
    """Start a task in the state file's session; with `delegate`, delegated from the current one (spec §5.9)."""
    seq = start_task(ledger, state.agent_session, intent, harness, session_id,
                     str(state.task_seq) if delegate and state.task_seq else "", principal_token, principal_header)
    state.tasks = [*(state.tasks if delegate else []), seq]
    return seq


def end(ledger: Ledger, state: State, outcome: str) -> dict:
    if state.task_seq is None:
        raise ValueError("no open task in this state file")
    r = end_task(ledger, state.agent_session, state.task_seq, outcome)
    state.tasks.pop()
    return r
