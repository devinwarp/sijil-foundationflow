"""`.sijil/guard.yaml` (spec §5.2): the parts this build reads. Unknown sections are refused, not ignored, so a
setting the guard does not honour is never mistaken for one it does."""

import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

PRINCIPAL = re.compile(r"oidc:[a-z0-9.-]+:\S+|email:[0-9a-f]{64}|local:[0-9a-f]{64}|human:[a-z0-9-]{1,32}:[0-9a-f]{64}")
SECTIONS = {"version", "sijil", "identity", "task", "state_path"}
KEYS = {"sijil": {"url", "token_env", "on_unreachable"},
        "identity": {"agent_id", "auth", "key_path", "registered_by", "display_name", "oidc_token_env"},
        "task": {"intent", "harness", "principal_header"}}


@dataclass(frozen=True)
class Config:
    path: str
    url: str
    token: str                    # X-Sijil-Token, read from the env var named by sijil.token_env
    agent_id: str
    auth: str                     # key | oidc
    key_path: str
    registered_by: str
    display_name: str
    oidc_token_env: str
    state_path: str
    intent: str
    harness: str
    principal_header: str


def _path(p: str, name: str, base: Path) -> str:
    """${VAR} and ~ expanded, then refused if either was left behind; relative to the config file's directory."""
    if not p:
        return ""
    out = os.path.expanduser(os.path.expandvars(p))
    if "$" in out or out.startswith("~"):
        raise ValueError(f"{name}: {p!r} names an unset variable or an unknown home directory")
    return str(base / out)


def _section(doc: dict, name: str, path: str) -> dict:
    sec = doc.get(name) or {}
    if not isinstance(sec, dict):
        raise ValueError(f"{path}: {name}: must be a mapping")
    unknown = set(sec) - KEYS[name]
    if unknown:
        raise ValueError(f"{path}: {name}.{sorted(unknown)[0]} is not supported by this guard")
    return sec


def load(path: str) -> Config:
    doc = yaml.safe_load(Path(path).read_bytes()) or {}
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise ValueError(f"{path}: version: 1 is required")
    unknown = set(doc) - SECTIONS
    if unknown:
        raise ValueError(f"{path}: sections {sorted(unknown)} are not supported by this guard")
    sijil, ident, task = (_section(doc, n, path) for n in ("sijil", "identity", "task"))
    if sijil.get("on_unreachable", "closed") != "closed":
        raise ValueError(f"{path}: sijil.on_unreachable must be closed (the open mode is not built)")
    if not sijil.get("url") or not ident.get("agent_id"):
        raise ValueError(f"{path}: sijil.url and identity.agent_id are required")
    auth = ident.get("auth", "key")
    if auth not in ("key", "oidc"):
        raise ValueError(f"{path}: identity.auth must be key or oidc (mtls is not built)")
    if auth == "key" and not ident.get("key_path"):
        raise ValueError(f"{path}: identity.key_path is required for auth: key")
    registered_by = ident.get("registered_by", "")
    if registered_by and not PRINCIPAL.fullmatch(registered_by):
        raise ValueError(f"{path}: identity.registered_by must be a principal (oidc:, email:, local:, human:)")
    token_env = sijil.get("token_env")
    if token_env and not os.environ.get(token_env):
        raise ValueError(f"{path}: sijil.token_env names {token_env}, which is unset or empty")
    base = Path(path).resolve().parent
    return Config(path=str(path), url=sijil["url"], token=os.environ.get(token_env or "SIJIL_TOKEN", ""),
                  agent_id=ident["agent_id"], auth=auth, key_path=_path(ident.get("key_path", ""), "identity.key_path", base),
                  registered_by=registered_by, display_name=ident.get("display_name", ""),
                  oidc_token_env=ident.get("oidc_token_env", "SIJIL_OIDC_TOKEN"),
                  state_path=_path(doc.get("state_path", ""), "state_path", base), intent=task.get("intent", ""),
                  harness=task.get("harness", "other"),
                  principal_header=task.get("principal_header", "X-Sijil-Principal-Token"))
