"""`.sijil/guard.yaml` (spec §5.2): the parts this build reads. Unknown sections are refused, not ignored, so a
setting the guard does not honour is never mistaken for one it does."""

import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

PRINCIPAL = re.compile(r"oidc:[a-z0-9.-]+:\S+|email:[0-9a-f]{64}|local:[0-9a-f]{64}|human:[a-z0-9-]{1,32}:[0-9a-f]{64}")
SECTIONS = {"version", "sijil", "identity", "task", "state_path", "repo", "rulepack", "egress", "context_window",
            "correlation", "results"}
UNICODE_ACTIONS = ("strip", "block", "record")


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
    repo: str                     # paths in commands are shown relative to this (spec §7.2)
    rulepack: str
    egress_pins: str
    context_window: str           # session | turn (spec §5.5)
    require_parent: bool          # spec §5.4: false seals orphans with correlation none
    max_result_bytes: int
    invisible_unicode: str        # strip | block | record (spec §7.3)


def _expand(p: str) -> str:
    return os.path.expanduser(os.path.expandvars(p)) if p else ""


def load(path: str) -> Config:
    doc = yaml.safe_load(Path(path).read_bytes()) or {}
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise ValueError(f"{path}: version: 1 is required")
    unknown = set(doc) - SECTIONS
    if unknown:
        raise ValueError(f"{path}: sections {sorted(unknown)} are not supported by this guard")
    sijil, ident, task = doc.get("sijil") or {}, doc.get("identity") or {}, doc.get("task") or {}
    if sijil.get("on_unreachable", "closed") != "closed":
        raise ValueError(f"{path}: sijil.on_unreachable must be closed (the open mode is not built)")
    if not sijil.get("url") or not ident.get("agent_id"):
        raise ValueError(f"{path}: sijil.url and identity.agent_id are required")
    auth = ident.get("auth", "key")
    if auth not in ("key", "oidc"):
        raise ValueError(f"{path}: identity.auth must be key or oidc (mtls is not built)")
    if auth == "key" and not ident.get("key_path"):
        raise ValueError(f"{path}: identity.key_path is required for auth: key")
    corr, res = doc.get("correlation") or {}, doc.get("results") or {}
    if doc.get("context_window", "session") not in ("session", "turn"):
        raise ValueError(f"{path}: context_window must be session or turn")
    if res.get("invisible_unicode", "strip") not in UNICODE_ACTIONS or type(corr.get("require_parent", True)) is not bool:
        raise ValueError(f"{path}: results.invisible_unicode must be strip, block or record; "
                         "correlation.require_parent a boolean")
    if type(res.get("max_result_bytes", 262144)) is not int or res.get("max_result_bytes", 262144) < 1024:
        raise ValueError(f"{path}: results.max_result_bytes must be an integer of at least 1024")
    registered_by = ident.get("registered_by", "")
    if registered_by and not PRINCIPAL.fullmatch(registered_by):
        raise ValueError(f"{path}: identity.registered_by must be a principal (oidc:, email:, local:, human:)")
    return Config(path=str(path), url=sijil["url"], token=os.environ.get(sijil.get("token_env", "SIJIL_TOKEN"), ""),
                  agent_id=ident["agent_id"], auth=auth, key_path=_expand(ident.get("key_path", "")),
                  registered_by=registered_by, display_name=ident.get("display_name", ""),
                  oidc_token_env=ident.get("oidc_token_env", "SIJIL_OIDC_TOKEN"),
                  state_path=_expand(doc.get("state_path", "")), intent=task.get("intent", ""),
                  harness=task.get("harness", "other"),
                  principal_header=task.get("principal_header", "X-Sijil-Principal-Token"),
                  repo=os.path.realpath(_expand(doc.get("repo", "")) or os.getcwd()),
                  rulepack=_expand(doc.get("rulepack", "")), egress_pins=_expand((doc.get("egress") or {}).get("pins", "")),
                  context_window=doc.get("context_window", "session"),
                  require_parent=corr.get("require_parent", True),
                  max_result_bytes=res.get("max_result_bytes", 262144),
                  invisible_unicode=res.get("invisible_unicode", "strip"))
