"""`.sijil/guard.yaml` (spec §5.2): the parts this build reads. Unknown sections are refused, not ignored, so a
setting the guard does not honour is never mistaken for one it does."""

import fnmatch
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import yaml

PRINCIPAL = re.compile(r"oidc:[a-z0-9.-]+:\S+|email:[0-9a-f]{64}|local:[0-9a-f]{64}|human:[a-z0-9-]{1,32}:[0-9a-f]{64}")
SECTIONS = {"version", "sijil", "identity", "task", "state_path", "repo", "rulepack", "egress", "context_window",
            "correlation", "results", "servers", "allowed_command_dirs", "mcp"}
KEYS = {"sijil": {"url", "token_env", "on_unreachable"},
        "identity": {"agent_id", "auth", "key_path", "registered_by", "display_name", "oidc_token_env"},
        "task": {"intent", "harness", "principal_header"},
        "egress": {"pins"}, "correlation": {"require_parent"}, "results": {"max_result_bytes", "invisible_unicode"}, "mcp": {"allowed_origins", "tools_token_env", "tls_cert", "tls_key"}}
TOOLS_KEYS = {"allow", "deny"}
SERVER_KEYS = {"name", "transport", "command", "args", "env", "url", "headers", "label", "tools", "command_arg"}
SERVER_NAME = re.compile(r"[a-z0-9_-]{1,32}")                      # source_label mcp:<name> (spec §17.1)
LABELS = ("telemetry", "web", "memory", "repo")                    # `user` cannot be assigned (spec §5.2)
COMMAND_DIRS = ("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "~/.nvm/versions/*/bin", "node_modules/.bin")
UNICODE_ACTIONS = ("strip", "block", "record")


@dataclass(frozen=True)
class Server:
    name: str
    transport: str                # stdio | http
    command: str                  # stdio: resolved, absolute
    args: tuple
    env: dict
    url: str
    headers: dict
    label: str                    # source_label of its results: mcp:<name> or the override
    allow: tuple                  # tools.allow / tools.deny globs on the bare tool name
    deny: tuple
    command_arg: str              # the argument that carries a shell command (spec §8.1)

    def allowed(self, tool: str) -> bool:
        """Allow wins over deny; with no lists every tool is allowed (spec §5.2)."""
        if any(fnmatch.fnmatchcase(tool, g) for g in self.allow):
            return True
        return not self.deny or not any(fnmatch.fnmatchcase(tool, g) for g in self.deny)


def _env(value: str) -> str:
    """${NAME} from the guard's environment; an unset name is an error, never an empty credential."""
    def sub(m):
        if m.group(1) not in os.environ:
            raise ValueError(f"${{{m.group(1)}}} is not set in the guard's environment")
        return os.environ[m.group(1)]
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", sub, str(value))


def _command_ok(command: str, repo: str, dirs) -> str:
    """The command as found on PATH, refused when its real path (symlinks resolved) is outside the repo and
    allowed_command_dirs: a config written into ~/.kiro cannot make the guard launch from there."""
    found = shutil.which(command)
    if not found:
        raise ValueError(f"server command {command!r} not found on PATH")
    real = os.path.realpath(found)
    roots = [repo, *(os.path.expanduser(d) if d.startswith(("/", "~")) else os.path.join(repo, d) for d in dirs)]
    if any(fnmatch.fnmatchcase(os.path.dirname(real), r) or real.startswith(r.rstrip("/") + "/") for r in roots):
        return real
    raise ValueError(f"server command {real} is outside the repo and allowed_command_dirs")


def _server(d: dict, repo: str, dirs) -> Server:
    name = d.get("name", "")
    if not isinstance(name, str) or not SERVER_NAME.fullmatch(name):
        raise ValueError(f"server name {name!r} must match [a-z0-9_-]{{1,32}}")
    if set(d) - SERVER_KEYS:
        raise ValueError(f"server {name}: {sorted(set(d) - SERVER_KEYS)[0]} is not supported by this guard")
    transport, label = d.get("transport", "stdio"), d.get("label", "")
    if transport not in ("stdio", "http") or (label and label not in LABELS):
        raise ValueError(f"server {name}: transport stdio|http; label one of {LABELS}")
    tools = d.get("tools") or {}
    if not isinstance(tools, dict) or set(tools) - TOOLS_KEYS or not all(
            isinstance(tools.get(k) or [], list) and all(isinstance(g, str) for g in tools.get(k) or []) for k in TOOLS_KEYS):
        raise ValueError(f"server {name}: tools takes allow and deny, each a list of globs")
    for key in ("env", "headers"):
        if not isinstance(d.get(key) or {}, dict):
            raise ValueError(f"server {name}: {key} must be a mapping")
    if not isinstance(d.get("args") or [], list):
        raise ValueError(f"server {name}: args must be a list")
    if transport == "stdio" and not d.get("command") or transport == "http" and not d.get("url"):
        raise ValueError(f"server {name}: stdio needs command, http needs url")
    return Server(name=name, transport=transport,
                  command=_command_ok(d["command"], repo, dirs) if transport == "stdio" else "",
                  args=tuple(str(a) for a in d.get("args") or ()),
                  env={k: _env(v) for k, v in (d.get("env") or {}).items()}, url=d.get("url", ""),
                  headers={k: _env(v) for k, v in (d.get("headers") or {}).items()},
                  label=label or f"mcp:{name}", allow=tuple(tools.get("allow") or ()),
                  deny=tuple(tools.get("deny") or ()), command_arg=d.get("command_arg", "command"))


def _servers(doc: dict, path: str, repo: str) -> tuple:
    dirs = doc.get("allowed_command_dirs", COMMAND_DIRS)
    items = doc.get("servers") or ()
    if not isinstance(dirs, (list, tuple)) or not isinstance(items, (list, tuple)):
        raise ValueError(f"{path}: servers and allowed_command_dirs must be lists")
    try:
        servers = tuple(_server(d if isinstance(d, dict) else {}, repo, dirs) for d in items)
    except (TypeError, AttributeError) as e:
        raise ValueError(f"{path}: servers: malformed entry ({e})") from None
    if len({s.name for s in servers}) != len(servers):
        raise ValueError(f"{path}: server names must be unique")
    return servers


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
    servers: tuple
    allowed_origins: tuple        # Origins besides loopback that the HTTP door accepts (MCP 2025-06-18)
    tools_token: str              # X-Sijil-Tools-Token the HTTP door requires (mcp.tools_token_env); "" is none
    tls_cert: str                 # serve --http off loopback needs both, and the token
    tls_key: str


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
    sijil, ident, task, egress, corr, res, mcp = (_section(doc, n, path) for n in
                                                  ("sijil", "identity", "task", "egress", "correlation", "results", "mcp"))
    if sijil.get("on_unreachable", "closed") != "closed":
        raise ValueError(f"{path}: sijil.on_unreachable must be closed (the open mode is not built)")
    if not sijil.get("url") or not ident.get("agent_id"):
        raise ValueError(f"{path}: sijil.url and identity.agent_id are required")
    auth = ident.get("auth", "key")
    if auth not in ("key", "oidc"):
        raise ValueError(f"{path}: identity.auth must be key or oidc (mtls is not built)")
    if auth == "key" and not ident.get("key_path"):
        raise ValueError(f"{path}: identity.key_path is required for auth: key")
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
    token_env = sijil.get("token_env")
    if token_env and not os.environ.get(token_env):
        raise ValueError(f"{path}: sijil.token_env names {token_env}, which is unset or empty")
    base = Path(path).resolve().parent
    repo = os.path.realpath(_path(doc.get("repo", ""), "repo", base) or os.getcwd())
    if doc.get("servers") and not doc.get("repo") and repo in (os.path.realpath(os.path.expanduser("~")), "/"):
        raise ValueError(f"{path}: repo is unset and the working directory is {repo}: set repo, or the Kiro "
                         "check would trust every command under it")
    tools_env = mcp.get("tools_token_env")
    if tools_env and not os.environ.get(tools_env):
        raise ValueError(f"{path}: mcp.tools_token_env names {tools_env}, which is unset or empty")
    return Config(path=str(path), url=sijil["url"], token=os.environ.get(token_env or "SIJIL_TOKEN", ""),
                  agent_id=ident["agent_id"], auth=auth, key_path=_path(ident.get("key_path", ""), "identity.key_path", base),
                  registered_by=registered_by, display_name=ident.get("display_name", ""),
                  oidc_token_env=ident.get("oidc_token_env", "SIJIL_OIDC_TOKEN"),
                  state_path=_path(doc.get("state_path", ""), "state_path", base), intent=task.get("intent", ""),
                  harness=task.get("harness", "other"),
                  principal_header=task.get("principal_header", "X-Sijil-Principal-Token"),
                  repo=repo,
                  rulepack=_path(doc.get("rulepack", ""), "rulepack", base),
                  egress_pins=_path(egress.get("pins", ""), "egress.pins", base),
                  context_window=doc.get("context_window", "session"),
                  require_parent=corr.get("require_parent", True),
                  max_result_bytes=res.get("max_result_bytes", 262144),
                  invisible_unicode=res.get("invisible_unicode", "strip"), servers=_servers(doc, path, repo),
                  allowed_origins=tuple(str(o) for o in mcp.get("allowed_origins") or ()),
                  tools_token=os.environ.get(tools_env, "") if tools_env else "",
                  tls_cert=_path(mcp.get("tls_cert", ""), "mcp.tls_cert", base),
                  tls_key=_path(mcp.get("tls_key", ""), "mcp.tls_key", base))
