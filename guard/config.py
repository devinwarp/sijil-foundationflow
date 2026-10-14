"""`.sijil/guard.yaml` (spec §5.2): the parts this build reads. Unknown sections are refused, not ignored, so a
setting the guard does not honour is never mistaken for one it does."""

import fnmatch
import ipaddress
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from . import rules

PRINCIPAL = re.compile(r"oidc:[a-z0-9.-]+:\S+|email:[0-9a-f]{64}|local:[0-9a-f]{64}|human:[a-z0-9-]{1,32}:[0-9a-f]{64}")
SECTIONS = {"version", "sijil", "identity", "task", "state_path", "repo", "rulepack", "egress", "context_window",
            "correlation", "results", "servers", "allowed_command_dirs", "mcp", "lockfile", "integrity", "http_tools",
            "limits"}
TOOLS_KEYS = {"allow", "deny"}
KEYS = {"sijil": {"url", "token_env", "on_unreachable"},
        "identity": {"agent_id", "auth", "key_path", "registered_by", "display_name", "oidc_token_env"},
        "task": {"intent", "harness", "principal_header"},
        "egress": {"pins"}, "correlation": {"require_parent"}, "results": {"max_result_bytes", "invisible_unicode"}, "mcp": {"allowed_origins", "tools_token_env", "tls_cert", "tls_key"},
        "integrity": {"recheck_seconds"}, "limits": {"max_command", "max_args"},
        "http_tools": {"listen", "tls", "inbound_auth", "servers"}, "http_tools.tls": {"cert", "key"},
        "http_tools.inbound_auth": {"mode", "token_env", "client_ca"}, "http_tools.operations": TOOLS_KEYS,
        "http_tools.server": {"name", "upstream", "spec", "label", "forward_headers", "operations", "max_body_bytes",
                              "command_arg"}}
SERVER_KEYS = {"name", "transport", "command", "args", "env", "url", "headers", "label", "tools", "command_arg"}
HARNESSES = ("foundry", "http-agent", "other")                      # X-Sijil-Harness values (spec §17.3.3)
NOT_FORWARDED = {"host", "content-length", "transfer-encoding", "connection", "te", "upgrade", "keep-alive",
                 "proxy-authorization"}      # the adapter sets these itself
SERVER_NAME = re.compile(r"[a-z0-9_-]{1,32}")                      # source_label mcp:<name> (spec §17.1)
LABELS = ("telemetry", "web", "memory", "repo")                    # `user` cannot be assigned (spec §5.2)
COMMAND_DIRS = ("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "~/.nvm/versions/*/bin", "node_modules/.bin")
UNICODE_ACTIONS = ("strip", "block", "record")


def _allowed(name: str, allow: tuple, deny: tuple) -> bool:
    """The tools.allow/deny (operations.allow/deny) filter, one rule for both doors (spec §5.2): allow wins over
    deny; an allow list without a deny list is the filter (deny ["*"] implied); with no lists all are allowed."""
    if any(fnmatch.fnmatchcase(name, g) for g in allow):
        return True
    return not any(fnmatch.fnmatchcase(name, g) for g in deny or (("*",) if allow else ()))


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
    real: str = ""                # realpath of `command` when it was checked; re-checked before every launch

    def allowed(self, tool: str) -> bool:
        return _allowed(tool, self.allow, self.deny)


def _env(value: str) -> str:
    """${NAME} from the guard's environment; an unset name is an error, never an empty credential."""
    def sub(m):
        if m.group(1) not in os.environ:
            raise ValueError(f"${{{m.group(1)}}} is not set in the guard's environment")
        return os.environ[m.group(1)]
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", sub, str(value))


def _command_ok(command: str, repo: str, dirs) -> tuple[str, str]:
    """(the command as found on PATH, its realpath), refused when its real path (symlinks resolved) is outside the repo and
    allowed_command_dirs: a config written into ~/.kiro cannot make the guard launch from there."""
    found = shutil.which(command)
    if not found:
        raise ValueError(f"server command {command!r} not found on PATH")
    real = os.path.realpath(found)
    roots = [repo, *(os.path.expanduser(d) if d.startswith(("/", "~")) else os.path.join(repo, d) for d in dirs)]
    if any(fnmatch.fnmatchcase(os.path.dirname(real), r) or real.startswith(r.rstrip("/") + "/") for r in roots):
        return found, real
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
    command, real = _command_ok(d["command"], repo, dirs) if transport == "stdio" else ("", "")
    return Server(name=name, transport=transport, command=command, real=real,
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
class HttpServer:
    name: str                     # source_label http:<name>; tools are http:<name>:<operationId>
    upstream: str
    spec: str                     # OpenAPI 3.0/3.1, JSON or YAML
    label: str
    forward_headers: tuple        # lower-case names passed upstream; values are never sealed
    allow: tuple
    deny: tuple
    max_body_bytes: int
    command_arg: str

    def allowed(self, operation: str) -> bool:
        return _allowed(operation, self.allow, self.deny)


@dataclass(frozen=True)
class HttpTools:
    listen: str
    tls_cert: str
    tls_key: str
    auth: str                     # bearer_env | mtls | none (loopback only)
    token: str                    # bearer_env: the expected X-Sijil-Tools-Token
    client_ca: str                # mtls: the CA client certificates must chain to
    servers: tuple


def loopback(host: str) -> bool:
    """An allowlist: localhost, 127.0.0.0/8 and ::1. An empty host or 0.0.0.0 binds every interface."""
    host = host.strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def mcp_listen(cfg: "Config", listen: str) -> tuple[str, int, dict]:
    """`serve --http HOST:PORT` checked against the config before anything starts: (host, port, uvicorn TLS
    settings). Off loopback the MCP door needs mcp.tls_cert, mcp.tls_key and mcp.tools_token_env, as the HTTP
    adapter needs TLS and inbound auth (checked in _http_tools)."""
    host, _, port = listen.rpartition(":")
    if not port.isdecimal() or not 0 <= int(port) < 65536:
        raise ValueError(f"--http {listen}: expected HOST:PORT")
    if loopback(host):
        return host.strip("[]"), int(port), {}
    if not (cfg.tls_cert and cfg.tls_key and cfg.tools_token):
        raise ValueError(f"--http {listen} is off loopback: mcp.tls_cert, mcp.tls_key and mcp.tools_token_env "
                         "are required")
    return host.strip("[]"), int(port), {"ssl_certfile": cfg.tls_cert, "ssl_keyfile": cfg.tls_key}


def _keys(d, name: str, path: str) -> dict:
    """A mapping with only the keys KEYS[name] lists."""
    if d is None:
        return {}
    if not isinstance(d, dict) or set(d) - KEYS[name]:
        raise ValueError(f"{path}: {name} must be a mapping with only {sorted(KEYS[name])}")
    return d


def _strs(v, what: str, path: str) -> tuple:
    if v is None:
        return ()
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ValueError(f"{path}: {what} must be a list of strings")
    return tuple(v)


def _http_server(s, path: str, base: Path) -> HttpServer:
    s = _keys(s, "http_tools.server", path)
    name, label, up, spec = s.get("name", ""), s.get("label", ""), s.get("upstream"), s.get("spec")
    if not isinstance(name, str) or not SERVER_NAME.fullmatch(name) or name == "_sijil" or not isinstance(label, str) \
            or (label and label not in LABELS) or not isinstance(up, str) or not isinstance(spec, str) or not spec:
        raise ValueError(f"{path}: http_tools server {name!r} needs a [a-z0-9_-] name, upstream and spec")
    u = urlsplit(up)
    try:
        u.port
    except ValueError:
        raise ValueError(f"{path}: http_tools server {name}: upstream port is not valid") from None
    if u.scheme not in ("http", "https") or not u.hostname or u.query or u.fragment or u.username:
        raise ValueError(f"{path}: http_tools server {name}: upstream must be an http(s) URL without credentials")
    ops = _keys(s.get("operations"), "http_tools.operations", path)
    fwd = tuple(h.lower() for h in _strs(s.get("forward_headers"), f"server {name}: forward_headers", path))
    if any(h.startswith("x-sijil-") or h in NOT_FORWARDED for h in fwd):
        raise ValueError(f"{path}: http_tools server {name}: forward_headers may not name X-Sijil-* or "
                         f"{sorted(NOT_FORWARDED)}")
    cap = s.get("max_body_bytes", 1048576)
    if type(cap) is not int or cap < 1:
        raise ValueError(f"{path}: http_tools server {name}: max_body_bytes must be a positive integer")
    return HttpServer(name=name, upstream=up.rstrip("/"), spec=_path(spec, f"http_tools server {name}: spec", base),
                      label=label or f"http:{name}", forward_headers=fwd,
                      allow=_strs(ops.get("allow"), "operations.allow", path),
                      deny=_strs(ops.get("deny"), "operations.deny", path), max_body_bytes=cap,
                      command_arg=str(s.get("command_arg", "")))


def _http_tools(d, path: str, base: Path) -> HttpTools | None:
    """spec §17.3.2. Off loopback both TLS and inbound auth are required; entra inbound auth is row 42."""
    if not d:
        return None
    d = _keys(d, "http_tools", path)
    tls, auth = _keys(d.get("tls"), "http_tools.tls", path), _keys(d.get("inbound_auth"), "http_tools.inbound_auth", path)
    listen, mode = d.get("listen", "127.0.0.1:8090"), auth.get("mode", "none")
    host, _, port = listen.rpartition(":") if isinstance(listen, str) else ("", "", "")
    if not port.isdecimal() or not 0 < int(port) < 65536:
        raise ValueError(f"{path}: http_tools.listen must be HOST:PORT")
    if mode not in ("bearer_env", "mtls", "none"):
        raise ValueError(f"{path}: http_tools.inbound_auth.mode must be bearer_env or mtls (entra is not built)")
    if not all(isinstance(v, str) for v in (tls.get("cert", ""), tls.get("key", ""), auth.get("client_ca", ""))):
        raise ValueError(f"{path}: http_tools tls.cert, tls.key and inbound_auth.client_ca must be paths")
    cert, key = _path(tls.get("cert", ""), "http_tools.tls.cert", base), _path(tls.get("key", ""), "http_tools.tls.key", base)
    if not loopback(host) and (not cert or not key or mode == "none"):
        raise ValueError(f"{path}: http_tools off loopback needs tls.cert, tls.key and inbound_auth")
    ca = _path(auth.get("client_ca", ""), "http_tools.inbound_auth.client_ca", base)
    if mode == "mtls" and not (cert and key and ca):
        raise ValueError(f"{path}: inbound_auth mtls needs tls and inbound_auth.client_ca")
    env = auth.get("token_env", "SIJIL_TOOLS_TOKEN")
    token = os.environ.get(env, "") if mode == "bearer_env" and isinstance(env, str) else ""
    if mode == "bearer_env" and not token:
        raise ValueError(f"{path}: inbound_auth bearer_env: {env} is not set")
    items = d.get("servers") or []
    if not isinstance(items, list):
        raise ValueError(f"{path}: http_tools.servers must be a list")
    servers = tuple(_http_server(s, path, base) for s in items)
    if len({s.name for s in servers}) != len(servers):
        raise ValueError(f"{path}: http_tools server names must be unique")
    return HttpTools(listen=listen, tls_cert=cert, tls_key=key, auth=mode, token=token, client_ca=ca, servers=servers)


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
    lockfile: str                 # pinned tool definitions (spec §7.4); "" = none, only invisible Unicode is checked
    recheck_seconds: float        # tools/call re-checks the wrapped server's tools when the last check is older
    http_tools: HttpTools | None = None
    max_command: int = rules.MAX_COMMAND    # limits: the rule engine's size caps, in characters (guard/rules.py)
    max_args: int = rules.MAX_ARGS


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
    try:
        doc = yaml.safe_load(Path(path).read_bytes()) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"{path}: not YAML: {e}") from None
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise ValueError(f"{path}: version: 1 is required")
    unknown = set(doc) - SECTIONS
    if unknown:
        raise ValueError(f"{path}: sections {sorted(unknown)} are not supported by this guard")
    sijil, ident, task, egress, corr, res, mcp, integ, limits = (
        _section(doc, n, path) for n in ("sijil", "identity", "task", "egress", "correlation", "results", "mcp",
                                         "integrity", "limits"))
    caps = {k: limits.get(k, getattr(rules, k.upper())) for k in ("max_command", "max_args")}
    # at most twice the default: the rules' regexes grow quadratically, about 0.25 s a call at twice the default and
    # 1 s at four times, holding the guard's GIL
    if any(type(v) is not int or not 1 <= v <= 2 * getattr(rules, k.upper()) for k, v in caps.items()):
        raise ValueError(f"{path}: limits.max_command and limits.max_args must be integers from 1 to "
                         f"{2 * rules.MAX_COMMAND} and {2 * rules.MAX_ARGS}")
    recheck = integ.get("recheck_seconds", 30)
    if type(recheck) not in (int, float) or not 0 <= recheck <= 86400:
        raise ValueError(f"{path}: integrity.recheck_seconds must be a number from 0 to 86400")
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
    if not isinstance(doc.get("lockfile", ""), str):
        raise ValueError(f"{path}: lockfile must be a path")
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
                  tls_key=_path(mcp.get("tls_key", ""), "mcp.tls_key", base),
                  lockfile=_path(doc.get("lockfile", ""), "lockfile", base), recheck_seconds=float(recheck),
                  http_tools=_http_tools(doc.get("http_tools"), path, base), **caps)
