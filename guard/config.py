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
            "correlation", "results", "servers", "allowed_command_dirs", "lockfile", "http_tools"}
HARNESSES = ("foundry", "http-agent", "other")                      # X-Sijil-Harness values (spec §17.3.3)
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
        return found
    raise ValueError(f"server command {real} is outside the repo and allowed_command_dirs")


def _server(d: dict, repo: str, dirs) -> Server:
    name = d.get("name", "")
    if not SERVER_NAME.fullmatch(name):
        raise ValueError(f"server name {name!r} must match [a-z0-9_-]{{1,32}}")
    transport, label = d.get("transport", "stdio"), d.get("label", "")
    if transport not in ("stdio", "http") or (label and label not in LABELS):
        raise ValueError(f"server {name}: transport stdio|http; label one of {LABELS}")
    tools = d.get("tools") or {}
    if transport == "stdio" and not d.get("command") or transport == "http" and not d.get("url"):
        raise ValueError(f"server {name}: stdio needs command, http needs url")
    return Server(name=name, transport=transport,
                  command=_command_ok(d["command"], repo, dirs) if transport == "stdio" else "",
                  args=tuple(str(a) for a in d.get("args") or ()),
                  env={k: _env(v) for k, v in (d.get("env") or {}).items()}, url=d.get("url", ""),
                  headers={k: _env(v) for k, v in (d.get("headers") or {}).items()},
                  label=label or f"mcp:{name}", allow=tuple(tools.get("allow") or ()),
                  deny=tuple(tools.get("deny") or ()), command_arg=d.get("command_arg", "command"))


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
        if any(fnmatch.fnmatchcase(operation, g) for g in self.allow):
            return True
        return not self.deny or not any(fnmatch.fnmatchcase(operation, g) for g in self.deny)


@dataclass(frozen=True)
class HttpTools:
    listen: str
    tls_cert: str
    tls_key: str
    auth: str                     # bearer_env | mtls | none (loopback only)
    token: str                    # bearer_env: the expected X-Sijil-Tools-Token
    client_ca: str                # mtls: the CA client certificates must chain to
    servers: tuple


def _http_tools(d, path: str) -> HttpTools | None:
    """spec §17.3.2. Off loopback both TLS and inbound auth are required; entra inbound auth is row 42."""
    if not d:
        return None
    listen, tls, auth = d.get("listen", "127.0.0.1:8090"), d.get("tls") or {}, d.get("inbound_auth") or {}
    mode = auth.get("mode", "none")
    loopback = listen.rsplit(":", 1)[0] in ("127.0.0.1", "localhost", "::1", "[::1]")
    if mode not in ("bearer_env", "mtls", "none"):
        raise ValueError(f"{path}: http_tools.inbound_auth.mode must be bearer_env or mtls (entra is not built)")
    if not loopback and (not tls.get("cert") or not tls.get("key") or mode == "none"):
        raise ValueError(f"{path}: http_tools off loopback needs tls.cert, tls.key and inbound_auth")
    if mode == "mtls" and not (tls.get("cert") and auth.get("client_ca")):
        raise ValueError(f"{path}: inbound_auth mtls needs tls and inbound_auth.client_ca")
    token = os.environ.get(auth.get("token_env", "SIJIL_TOOLS_TOKEN"), "") if mode == "bearer_env" else ""
    if mode == "bearer_env" and not token:
        raise ValueError(f"{path}: inbound_auth bearer_env: {auth.get('token_env', 'SIJIL_TOOLS_TOKEN')} is not set")
    servers = []
    for s in d.get("servers") or ():
        name, label = s.get("name", ""), s.get("label", "")
        if not SERVER_NAME.fullmatch(name) or (label and label not in LABELS) or not s.get("upstream") \
                or not s.get("spec"):
            raise ValueError(f"{path}: http_tools server {name!r} needs a [a-z0-9_-] name, upstream and spec")
        ops = s.get("operations") or {}
        servers.append(HttpServer(name=name, upstream=s["upstream"].rstrip("/"), spec=_expand(s["spec"]),
                                  label=label or f"http:{name}",
                                  forward_headers=tuple(h.lower() for h in s.get("forward_headers") or ()),
                                  allow=tuple(ops.get("allow") or ()), deny=tuple(ops.get("deny") or ()),
                                  max_body_bytes=int(s.get("max_body_bytes", 1048576)),
                                  command_arg=s.get("command_arg", "")))
    return HttpTools(listen=listen, tls_cert=_expand(tls.get("cert", "")), tls_key=_expand(tls.get("key", "")),
                     auth=mode, token=token, client_ca=_expand(auth.get("client_ca", "")), servers=tuple(servers))


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
    lockfile: str                 # pinned tool definitions (spec §7.4); "" = none, only invisible Unicode is checked
    http_tools: HttpTools | None


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
                  invisible_unicode=res.get("invisible_unicode", "strip"),
                  servers=_servers(doc, path), lockfile=_expand(doc.get("lockfile", "")),
                  http_tools=_http_tools(doc.get("http_tools"), path))


def _servers(doc: dict, path: str) -> tuple:
    repo = os.path.realpath(_expand(doc.get("repo", "")) or os.getcwd())
    dirs = doc.get("allowed_command_dirs", COMMAND_DIRS)
    servers = tuple(_server(d if isinstance(d, dict) else {}, repo, dirs) for d in doc.get("servers") or ())
    if len({s.name for s in servers}) != len(servers):
        raise ValueError(f"{path}: server names must be unique")
    return servers
