"""Shell command parsing for the rule engine (spec §8.1, §2.4.1 summary, §7.2 paths).

# ponytail: a shlex approximation, not a shell. Ceiling: nothing is executed or expanded except a leading `~`
# or `$HOME`, so base64-decoded payloads (`echo Y2F0 | base64 -d | sh`), variable indirection (`D=~/.ssh; cat
# $D/id_rsa`), globs (`cat ~/.s*/id_rsa`), `~user` and any shell syntax shlex does not model are invisible.
# Upgrade path: a real shell parser such as bashlex (not a dependency now); the interface below would not change.

Within that ceiling the grammar errs towards seeing more, because a missed path is a missed block and an extra
one is at worst a confirm. `;`, `&&`, `||`, `|`, `&`, newlines, parentheses and compound keywords split or strip
segments; `$(...)`, backticks, `<(...)`, `>(...)`, `sh -c`, `eval`, here-strings and heredocs fed to a shell, and
the command behind wrappers (`sudo`, `env`, `timeout`, `xargs`, `find -exec`, ...) become further segments.
"""

import os
import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

OPCHARS = set(";&|()<>")
OPERATORS = ["&>>", "<<<", "<<-", "&&", "||", "|&", ";;", ";&", "&>", ">>", ">|", ">&", "<&", "<>", "<<",
             ";", "|", "&", "(", ")", "<", ">"]                       # longest first, so clusters split left to right
SEPARATORS = {";", "&&", "||", "|", "&", "|&", "(", ")", ";;", ";&"}
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>", "<>"}
KEYWORDS = {"if", "then", "elif", "else", "fi", "do", "done", "while", "until", "esac", "!", "{", "}", "coproc"}
# wrapper -> (options that take a separate argument, leading positionals to skip, e.g. timeout's duration)
SUDO_OPTS = {"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D", "-T", "--user", "--group", "--host", "--prompt",
             "--role", "--type", "--other-user", "--chdir", "--close-from", "--command-timeout"}
WRAPPERS = {
    "sudo": (SUDO_OPTS, 0), "doas": ({"-u", "-C"}, 0), "env": ({"-u", "-C", "--unset", "--chdir"}, 0),
    "command": (set(), 0), "exec": ({"-a"}, 0), "nohup": (set(), 0), "setsid": (set(), 0), "busybox": (set(), 0),
    "time": ({"-f", "-o", "--format", "--output"}, 0), "nice": ({"-n", "--adjustment"}, 0),
    "ionice": ({"-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"}, 0),
    "stdbuf": ({"-i", "-o", "-e", "--input", "--output", "--error"}, 0),
    "timeout": ({"-s", "-k", "--signal", "--kill-after"}, 1), "chrt": (set(), 1),
    "taskset": ({"-c", "--cpu-list"}, 1), "watch": ({"-n", "--interval"}, 0),
    "xargs": ({"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter", "--eof", "--max-args",
               "--max-lines", "--max-procs", "--max-chars"}, 0),
}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
SHORT_C = re.compile(r"-[A-Za-z]*c")                        # -c, -lc, -ec, -xc: a cluster ending in c runs a string
READERS = {"cat", "less", "more", "head", "tail", "base64", "xxd", "od", "strings", "source", ".", "wc", "sort",
           "uniq", "nl", "tac", "jq", "yq", "file", "stat", "diff", "cmp", "md5sum", "sha256sum", "shasum"}
PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "ag"}           # first positional is the pattern
WRITERS = {"rm", "touch", "mkdir", "rmdir", "truncate", "chmod", "chown", "shred", "unlink", "tee"}
COPIERS = {"cp", "mv", "install", "rsync", "scp", "ln"}          # last positional is written
FETCHERS = {"curl", "wget", "http", "https", "xh"}
NETWORK = {"nc", "ncat", "netcat", "telnet", "ssh", "sftp"}        # first positional is a host, not a file
INSTALLERS = {"npx", "bunx", "uvx", "npm", "pnpm", "yarn", "bun", "pip", "pip3", "pipx"}   # positionals are packages
ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.S)
ENV_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>|;&]+")
SCP_HOST = re.compile(r"[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):")
REMOTE = re.compile(r"(?:[\w.+-]+@)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):(?!//)")    # [user@]host:path of scp/rsync
NAME_EXT = re.compile(r"[\w-]+\.[A-Za-z0-9]{1,8}")
NUMBERISH = re.compile(r"[0-9.]+[smhd]?")
FD_PREFIX = re.compile(r"(?<![^\s;&|()])[0-9]+(?=[<>])")          # the 2 of `2>file`, dropped before lexing
HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
HEREDOC_MARK = re.compile(r"@HD([0-9]+)")
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
MASKED = dict(zip(";&|()<>", "\x01\x02\x03\x04\x05\x06\x07"))     # quoted or escaped operators, hidden from shlex
UNMASK = {v: k for k, v in MASKED.items()}
MAX_DEPTH = 10            # nesting a real command never reaches; bounds hostile input


class Op(str):
    """An unquoted shell operator, as opposed to a word that merely looks like one (a quoted or escaped `;`)."""


@dataclass
class Segment:
    argv0: str
    args: list[str]
    reads: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)


@dataclass
class Parsed:
    command: str
    segments: list[Segment]
    env_refs: list[str]

    def argv0s(self) -> list[str]:
        """Every segment's argv0, distinct, in order (nested shells and substitutions included)."""
        return list(dict.fromkeys(s.argv0 for s in self.segments if s.argv0))

    def summary(self) -> dict:
        """The value-free `summary` of a tool_call (spec §2.4.1). argv0 is the first segment's, a string, as in
        golden vector seq 45; the rules see every segment."""
        return {"argv0": (self.argv0s() or [""])[0], "packages": sorted({p for s in self.segments for p in s.packages}),
                "env_refs": self.env_refs, "hosts": sorted({h for s in self.segments for h in s.hosts}),
                "paths": sorted({p for s in self.segments for p in s.reads + s.writes})}


@dataclass(frozen=True)
class Roots:
    """Where relative paths start and how they are written back (spec §7.2)."""
    cwd: str
    repo: str
    home: str

    @classmethod
    def here(cls, repo: str | None = None) -> "Roots":
        cwd = os.getcwd()
        return cls(cwd=cwd, repo=os.path.realpath(repo or cwd), home=os.path.realpath(os.path.expanduser("~")))


def _shown(full: str, roots: Roots) -> str:
    for root, shown in ((roots.repo, ""), (roots.home, "~/")):
        if full == root:
            return shown.rstrip("/") or "."
        if full.startswith(root.rstrip("/") + "/"):
            return shown + os.path.relpath(full, root)
    return full


def normalise(path: str, roots: Roots) -> list[str]:
    """Expand ~ and $HOME, make absolute, resolve symlinks; then repo-relative inside the repo, ~/... inside
    $HOME, absolute elsewhere (spec §7.2). The real home directory never appears in the result. Both the
    resolved and the as-written form are returned when they differ, so `ln -s ~/.ssh k; cat k/id_rsa` and
    /etc on a host where /etc is a symlink both still match their globs."""
    for prefix in ("~", "$HOME", "${HOME}"):
        if path == prefix or path.startswith(prefix + "/"):
            path = roots.home + path[len(prefix):]
            break
    lexical = os.path.normpath(os.path.join(roots.cwd, path))
    return list(dict.fromkeys((_shown(os.path.realpath(lexical), roots), _shown(lexical, roots))))


def host_of(url: str) -> str | None:
    try:
        h = urlsplit(url).hostname
    except ValueError:
        return None
    if not h:
        return None
    try:
        return h.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return h.lower()


def path_like(tok: str) -> bool:
    if not tok or tok.startswith("-") or URL.match(tok) or SCP_HOST.match(tok) or ASSIGN.fullmatch(tok):
        return False
    return (tok.startswith(("/", "~", "$HOME", "${HOME}", ".")) or "/" in tok or bool(NAME_EXT.fullmatch(tok)))


def _heredocs(text: str, bodies: list) -> str:
    """Cut heredoc bodies out of the text (they are data, not commands) and park them in `bodies` as
    (body, expands) pairs; each `<<DELIM` becomes `<< @HDn`. Quoted and commented `<<` are left alone."""
    out, pending, quote, i = [], [], "", 0
    while i < len(text):
        c, m = text[i], None
        if c == "\\" and quote != "'":
            out.append(text[i:i + 2])
            i += 2
            continue
        if quote:
            quote = "" if c == quote else quote
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or text[i - 1] in " \t\n;&|()"):
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
            out.append(text[i:end])
            i = end
            continue
        elif text.startswith("<<<", i):
            out.append("<<<")
            i += 3
            continue
        elif c == "<" and (m := HEREDOC.match(text, i)):
            pending.append((len(bodies), m.group(1) == "-", m.group(3)))
            bodies.append(("", not m.group(2)))                   # body filled in at the next newline
            out.append(f"<< @HD{len(bodies) - 1} ")
            i = m.end()
            continue
        elif c == "\n" and pending:
            out.append(c)
            i += 1
            for idx, strip, delim in pending:
                lines = []
                while i < len(text):
                    end = text.find("\n", i)
                    end = len(text) if end < 0 else end
                    line, i = text[i:end], end + 1
                    if (line.lstrip("\t") if strip else line) == delim:
                        break
                    lines.append(line)
                bodies[idx] = ("\n".join(lines), bodies[idx][1])
            pending = []
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _substitutions(text: str) -> tuple[str, list[str]]:
    """Cut out $(...), <(...), >(...) and `...` bodies (each parsed on its own) so shlex sees one placeholder word."""
    inner, out, i = [], [], 0
    while i < len(text):
        if text.startswith(("$(", "<(", ">("), i):
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += {"(": 1, ")": -1}.get(text[j], 0)
                j += 1
            inner.append(text[i + 2:j - 1] if depth == 0 else text[i + 2:j])
            out.append("_")
            i = j
        elif text[i] == "`":
            j = text.find("`", i + 1)
            j = len(text) if j < 0 else j
            inner.append(text[i + 1:j])
            out.append("_")
            i = j + 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out), inner


def _mask(text: str) -> str:
    """Hide operator characters that are quoted or escaped (shlex cannot tell them apart), turn unquoted newlines
    into `;`, and join backslash-newline continuations."""
    out, quote, i = [], "", 0
    while i < len(text):
        c = text[i]
        if c == "\\" and quote != "'" and i + 1 < len(text):
            if text[i + 1] != "\n":
                out.append(c + MASKED.get(text[i + 1], text[i + 1]))
            i += 2
            continue
        if quote:
            quote = "" if c == quote else quote
            out.append(MASKED.get(c, c))
        elif c in "'\"":
            quote = c
            out.append(c)
        else:
            out.append(" ; " if c == "\n" else c)
        i += 1
    return "".join(out)


def _split_ops(cluster: str) -> list[Op]:
    """`;>` -> `;` `>`, `&&(` -> `&&` `(`: longest known operator first, left to right."""
    ops, i = [], 0
    while i < len(cluster):
        op = next((o for o in OPERATORS if cluster.startswith(o, i)), cluster[i])
        ops.append(Op(op))
        i += len(op)
    return ops


def _lex(text: str) -> list[str]:
    lex = shlex.shlex(text, posix=True, punctuation_chars=True)
    lex.whitespace_split, lex.commenters = True, ""
    return list(lex)


def _tokens(text: str) -> list[str]:
    """Words (str) and unquoted operators (Op), in order."""
    try:
        raw = _lex(FD_PREFIX.sub("", _mask(text)))
    except ValueError:                        # unbalanced quote: drop the quote characters and lex what is left
        raw = _lex(re.sub(r"['\"\\]", "", FD_PREFIX.sub("", text.replace("\n", " ; "))))
    out = []
    for tok in raw:
        if tok and all(c in OPCHARS for c in tok):
            out += _split_ops(tok)
        else:
            out.append("".join(UNMASK.get(c, c) for c in tok))
    return out


def _unwrap(argv: list[str]) -> tuple[list[str], list[str]]:
    """Strip assignments, compound keywords and command wrappers so argv0 is the command that really runs.
    Returns (argv, nested): a wrapper that takes a whole command string (env -S, watch) hands it back as one."""
    i = 0
    while i < len(argv):
        name = os.path.basename(argv[i])
        if ASSIGN.fullmatch(argv[i]) or argv[i] in KEYWORDS:
            i += 1
        elif name in WRAPPERS:
            value_opts, positionals = WRAPPERS[name]
            i += 1
            while i < len(argv) and (argv[i].startswith("-") or ASSIGN.fullmatch(argv[i])):
                opt, i = argv[i], i + 1
                if opt == "--":
                    break
                if name == "env" and opt.startswith(("-S", "--split-string")):
                    if opt in ("-S", "--split-string"):
                        value, i = (argv[i] if i < len(argv) else ""), i + 1
                    else:
                        value = opt.partition("=")[2] if opt.startswith("--") else opt[2:]
                    return [], [" ".join([value] + [shlex.quote(a) for a in argv[i:]])]
                if opt in value_opts and i < len(argv):
                    i += 1                                    # the option's separate argument
                if name == "taskset" and opt.startswith("-c"):
                    positionals = 0                           # the CPU list replaces the mask
            i += min(positionals, len(argv) - i)
            if name == "watch" and i < len(argv):
                rest = argv[i:]
                return [], [rest[0] if len(rest) == 1 else shlex.join(rest)]
        else:
            break
    return argv[i:], []


def _positionals(args: list[str]) -> list[str]:
    return [a for a in args if not a.startswith("-") and a not in ("_", "{}")]     # not a substitution or find's {}


def _packages(argv0: str, args: list[str]) -> list[str]:
    pos = _positionals(args)
    if argv0 in ("npx", "bunx", "uvx"):
        names = [args[args.index("-p") + 1]] if "-p" in args[:-1] else pos[:1]
    elif (argv0, pos[:1]) in (("npm", ["exec"]), ("pnpm", ["dlx"]), ("pipx", ["run"])):
        names = pos[1:2]
    elif argv0 in ("pip", "pip3", "npm", "pnpm", "yarn", "bun") and pos[:1] in (["install"], ["i"], ["add"]):
        names = pos[1:]
    else:
        return []
    out = []
    for n in names:
        n = n[:n.index("@", 1)] if "@" in n[1:] else n          # npm: name@version, @scope/name@version
        out.append(re.split(r"[=<>!~\[;]", n)[0])                # pip: name==1.0, name[extra]
    return [n for n in out if n and "{" not in n]                # `{}` is an xargs/find placeholder


CURL_SHORT = "AbcCdDeEFHKmoPQrtTuUwxXyYz"        # short options that take a value, per tool
CURL_LONG = set("""--url --data --data-raw --data-binary --data-ascii --data-urlencode --json --header --user-agent
    --request --output --upload-file --form --form-string --config --cookie --cookie-jar --proxy --referer --user
    --resolve --connect-to --max-time --connect-timeout --retry --limit-rate --write-out --range --cacert --cert --key
    --dump-header --stderr --trace --trace-ascii --netrc-file --unix-socket --proto --oauth2-bearer""".split())
WGET_SHORT = "OoaetTwQPUiBlIXDAR"
WGET_LONG = set("""--output-document --output-file --append-output --input-file --header --user-agent --post-data
    --post-file --body-data --body-file --method --referer --user --password --http-user --http-password
    --directory-prefix --execute --tries --timeout --wait --limit-rate --bind-address --certificate --private-key
    --ca-certificate --load-cookies --save-cookies --proxy-user --domains --base""".split())
HTTPIE = ("aAospP", {"--auth", "--auth-type", "--output", "--style", "--print", "--history-print", "--proxy",
                     "--timeout", "--verify", "--cert", "--cert-key", "--session", "--session-read-only"})
OPTS = {"curl": (CURL_SHORT, CURL_LONG), "wget": (WGET_SHORT, WGET_LONG), "http": HTTPIE, "https": HTTPIE,
        "xh": HTTPIE, "nc": ("pswiIOTxXPqecC", {"--exec", "--sh-exec", "--source", "--source-port", "--wait"}),
        "ncat": ("pswiIOTxXPqecC", {"--exec", "--sh-exec", "--source", "--source-port", "--wait"}),
        "netcat": ("pswiIOTxXPqecC", set()), "telnet": ("lbeSsX", set()),
        "ssh": ("BbcDEeFIiJLlmOopQRSWw", set()), "sftp": ("BbcDFiJlOoPRSsX", set())}
# per fetcher: (options whose value is a file written, options whose value is a file read)
FETCH_FILES = {
    "curl": ({"-o", "--output", "-D", "--dump-header", "-c", "--cookie-jar", "--stderr", "--trace", "--trace-ascii"},
             {"-T", "--upload-file", "-K", "--config", "-E", "--cert", "--key", "--cacert", "--netrc-file"}),
    "wget": ({"-O", "--output-document", "-o", "--output-file", "-a", "--append-output", "-P", "--directory-prefix",
              "--save-cookies"},
             {"-i", "--input-file", "--post-file", "--body-file", "--load-cookies", "--certificate", "--private-key",
              "--ca-certificate"}),
}
HTTPIE_FILES = ({"-o", "--output"}, {"--cert", "--cert-key"})
ITEM_FILE = re.compile(r"[^@=:]*(?:@|:?=@)(.+)")                  # httpie: field@file, field=@file, field:=@file


def _split_opts(args: list[str], short_val: str, long_val: set) -> tuple[list[tuple[str, str]], list[str]]:
    """(options as (name, value or ""), positionals). Understands -oVALUE, -abc clusters, --opt=value, `--opt
    value` for the listed long options, and `--`. A lone `-` (stdin) is neither."""
    opts, pos, i = [], [], 0
    while i < len(args):
        a, i = args[i], i + 1
        if a == "--":
            pos += args[i:]
            break
        if a.startswith("--"):
            name, eq, val = a.partition("=")
            if not eq and name in long_val and i < len(args):
                val, i = args[i], i + 1
            opts.append((name, val))
        elif a.startswith("-"):
            for k in range(1, len(a)):
                if a[k] in short_val:
                    val = a[k + 1:]
                    if not val and i < len(args):
                        val, i = args[i], i + 1
                    opts.append(("-" + a[k], val))
                    break
                opts.append(("-" + a[k], ""))
        else:
            pos.append(a)
    return opts, pos


def _upload_path(name: str, value: str) -> str:
    """The file a curl option value reads: -d @file, -F name=@file or name=<file, --data-urlencode name@file."""
    if name in ("-d", "--data", "--data-binary", "--data-ascii", "--json"):
        return value[1:] if value.startswith("@") else ""
    if name in ("-F", "--form"):
        rhs = value.partition("=")[2]
        return rhs[1:].split(";")[0] if rhs[:1] in ("@", "<") else ""
    if name == "--data-urlencode":
        before, at, after = value.partition("@")
        return after if at and "=" not in before else ""
    if name in ("-b", "--cookie"):
        return value if path_like(value) else ""
    return ""


def _fetch_paths(argv0: str, args: list[str]) -> tuple[list[str], list[str]]:
    opts, pos = _split_opts(args, *OPTS[argv0])
    writes_opts, reads_opts = FETCH_FILES.get(argv0, HTTPIE_FILES)
    reads, writes = [], []
    for name, value in opts:
        if not value:
            continue
        if name in writes_opts:
            writes.append(value)
        elif name in reads_opts:
            reads.append(value)
        elif argv0 == "curl":
            reads.append(_upload_path(name, value))
    if argv0 in ("http", "https", "xh"):
        reads += [m.group(1) for item in pos[1:] for m in [ITEM_FILE.fullmatch(item)] if m]
    return [r for r in reads if r and r != "-"], [w for w in writes if w != "-"]


def _net_paths(argv0: str, args: list[str]) -> tuple[list[str], list[str]]:
    """nc and telnet name hosts, not files; ssh and sftp read the identity, config and batch files they are given."""
    if argv0 not in ("ssh", "sftp"):
        return [], []
    opts, _ = _split_opts(args, *OPTS[argv0])
    return [v for k, v in opts if k in ("-i", "-F", "-b") and v], []


def _paths(argv0: str, args: list[str]) -> tuple[list[str], list[str]]:
    """(reads, writes) as raw tokens; the caller normalises them."""
    if argv0 in FETCHERS:
        return _fetch_paths(argv0, args)
    if argv0 in NETWORK:
        return _net_paths(argv0, args)
    reads, writes, pos = [], [], _positionals(args)
    for a in args:                          # --opt=value options that name files
        if a.startswith("--") and "=" in a and path_like(a.split("=", 1)[1]):
            (writes if a.startswith(("--output=", "--output-document=")) else reads).append(a.split("=", 1)[1])
        elif argv0 == "dd" and a.startswith(("if=", "of=")):
            (reads if a.startswith("if=") else writes).append(a[3:])
    if argv0 in READERS:
        reads += [p for p in pos if not NUMBERISH.fullmatch(p)]
    elif argv0 in PATTERN_FIRST:
        reads += pos[1:]
    elif argv0 in WRITERS:
        writes += pos
    elif argv0 in COPIERS and pos:
        remote = [p for p in pos if argv0 in ("scp", "rsync") and (REMOTE.match(p) or URL.match(p))]
        local = [p for p in pos if p not in remote]            # a remote operand is a host, not a local path
        if pos[-1] in remote:
            reads += local
        else:
            writes.append(pos[-1])
            (writes if argv0 == "mv" else reads).extend(local[:-1])
    elif argv0 in ("sed", "perl") and any(a.startswith(("-i", "--in-place")) for a in args):
        writes += [p for p in pos[1:] if path_like(p)]
    elif argv0 in SHELLS or argv0 == "eval":
        pass                                  # scripts, not files; handled as nested segments
    elif argv0 in INSTALLERS:                 # @scope/name is a package; ./dir and /abs are paths
        reads += [p for p in pos if p.startswith(("/", ".", "~", "$HOME", "${HOME}"))]
    else:
        reads += [p for p in pos if path_like(p)]
    return reads, writes


def _host_part(dest: str) -> str:
    """`user@host`, `host:path` or `[::1]:22` -> the host (bracketed for IPv6), or "" when it is not a plain name."""
    h = dest.rsplit("@", 1)[-1]
    if h.startswith("["):
        return h.split("]")[0] + "]"
    h = h.split(":")[0]
    return h if re.fullmatch(r"[A-Za-z0-9._-]+", h) else ""


def _operand_hosts(argv0: str, args: list[str]) -> list[str]:
    """Hosts named by a bare operand, as host[:port][/path] strings: `curl api.example.com/x`, `nc evil.example 9`,
    `ssh user@evil.example`, `scp f user@evil.example:/x`. Option values never count."""
    if argv0 in ("scp", "rsync"):
        return [m.group(1) for p in _positionals(args) for m in [REMOTE.match(p)] if m]
    if argv0 not in FETCHERS | NETWORK:
        return []
    opts, pos = _split_opts(args, *OPTS[argv0])
    if argv0 in ("curl", "wget"):
        pos += [v for k, v in opts if k == "--url"]
        return [p for p in pos if "://" not in p and not p.startswith(("/", ".", "~", "$", "@", "_"))]
    if argv0 in ("http", "https", "xh"):
        pos = pos[1:] if pos[:1] and pos[0] in HTTP_METHODS else pos
        return [p for p in pos[:1] if "://" not in p and not p.startswith(("/", ".", "~", "$", "@", "_", ":"))]
    if argv0 in ("ssh", "sftp"):
        jumps = [h for k, v in opts if k == "-J" for h in v.split(",")]
        return [h for h in map(_host_part, pos[:1] + jumps) if h]
    listening = any(k in ("-l", "--listen") for k, _ in opts)      # nc -l 9999: the operand is a port
    return [] if listening or not pos or pos[0].isdigit() else [pos[0]]


def _hosts(argv0: str, args: list[str]) -> list[str]:
    hosts = [host_of(m) for a in args for m in URL.findall(a)]
    hosts += [m.group(1).lower() for a in args for m in [SCP_HOST.match(a)] if m]
    hosts += [host_of("http://" + h) for h in _operand_hosts(argv0, args)]
    return sorted({h for h in hosts if h})


def _redirections(raw: list[str]) -> tuple[list[str], list[str], list[str], list[tuple[str, str]]]:
    """(argv, reads, writes, feeds): redirection operators and their targets come out of argv. A feed is a
    heredoc or here-string, kept so a shell reading it can be parsed."""
    argv, reads, writes, feeds, i = [], [], [], [], 0
    while i < len(raw):
        tok = raw[i]
        if not isinstance(tok, Op):
            argv.append(tok)
            i += 1
            continue
        has_target = i + 1 < len(raw) and not isinstance(raw[i + 1], Op)
        target = raw[i + 1] if has_target else ""
        i += 2 if has_target else 1
        if not target:
            continue
        if tok in WRITE_REDIRECTS or (tok == ">&" and not (target.isdigit() or target == "-")):
            writes.append(target)
        elif tok == "<":
            reads.append(target)
        elif tok in ("<<", "<<-"):
            feeds.append(("heredoc", target))
        elif tok == "<<<":
            feeds.append(("string", target))
    return argv, reads, writes, feeds


def _find_execs(args: list[str]) -> list[str]:
    """`find ... -exec CMD ... \;` (or `+`, -execdir, -ok, -okdir): each CMD as a command string."""
    out, i = [], 0
    while i < len(args):
        if args[i] in ("-exec", "-execdir", "-ok", "-okdir"):
            j = i + 1
            while j < len(args) and args[j] not in (";", "+"):
                j += 1
            if j > i + 1:
                out.append(shlex.join(args[i + 1:j]))
            i = j
        i += 1
    return out


def _nested_commands(argv0: str, args: list[str]) -> list[str]:
    if argv0 in SHELLS:
        return [args[i + 1] for i, a in enumerate(args[:-1]) if SHORT_C.fullmatch(a)][:1]
    if argv0 == "eval":
        return [" ".join(args)]
    return _find_execs(args) if argv0 == "find" else []


def _fed_commands(argv0: str, feeds: list[tuple[str, str]], bodies: list) -> tuple[list[str], list[str]]:
    """(run, texts). A shell runs the heredoc or here-string it is fed; anything else only expands $(...) in a
    heredoc, and its texts are returned in case a later `| sh` runs them."""
    run, texts = [], []
    for kind, target in feeds:
        if kind == "string":
            body, expands = target, False                 # its $(...) was already cut out with the whole command
        else:
            m = HEREDOC_MARK.fullmatch(target)
            if not m or int(m.group(1)) >= len(bodies):
                continue
            body, expands = bodies[int(m.group(1))]
        if argv0 in SHELLS:
            run.append(body)
        else:
            texts.append(body)
            run += _substitutions(body)[1] if expands else []
    return run, texts


def _segments(tokens: list[str]) -> list[list[str]]:
    segments, current = [], []
    for tok in tokens + [Op(";")]:
        if isinstance(tok, Op) and tok in SEPARATORS:
            if current:
                segments.append(current)
            current = []
        else:
            current.append(tok)
    return segments


def parse(command: str, roots: Roots, _depth: int = 0, _bodies: list | None = None) -> Parsed:
    bodies = [] if _bodies is None else _bodies           # heredoc bodies, shared with nested parses
    text, inner = _substitutions(_heredocs(command, bodies))
    out, nested, piped, stdin_shell = [], list(inner), [], False
    for raw in _segments(_tokens(text)):
        argv, reads, writes, feeds = _redirections(raw)
        argv, wrapped = _unwrap(argv)
        argv0 = os.path.basename(argv[0]) if argv else ""
        args = argv[1:]
        commands = _nested_commands(argv0, args)
        run, texts = _fed_commands(argv0, feeds, bodies)
        nested += wrapped + commands + run
        piped += texts + ([" ".join(args)] if argv0 in ("echo", "printf") else [])
        stdin_shell |= argv0 in SHELLS and not commands and not _positionals(args)
        if not (argv0 or reads or writes):
            continue                                       # `fi`, `done`, `}` and the like
        r, w = _paths(argv0, args)
        out.append(Segment(argv0=argv0, args=args, reads=[n for p in reads + r for n in normalise(p, roots)],
                           writes=[n for p in writes + w for n in normalise(p, roots)], hosts=_hosts(argv0, args),
                           packages=_packages(argv0, args)))
    if stdin_shell:
        nested += piped                                    # `cat <<EOF | sh`, `echo 'npx x' | sh`: over-see the text
    if _depth < MAX_DEPTH:
        for text in nested:
            out += parse(text, roots, _depth + 1, bodies).segments
    return Parsed(command=command, segments=out, env_refs=sorted(set(ENV_REF.findall(command))))
