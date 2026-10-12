"""Shell command parsing for the rule engine (spec §8.1, §2.4.1 summary, §7.2 paths).

A fixed, shlex-based grammar: no shell is run and nothing is expanded except a leading `~` or `$HOME`.
`;`, `&&`, `||`, `|`, `&` and newlines split segments; `$(...)`, backticks, `sh -c` and `eval` are parsed as
further segments. Ambiguity resolves towards seeing more (a token that might be a path is a path), because
a missed path is a missed block and an extra one is at worst a confirm.
"""

import os
import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

SEPARATORS = {";", "&&", "||", "|", "&", "|&", "(", ")", ";;"}
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>", "<>"}
SKIP_REDIRECTS = {">&", "<&", "<<", "<<<", "<<-"}
WRAPPERS = {"sudo", "doas", "env", "command", "exec", "nohup", "time", "nice", "stdbuf", "timeout", "xargs"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
READERS = {"cat", "less", "more", "head", "tail", "base64", "xxd", "od", "strings", "source", ".", "wc", "sort",
           "uniq", "nl", "tac", "jq", "yq", "file", "stat", "diff", "cmp", "md5sum", "sha256sum", "shasum"}
PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "ag"}           # first positional is the pattern
WRITERS = {"rm", "touch", "mkdir", "rmdir", "truncate", "chmod", "chown", "shred", "unlink", "tee"}
COPIERS = {"cp", "mv", "install", "rsync", "scp", "ln"}          # last positional is written
FETCHERS = {"curl", "wget", "http", "https", "xh"}
INSTALLERS = {"npx", "bunx", "uvx", "npm", "pnpm", "yarn", "bun", "pip", "pip3", "pipx"}   # positionals are packages
ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.S)
ENV_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>|;&]+")
SCP_HOST = re.compile(r"[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):")
NAME_EXT = re.compile(r"[\w-]+\.[A-Za-z0-9]{1,8}")
NUMBERISH = re.compile(r"[0-9.]+[smhd]?")
MAX_DEPTH = 10            # nesting a real command never reaches; bounds hostile input


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


def _substitutions(text: str) -> tuple[str, list[str]]:
    """Cut out $(...) and `...` bodies (each parsed on its own) so shlex sees one placeholder word."""
    inner, out, i = [], [], 0
    while i < len(text):
        if text.startswith("$(", i):
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += {"(": 1, ")": -1}.get(text[j], 0)
                j += 1
            inner.append(text[i + 2:j - 1])
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


def _tokens(text: str) -> list[str]:
    lex = shlex.shlex(text.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lex.whitespace_split, lex.commenters = True, ""
    try:
        return list(lex)
    except ValueError:                        # unbalanced quote: plain whitespace split, still deterministic
        return text.replace("\n", " ; ").split()


def _strip_wrappers(argv: list[str]) -> list[str]:
    i = 0
    while i < len(argv) and ASSIGN.fullmatch(argv[i]):
        i += 1
    while i < len(argv) and os.path.basename(argv[i]) in WRAPPERS:
        name, i = os.path.basename(argv[i]), i + 1
        while i < len(argv) and (argv[i].startswith("-") or ASSIGN.fullmatch(argv[i]) or NUMBERISH.fullmatch(argv[i])):
            i += 2 if name in ("sudo", "doas") and argv[i] in ("-u", "-g") else 1
    return argv[i:]


def _positionals(args: list[str]) -> list[str]:
    return [a for a in args if not a.startswith("-")]


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
    return [n for n in out if n]


def _paths(argv0: str, args: list[str]) -> tuple[list[str], list[str]]:
    """(reads, writes) as raw tokens; the caller normalises them."""
    reads, writes, pos = [], [], _positionals(args)
    for i, a in enumerate(args):            # --opt=value and option arguments that name files
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a.startswith("--") and "=" in a and path_like(a.split("=", 1)[1]):
            (writes if a.startswith(("--output=", "--output-document=")) else reads).append(a.split("=", 1)[1])
        elif argv0 in FETCHERS and a in ("-o", "--output", "-O", "--output-document") and nxt:
            writes.append(nxt)
        elif argv0 in FETCHERS and a in ("-T", "--upload-file", "-K", "--config", "-i", "--post-file") and nxt:
            reads.append(nxt)
        elif argv0 in FETCHERS and a.startswith(("-d", "--data", "-F", "--form")) and "@" in nxt:
            reads.append(nxt[nxt.index("@") + 1:])
        elif argv0 == "dd" and a.startswith(("if=", "of=")):
            (reads if a.startswith("if=") else writes).append(a[3:])
    if argv0 in READERS:
        reads += [p for p in pos if not NUMBERISH.fullmatch(p)]
    elif argv0 in PATTERN_FIRST:
        reads += pos[1:]
    elif argv0 in WRITERS:
        writes += pos
    elif argv0 in COPIERS and pos:
        writes.append(pos[-1])
        (writes if argv0 == "mv" else reads).extend(pos[:-1])
    elif argv0 in ("sed", "perl") and any(a.startswith(("-i", "--in-place")) for a in args):
        writes += [p for p in pos[1:] if path_like(p)]
    elif argv0 in FETCHERS or argv0 in SHELLS or argv0 == "eval":
        pass                                  # URLs and scripts, not files; handled above or parsed as segments
    elif argv0 in INSTALLERS:                 # @scope/name is a package; ./dir and /abs are paths
        reads += [p for p in pos if p.startswith(("/", ".", "~", "$HOME", "${HOME}"))]
    else:
        reads += [p for p in pos if path_like(p)]
    return reads, writes


def _hosts(argv0: str, args: list[str]) -> list[str]:
    hosts = [host_of(m) for a in args for m in URL.findall(a)]
    hosts += [m.group(1).lower() for a in args for m in [SCP_HOST.match(a)] if m]
    if argv0 in FETCHERS:
        hosts += [host_of("http://" + p) for p in _positionals(args)
                  if "://" not in p and not p.startswith(("/", ".", "~", "$", "@"))]
    return sorted({h for h in hosts if h})


def parse(command: str, roots: Roots, _depth: int = 0) -> Parsed:
    text, inner = _substitutions(command)
    segments, current = [], []
    for tok in _tokens(text) + [";"]:
        if tok in SEPARATORS:
            if current:
                segments.append(current)
            current = []
        else:
            current.append(tok)
    out, nested = [], list(inner)
    for raw in segments:
        argv, reads, writes, i = [], [], [], 0
        while i < len(raw):                  # redirections out of argv, their targets into reads/writes
            tok = raw[i]
            if (tok in WRITE_REDIRECTS or tok in SKIP_REDIRECTS or tok == "<") and argv[-1:] == raw[i - 1:i] \
                    and argv[-1].isdigit():
                argv.pop()                    # the "2" of "2>": shlex splits fd numbers from the operator
            if tok in WRITE_REDIRECTS or tok == "<":
                if i + 1 < len(raw):
                    (reads if tok == "<" else writes).append(raw[i + 1])
                i += 2
            elif tok in SKIP_REDIRECTS:
                i += 2
            else:
                argv.append(tok)
                i += 1
        argv = _strip_wrappers(argv)
        argv0 = os.path.basename(argv[0]) if argv else ""
        args = argv[1:]
        if argv0 in SHELLS and "-c" in args[:-1]:
            nested.append(args[args.index("-c") + 1])
        elif argv0 == "eval":
            nested.append(" ".join(args))
        r, w = _paths(argv0, args)
        out.append(Segment(argv0=argv0, args=args, reads=[n for p in reads + r for n in normalise(p, roots)],
                           writes=[n for p in writes + w for n in normalise(p, roots)], hosts=_hosts(argv0, args),
                           packages=_packages(argv0, args)))
    if _depth < MAX_DEPTH:
        for text in nested:
            out += parse(text, roots, _depth + 1).segments
    return Parsed(command=command, segments=out, env_refs=sorted(set(ENV_REF.findall(command))))
