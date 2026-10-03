"""Shell command analysis for SEC-TOOL-01 and SEC-FLOW-01 (concept §9 "coding-agent specifics: Shell").

    analyze_command(command, cwd=, root=) -> CommandAnalysis

Three outcomes, in this order of precedence:
  * `deny`   deterministic deny classes → block: `rm -rf /`-class deletes, `curl|sh` / `wget|sh` / decode-to-shell,
             `terraform destroy`, `aws … delete-*`, "skip permission" flags, reverse shells, disk wipes, and any
             access to protected locations (`~/.ssh`, `.env`, cloud credentials, wallets, browser profiles);
  * safe     every segment is a known read-only command (`git status`, `ls`, test runners, …), no output
             redirection, no unresolved expansion, paths inside the workspace → allowed without approval;
  * otherwise → `approval` reasons (everything else requires a human).

`egress` marks commands that send data out or publish (curl, git push, scp, npm publish, …); SEC-FLOW-01 treats a
call with `egress` as a sink even when the tool itself (`opencode.bash`) is not labelled `external_egress`.

The parser is deliberately conservative: anything it cannot understand (command substitution, process substitution,
variables, globs in security-relevant positions) can never be "safe". It is a gate for the common agent mistakes
and injection payloads, not a shell interpreter; the egress allowlist of the sandbox remains the backstop.
No raw argument values are put into reasons: codes and classes only.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass, field

from acl.controls.normalise.intent import _NPM_VALUE_OPTS, _PIP_VALUE_OPTS, _specs, packages_from_argv, split_command
from acl.controls.tools.paths import UNSET, canonical, classify_sensitive, within, workspace_root

MAX_DEPTH = 3
MAX_COMMAND_CHARS = 16_000

_OPS = frozenset("();<>|&")
_WRAPPERS = frozenset({"sudo", "doas", "env", "time", "nohup", "nice", "command", "exec", "timeout", "xargs", "stdbuf"})
_ELEVATORS = frozenset({"sudo", "doas"})
_WRAPPER_VALUE_OPTS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-r", "-t", "-U"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S"},
    "nice": {"-n"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "xargs": {"-I", "-n", "-P", "-d", "-L", "-E", "-s", "-a"},
    "stdbuf": {"-i", "-o", "-e"},
}
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "busybox"})
_INTERPRETERS = frozenset(
    {
        "python",
        "python2",
        "python3",
        "py",
        "perl",
        "ruby",
        "node",
        "nodejs",
        "php",
        "lua",
        "deno",
        "bun",
        "pwsh",
        "powershell",
    }
)
_PATTERN_FIRST = frozenset({"grep", "egrep", "fgrep", "rg", "findstr", "ag", "ack"})
_PIPE_SINKS = _SHELLS | _INTERPRETERS | {"iex", "invoke-expression", "source", "eval", "cmd"}
_FETCHERS = frozenset(
    {
        "curl",
        "wget",
        "fetch",
        "iwr",
        "irm",
        "invoke-webrequest",
        "invoke-restmethod",
        "nc",
        "ncat",
        "netcat",
        "http",
        "https",
        "xh",
        "aria2c",
        "lwp-request",
    }
)
_DECODERS = re.compile(
    r"(?:\bbase64\b[^|;&]*(?:\s-d\b|\s--decode\b|\s-D\b)|\bxxd\b[^|;&]*\s-r\b|\bopenssl\b[^|;&]*\benc\b[^|;&]*\s-d\b)"
)

_EGRESS_EXES = frozenset(
    {
        "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "rsync", "ftp", "tftp", "telnet", "ping",
        "nslookup", "dig", "host", "traceroute", "aria2c", "http", "https", "xh", "lynx", "links", "w3m", "mail",
        "sendmail", "mutt", "msmtp", "mailx", "swaks", "nmap", "iwr", "irm", "invoke-webrequest", "invoke-restmethod",
        "start-bitstransfer", "bitsadmin", "gh", "glab", "hub", "aws", "gsutil", "gcloud", "az", "twine", "lwp-request",
    }
)  # fmt: skip
_EGRESS_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "git": frozenset({"push", "clone", "fetch", "pull", "ls-remote", "send-email", "submodule"}),
    "npm": frozenset(
        {"publish", "adduser", "login", "install", "i", "add", "ci", "update", "exec", "dist-tag", "access"}
    ),
    "pnpm": frozenset({"publish", "add", "install", "i", "dlx", "update"}),
    "yarn": frozenset({"publish", "add", "install", "npm", "dlx"}),
    "cargo": frozenset({"publish", "install", "login", "add", "update", "fetch"}),
    "gem": frozenset({"push", "install"}),
    "docker": frozenset({"push", "login", "pull", "run"}),
    "podman": frozenset({"push", "login", "pull", "run"}),
    "kubectl": frozenset({"cp", "exec", "port-forward", "run"}),
    "pip": frozenset({"install", "download", "upload"}),
    "pip3": frozenset({"install", "download", "upload"}),
    "uv": frozenset({"publish", "add", "tool", "pip", "sync"}),
    "go": frozenset({"get", "install", "mod"}),
    "brew": frozenset({"install", "upgrade", "tap"}),
    "apt": frozenset({"install", "update", "upgrade"}),
    "apt-get": frozenset({"install", "update", "upgrade"}),
}
_INLINE_NET = re.compile(
    r"(?i)\b(?:urllib|requests|httpx|aiohttp|http\.client|socket|urlopen|fetch\(|XMLHttpRequest|net\.connect|curl|wget)\b"
)

_SKIP_PERMS = re.compile(
    r"(?i)^--?(?:(?:allow-)?dangerously-?(?:skip|bypass)[\w-]*|(?:skip|bypass)-?(?:the-)?(?:permissions?|approvals?|sandbox)[\w-]*"
    r"|yolo|trust-all-tools|permission-mode=bypass\w*)$"
)
_DANGEROUS_RM = {
    "/", "/*", "~", "~/", "~/*", "$home", "${home}", "$home/", "$home/*", "${home}/*", "%userprofile%", "%homepath%",
    "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root", "/run", "/sbin", "/srv",
    "/sys", "/usr", "/var", "/mnt", "/media", "/users", "/system", "/library", "/.",
}  # fmt: skip
_FORK_BOMB = re.compile(r":\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:")
_SUBST = re.compile(r"\$\(([^()]*)\)|`([^`]*)`|[<>]\(([^()]*)\)")
_VAR = re.compile(r"\$(?:\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?!$-])")
_GLOB = re.compile(r"[*?\[{]")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_REVERSE_SHELL = re.compile(
    r"(?i)(?:/dev/(?:tcp|udp)/|\bnc(?:at)?\b[^|;&]*\s-[a-z]*e\b|\bbash\s+-i\b[^|;&]*[<>]&|\bmkfifo\b[^|;&]*\bnc\b)"
)
_WIN_DESTRUCTIVE = re.compile(
    r"(?i)(?:\b(?:rd|rmdir)\s+/s\b[^|;&]*\b[a-z]:\\?(?:\s|$)|\bdel\s+(?:/[a-z]\s+)*[a-z]:\\\*|\bformat\s+[a-z]:|"
    r"remove-item\b[^|;&]*-recurse[^|;&]*\b[a-z]:\\?(?:\s|$)|\bcipher\s+/w)"
)
_PS_ENC = re.compile(r"(?i)\b(?:powershell|pwsh)\b[^|;&]*\s-e(?:nc(?:odedcommand)?)?\s")


# ---------------------------------------------------------------- safe lists

_SAFE_SIMPLE = frozenset(
    {
        "ls", "dir", "pwd", "cat", "head", "tail", "wc", "echo", "grep", "egrep", "fgrep", "rg", "sort", "uniq", "diff",
        "cmp", "tree", "which", "where", "whoami", "date", "uname", "file", "stat", "du", "df", "basename", "dirname",
        "realpath", "cut", "tr", "hostname", "true", "false", "test", "[", "nl", "column", "jq", "sha256sum", "md5sum",
        "seq", "sleep", "cd", "type", "ver", "findstr", "printf", "readlink", "tac", "rev", "fold",
        "paste", "comm", "join", "expand", "od", "hexdump", "strings",
    }
)  # fmt: skip
_SAFE_GIT = frozenset(
    {
        "status", "diff", "log", "show", "rev-parse", "ls-files", "blame", "shortlog", "describe", "grep", "cat-file",
        "ls-tree", "merge-base", "whatchanged", "count-objects", "check-ignore", "diff-tree", "name-rev", "rev-list",
        "show-ref", "for-each-ref", "diff-index", "diff-files", "var", "version",
    }
)  # fmt: skip
_GIT_UNSAFE_FLAGS = ("--output", "--ext-diff", "--textconv", "--open-files-in-pager", "-O", "--exec", "--upload-pack")
_FIND_UNSAFE = frozenset({"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"})
_SORT_UNSAFE = frozenset({"-o", "--output", "--compress-program"})
_RG_UNSAFE = frozenset({"--pre", "--hostname-bin"})
# (prefix tokens) → allowed; test runners and read-only project tooling
_SAFE_PREFIXES: tuple[tuple[str, ...], ...] = (
    ("pytest",), ("python", "-m", "pytest"), ("python3", "-m", "pytest"), ("py", "-m", "pytest"),
    ("uv", "run", "pytest"), ("uv", "run", "python", "-m", "pytest"), ("uv", "run", "python", "scripts/dev.py", "test"),
    ("uv", "run", "python", "scripts/dev.py", "lint"), ("python", "scripts/dev.py", "test"),
    ("python", "scripts/dev.py", "lint"), ("make", "test"), ("make", "check"), ("make", "lint"),
    ("ruff", "check"), ("ruff", "format", "--check"), ("ruff", "format", "--diff"), ("mypy",), ("pyright",),
    ("flake8",), ("pylint",), ("black", "--check"), ("isort", "--check"), ("tox",),
    ("npm", "test"), ("npm", "t"), ("npm", "run", "test"), ("npm", "run", "lint"), ("npm", "run", "build"),
    ("npm", "run", "typecheck"), ("npm", "run", "check"), ("pnpm", "test"), ("pnpm", "run", "test"),
    ("pnpm", "run", "lint"), ("pnpm", "run", "build"), ("pnpm", "lint"), ("yarn", "test"), ("yarn", "lint"),
    ("yarn", "build"), ("bun", "test"), ("jest",), ("vitest",), ("tsc", "--noemit"), ("eslint",),
    ("go", "test"), ("go", "vet"), ("go", "build"), ("go", "list"), ("cargo", "test"), ("cargo", "check"),
    ("cargo", "clippy"), ("cargo", "build"), ("cargo", "fmt", "--check"), ("mvn", "test"), ("mvn", "verify"),
    ("mvn", "compile"), ("./mvnw", "test"), ("gradle", "test"), ("gradle", "check"), ("gradle", "build"),
    ("./gradlew", "test"), ("./gradlew", "check"), ("./gradlew", "build"), ("dotnet", "test"), ("dotnet", "build"),
    ("rspec",), ("bundle", "exec", "rspec"), ("phpunit",),
    # read-only infrastructure / platform inspection (mutating verbs fall through to approval or the deny classes)
    ("terraform", "plan"), ("terraform", "validate"), ("terraform", "show"), ("terraform", "output"),
    ("terraform", "version"), ("terraform", "fmt", "-check"), ("tofu", "plan"), ("tofu", "validate"),
    ("kubectl", "get"), ("kubectl", "describe"), ("kubectl", "logs"), ("docker", "ps"), ("docker", "images"),
    ("docker", "logs"), ("docker", "inspect"), ("gh", "pr", "view"), ("gh", "pr", "list"), ("gh", "pr", "status"),
    ("gh", "issue", "list"), ("gh", "issue", "view"), ("gh", "repo", "view"),
)  # fmt: skip
_PREFIX_UNSAFE = frozenset({"--fix", "--write", "-w", "--output", "--install", "-u", "--update-snapshot"})


# ---------------------------------------------------------------- result types


@dataclass(frozen=True)
class DenyHit:
    code: str
    reason: str


@dataclass
class CommandAnalysis:
    deny: list[DenyHit] = field(default_factory=list)
    approval: list[str] = field(default_factory=list)  # reason codes
    egress: bool = False
    install: bool = False
    paths: list[str] = field(default_factory=list)  # raw path-like tokens (for logging counts only)
    safe: bool = False

    def add_deny(self, code: str, reason: str) -> None:
        if all(h.code != code for h in self.deny):
            self.deny.append(DenyHit(code, reason))

    def need_approval(self, code: str) -> None:
        if code not in self.approval:
            self.approval.append(code)


@dataclass
class _Segment:
    argv: list[str]
    redirects: list[tuple[str, str]] = field(default_factory=list)
    pipe_in: bool = False
    pipe_out: bool = False


# ---------------------------------------------------------------- tokenising


def _flatten_newlines(command: str) -> str:
    """Unquoted newlines are command separators; backslash-newline is a continuation."""
    out: list[str] = []
    quote = ""
    i = 0
    while i < len(command):
        c = command[i]
        if quote:
            out.append(c)
            if c == quote:
                quote = ""
            elif c == "\\" and quote == '"' and i + 1 < len(command):
                out.append(command[i + 1])
                i += 1
        elif c in "'\"":
            quote = c
            out.append(c)
        elif c == "\\" and command[i : i + 2] in ("\\\n", "\\\r"):
            i += 1
            if command[i : i + 2] == "\r\n":
                i += 1
        elif c in "\r\n":
            out.append(" ; ")
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _is_op(tok: str) -> bool:
    return bool(tok) and all(ch in _OPS for ch in tok)


def _segments(tokens: list[str]) -> list[_Segment]:
    segs: list[_Segment] = [_Segment([])]
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if _is_op(tok) and ("<" in tok or ">" in tok):
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            # `2>&1`, `>&2`: fd duplication, not a file
            if tok.endswith("&") and re.fullmatch(r"\d+|-", target or "x"):
                i += 2
                continue
            segs[-1].redirects.append((tok, target))
            if segs[-1].argv and re.fullmatch(r"\d", segs[-1].argv[-1]):
                segs[-1].argv.pop()  # `2>file`: the fd number is part of the redirection
            i += 2
            continue
        if _is_op(tok):
            piped = tok in ("|", "|&")
            if segs[-1].argv or segs[-1].redirects:
                segs[-1].pipe_out = piped
                segs.append(_Segment([], pipe_in=piped))
            elif piped:
                segs[-1].pipe_in = True
            i += 1
            continue
        segs[-1].argv.append(tok)
        i += 1
    return [s for s in segs if s.argv or s.redirects]


def _seg_exe(seg: _Segment) -> str:
    argv = _strip_wrappers(seg.argv)[0]
    return _exe_of(argv[0]) if argv else ""


def _exe_of(tok: str) -> str:
    name = posixpath.basename(tok.replace("\\", "/")).lower()
    return re.sub(r"\.(exe|cmd|bat|ps1|sh)$", "", name) if name not in ("[",) else name


def _strip_wrappers(argv: list[str]) -> tuple[list[str], bool, bool]:
    """(argv without env assignments / wrappers, wrapped?, elevated?)."""
    wrapped = elevated = False
    a = list(argv)
    while a:
        if _ENV_ASSIGN.match(a[0]):
            a.pop(0)
            wrapped = True
            continue
        exe = _exe_of(a[0])
        if exe not in _WRAPPERS:
            break
        wrapped = True
        elevated = elevated or exe in _ELEVATORS
        a.pop(0)
        value_opts = _WRAPPER_VALUE_OPTS.get(exe, set())
        while a and (
            a[0].startswith("-")
            or _ENV_ASSIGN.match(a[0])
            or (exe == "timeout" and re.fullmatch(r"[\d.]+[smhd]?", a[0]))
        ):
            tok = a.pop(0)
            if tok in value_opts and a:
                a.pop(0)
    return a, wrapped, elevated


# ---------------------------------------------------------------- analysis


def analyze_command(
    command: str,
    *,
    cwd: str | None = None,
    root: str | None = None,
    extra_safe: tuple[str, ...] = (),
    workspace: str | object | None = UNSET,
) -> CommandAnalysis:
    res = CommandAnalysis()
    if len(command) > MAX_COMMAND_CHARS:
        # an approver only reads a preview: a payload hidden behind kilobytes of padding must not become an approval
        res.add_deny("TOO_LARGE", "shell command is too large to be analysed")
        res.egress = True
        return res
    ws: str | None = workspace_root(root, cwd) if workspace is UNSET else workspace  # type: ignore[assignment]
    _analyze(command, res, cwd=cwd, root=root, ws=ws, depth=0, extra_safe=extra_safe)
    res.safe = not res.deny and not res.approval
    return res


def _analyze(
    command: str,
    res: CommandAnalysis,
    *,
    cwd: str | None,
    root: str | None,
    ws: str | None,
    depth: int,
    extra_safe: tuple[str, ...],
) -> None:
    if depth > MAX_DEPTH:
        res.need_approval("TOO_DEEP")
        return
    text = _flatten_newlines(command)
    low = text.lower()

    _regex_denies(text, low, res)

    if "$(" in text or "`" in text or "<(" in text or ">(" in text:
        res.need_approval("SUBSTITUTION")  # never "safe", even when the substitution is too nested to scan
    for m in _SUBST.finditer(text):  # command / process substitution: scan the inner text
        res.need_approval("SUBSTITUTION")
        inner = next(g for g in m.groups() if g is not None)
        if inner.strip():
            _analyze(inner, res, cwd=cwd, root=root, ws=ws, depth=depth + 1, extra_safe=extra_safe)
    if "<<" in text:
        res.need_approval("HEREDOC")

    tokens = split_command(text)
    segs = _segments(tokens)
    if not segs:
        if text.strip():
            res.need_approval("UNPARSEABLE")
        return

    # pipelines: [fetcher | … | shell]
    chain: list[_Segment] = []
    for seg in segs:
        if not seg.pipe_in:
            chain = []
        chain.append(seg)
        if seg.pipe_in and _seg_exe(seg) in _PIPE_SINKS:
            upstream = " ".join(" ".join(s.argv) for s in chain[:-1]).lower()
            if any(_seg_exe(s) in _FETCHERS for s in chain[:-1]):
                res.add_deny("PIPE_TO_SHELL", "remote content piped into a shell/interpreter")
            elif _DECODERS.search(upstream):
                res.add_deny("DECODE_TO_SHELL", "decoded content piped into a shell/interpreter")
            else:
                res.need_approval("PIPE_TO_INTERPRETER")

    for seg in segs:
        _segment(seg, res, cwd=cwd, root=root, ws=ws, depth=depth, extra_safe=extra_safe)


def _regex_denies(text: str, low: str, res: CommandAnalysis) -> None:
    if _FORK_BOMB.search(text):
        res.add_deny("FORK_BOMB", "fork bomb")
    if _REVERSE_SHELL.search(text):
        res.add_deny("REVERSE_SHELL", "reverse shell / raw socket redirection")
        res.egress = True
    if _WIN_DESTRUCTIVE.search(text):
        res.add_deny("DESTRUCTIVE_WINDOWS", "destructive delete/format of a drive")
    if re.search(
        r"(?i)\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|\n]*\|\s*(?:iex|invoke-expression)\b", text
    ):
        res.add_deny("PIPE_TO_SHELL", "remote content piped into Invoke-Expression")
    if _PS_ENC.search(text):
        res.add_deny("ENCODED_POWERSHELL", "encoded PowerShell command")
    if re.search(r"(?i)\b(?:eval|source|\.|(?:ba|z|da|k)?sh(?:\s+-c)?)\s+[\"']?(?:\$\(|`|<\()\s*(?:curl|wget)\b", text):
        res.add_deny("PIPE_TO_SHELL", "remote content executed through substitution")
    if re.search(r"(?i)\b(?:ba|z|da|k)?sh\s+<\(\s*(?:curl|wget)\b", text):
        res.add_deny("PIPE_TO_SHELL", "remote content executed through process substitution")
    if re.search(r">\s*/dev/(?:sd|nvme|hd|vd|disk)\w*", text):
        res.add_deny("DISK_WIPE", "write to a raw disk device")


def _segment(
    seg: _Segment,
    res: CommandAnalysis,
    *,
    cwd: str | None,
    root: str | None,
    ws: str | None,
    depth: int,
    extra_safe: tuple[str, ...],
) -> None:
    for op, target in seg.redirects:
        _redirect(op, target, res, cwd=cwd, root=root)
    argv, wrapped, elevated = _strip_wrappers(seg.argv)
    for tok in seg.argv:
        if _SKIP_PERMS.match(tok):
            res.add_deny("SKIP_PERMISSIONS", "flag that disables the permission checks of an AI tool")
    if not argv:
        if wrapped:
            res.need_approval("WRAPPER_ONLY")
        return
    exe = _exe_of(argv[0])
    args = argv[1:]
    if elevated:
        res.need_approval("PRIVILEGE_ESCALATION")
    if wrapped:
        res.need_approval("WRAPPED")

    scan = list(argv)
    if exe in _PATTERN_FIRST:  # `grep id_rsa notes.txt`: the search pattern is not a path
        for k, tok in enumerate(scan[1:], 1):
            if not tok.startswith("-"):
                del scan[k]
                break
    _token_paths(scan, res, cwd=cwd, root=root)
    _deny_classes(exe, args, res)
    _egress_flags(exe, args, res)

    inline = _inline_code(exe, args) if (exe in _SHELLS or exe in _INTERPRETERS) else None
    if inline is not None:
        if exe in _SHELLS:
            _analyze(inline, res, cwd=cwd, root=root, ws=ws, depth=depth + 1, extra_safe=extra_safe)
        else:
            if _INLINE_NET.search(inline):
                res.egress = True
            res.need_approval("INLINE_CODE")
        return
    if exe in _SHELLS or not _is_safe(exe, args, argv, extra_safe):
        res.need_approval("UNLISTED_COMMAND")
        return
    for tok in args:
        if _VAR.search(tok) or "`" in tok:
            res.need_approval("EXPANSION")
        elif _GLOB.search(tok) and _glob_hits_sensitive(tok):
            res.add_deny("SENSITIVE_PATH", "glob may expand to a protected location")
    for tok in args:
        if tok.startswith("-") or not (_abs_like(tok) or "/" in tok or "\\" in tok or tok.startswith(".")):
            continue
        if ws is None:  # no workspace known: only plainly relative paths without `..` can be vouched for
            if _abs_like(tok) or ".." in tok.replace("\\", "/").split("/"):
                res.need_approval("OUTSIDE_WORKSPACE")
        elif not within(canonical(tok, cwd, root), ws):
            res.need_approval("OUTSIDE_WORKSPACE")  # also `../../etc/hosts`: `..` is resolved before comparing


def _abs_like(tok: str) -> bool:
    return tok.startswith(("/", "~")) or bool(re.match(r"^[A-Za-z]:[\\/]", tok))


def _redirect(op: str, target: str, res: CommandAnalysis, *, cwd: str | None, root: str | None) -> None:
    if ">" in op and target not in ("/dev/null", "nul", "NUL"):
        res.need_approval("OUTPUT_REDIRECT")
    if target and not target.startswith("&"):
        cls = classify_sensitive(canonical(target, cwd, root), bare=True)
        if cls is not None:
            res.add_deny("SENSITIVE_PATH", f"redirection touches a protected location ({cls})")


def _token_paths(argv: list[str], res: CommandAnalysis, *, cwd: str | None, root: str | None) -> None:
    for tok in argv:
        value = tok
        if "=" in tok and not _abs_like(tok):
            value = tok.split("=", 1)[1]  # --output=path, of=/dev/x
        elif tok.startswith("-"):
            continue
        if not value or value.startswith("-"):
            continue
        pathy = "/" in value or "\\" in value or value.startswith(("~", ".")) or "$" in value
        cls = classify_sensitive(canonical(value, cwd, root), bare=not pathy)
        if cls is not None:
            res.add_deny("SENSITIVE_PATH", f"command touches a protected location ({cls})")
        if pathy:
            res.paths.append(value)


def _glob_hits_sensitive(token: str) -> bool:
    t = token.casefold().replace("\\", "/")
    samples = (
        "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/authorized_keys", "~/.aws/credentials", "~/.npmrc", "~/.netrc",
        ".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", ".npmrc", ".pypirc", ".netrc",
    )  # fmt: skip
    base = t.rsplit("/", 1)[-1]
    for s in samples:
        if fnmatch.fnmatchcase(s, t):
            return True
        if "/" not in t and fnmatch.fnmatchcase(s.rsplit("/", 1)[-1], base):
            return True
        if "/" in t and "/" in s and fnmatch.fnmatchcase(s, "~/" + t.removeprefix("~/").lstrip("/")):
            return True
    return False


def _inline_code(exe: str, args: list[str]) -> str | None:
    flags = {"-c", "-e", "-r", "-command", "--command", "/c", "/k"}
    for i, tok in enumerate(args):
        if i + 1 < len(args) and (tok.lower() in flags or (exe in _SHELLS and re.fullmatch(r"-[a-z]*c[a-z]*", tok))):
            return " ".join(args[i + 1 :])
    return None


def _flag_cluster(args: list[str]) -> set[str]:
    out: set[str] = set()
    for a in args:
        if a.startswith("--"):
            out.add(a.split("=", 1)[0].lower())
        elif a.startswith("-") and len(a) > 1:
            out.update("-" + ch for ch in a[1:])
    return out


def _dangerous_target(t: str) -> bool:
    low = t.lower().replace("\\", "/")
    return low in _DANGEROUS_RM or (low.rstrip("/") or "/") in _DANGEROUS_RM


def _deny_classes(exe: str, args: list[str], res: CommandAnalysis) -> None:
    flags = _flag_cluster(args)
    targets = [a for a in args if not a.startswith("-")]
    if exe in ("rm", "rmdir", "shred", "del", "erase", "rd", "remove-item", "ri"):
        recursive = bool(flags & {"-r", "-R", "--recursive", "-recurse"})
        if (recursive or "--no-preserve-root" in flags) and any(_dangerous_target(t) for t in targets):
            res.add_deny("RM_RECURSIVE_ROOT", "recursive delete of a root, home or system directory")
    if (
        exe in ("chmod", "chown", "chgrp")
        and flags & {"-R", "-r", "--recursive"}
        and any(_dangerous_target(t) for t in targets[1:])
    ):
        res.add_deny("PERMISSIONS_ROOT", "recursive permission change of a system directory")
    if exe.startswith("mkfs") or exe in ("wipefs", "fdisk", "parted", "sgdisk", "diskpart"):
        res.add_deny("DISK_WIPE", "disk partitioning / formatting")
    if exe == "dd" and any(a.lower().startswith("of=/dev/") for a in args):
        res.add_deny("DISK_WIPE", "dd to a raw device")
    if exe in ("terraform", "tofu", "terragrunt"):
        low_args = [a.lower() for a in args if not a.startswith("-chdir")]
        if "destroy" in low_args or ("apply" in low_args and "-destroy" in low_args):
            res.add_deny("INFRA_DESTROY", "infrastructure teardown (terraform destroy)")
    if exe == "aws":
        low_args = [a.lower() for a in args]
        if any(re.match(r"^(?:delete|terminate|remove|deregister|destroy)-", a) for a in low_args):
            res.add_deny("CLOUD_DELETE", "destructive AWS operation")
        elif low_args[:2] == ["s3", "rb"] or (low_args[:2] == ["s3", "rm"] and "--recursive" in low_args):
            res.add_deny("CLOUD_DELETE", "destructive AWS S3 operation")
    if (
        exe == "git"
        and args[:1] == ["push"]
        and flags & {"--force", "-f", "--force-with-lease", "--mirror", "--delete"}
    ):
        res.need_approval("GIT_FORCE_PUSH")


def _egress_flags(exe: str, args: list[str], res: CommandAnalysis) -> None:
    first = next((a for a in args if not a.startswith("-")), "")
    if exe in _EGRESS_EXES:
        res.egress = True
    subs = _EGRESS_SUBCOMMANDS.get(exe)
    if subs is not None and first in subs:
        res.egress = True
    pip_m = exe in ("python", "python3", "py") and args[:3] == ["-m", "pip", "install"]
    if pip_m:
        res.egress = True
    installer = exe in ("pip", "pip3", "pipx", "uv", "poetry", "pdm", "npm", "pnpm", "yarn", "bun") and first in (
        "install",
        "i",
        "add",
        "tool",
        "pip",
        "dlx",
    )
    if pip_m or installer or exe in ("npx", "bunx"):
        res.install = True


_INSTALL_FORBIDDEN = frozenset(
    {
        "-r", "--requirement", "-e", "--editable", "-c", "--constraint", "-i", "--index-url", "--extra-index-url",
        "--registry", "-f", "--find-links", "--trusted-host", "--no-index", "--target", "-t", "--prefix", "--root",
        "--global", "-g", "--ignore-scripts=false", "--user-agent", "--proxy", "--cert", "--no-verify",
    }
)  # fmt: skip


def _resolvable_install(exe: str, args: list[str], argv: list[str]) -> bool:
    """`pip install requests==2.32.3`, `npm install left-pad`: every target is a named package (version optional), no
    URL / path / requirements file / alternative index. Such installs are handed to the signature feed (SEC-SIG-01
    blocks known-bad versions) through the typed intent instead of asking a human for every dependency."""
    first = next((a for a in args if not a.startswith("-")), "")
    after_first = args[args.index(first) + 1 :] if first else []
    if exe in ("pip", "pip3") and first == "install":
        rest, opts = after_first, _PIP_VALUE_OPTS
    elif exe in ("python", "python3", "py") and args[:3] == ["-m", "pip", "install"]:
        rest, opts = args[3:], _PIP_VALUE_OPTS
    elif exe == "uv" and args[:2] == ["pip", "install"]:
        rest, opts = args[2:], _PIP_VALUE_OPTS
    elif exe == "uv" and first == "add":
        rest, opts = after_first, _PIP_VALUE_OPTS
    elif exe in ("npm", "pnpm", "yarn", "bun") and first in ("install", "i", "add"):
        rest, opts = after_first, _NPM_VALUE_OPTS
    else:
        return False
    if set(args) & _INSTALL_FORBIDDEN or any(a.split("=", 1)[0] in _INSTALL_FORBIDDEN for a in args):
        return False
    specs = _specs(rest, opts)
    return bool(specs) and len(packages_from_argv(argv)) == len(specs)


def _is_safe(exe: str, args: list[str], argv: list[str], extra_safe: tuple[str, ...]) -> bool:
    low = [a.lower() for a in argv]
    named = [exe, *low[1:]]
    for entry in extra_safe:
        toks = entry.lower().split()
        if toks and (low[: len(toks)] == toks or named[: len(toks)] == toks):
            return True
    if _resolvable_install(exe, args, argv):
        return True
    if exe in _SAFE_SIMPLE:
        return not (exe == "rg" and set(args) & _RG_UNSAFE)
    if exe == "find":
        return not (set(args) & _FIND_UNSAFE)
    if exe == "sort":
        return not (set(args) & _SORT_UNSAFE)
    if exe == "git":
        return _git_safe(args)
    if exe == "aws":  # read-only verbs only: `s3 ls`, `describe-*`, `list-*`, `get-*`
        verbs = [a.lower() for a in args if not a.startswith("-")]
        return len(verbs) >= 2 and (verbs[:2] == ["s3", "ls"] or verbs[1].startswith(("describe-", "list-", "get-")))
    for prefix in _SAFE_PREFIXES:
        if low[: len(prefix)] == list(prefix) or named[: len(prefix)] == list(prefix):
            return not (set(args) & _PREFIX_UNSAFE)
    return False


def _git_safe(args: list[str]) -> bool:
    a = list(args)
    while a and a[0].startswith("-"):
        if a[0] in ("--no-pager", "--paginate", "--no-optional-locks"):
            a.pop(0)
        elif a[0] == "-C" and len(a) > 1:
            a = a[2:]
        else:
            return False
    if not a:
        return False
    sub, rest = a[0], a[1:]
    if any(r.split("=", 1)[0] in _GIT_UNSAFE_FLAGS for r in rest):
        return False
    if sub == "reflog":
        return not ({"expire", "delete"} & set(rest))
    if sub in _SAFE_GIT:
        return True
    if sub == "branch":
        return all(r in ("-a", "-r", "-v", "-vv", "--list", "--show-current", "--all", "--remotes") for r in rest)
    if sub == "tag":
        return ("-l" in rest or "--list" in rest) and all(
            r in ("-l", "--list", "-n") or not r.startswith("-") for r in rest
        )
    if sub == "remote":
        return rest in ([], ["-v"], ["--verbose"])
    if sub == "stash":
        return rest[:1] == ["list"]
    if sub == "config":
        return bool(rest) and rest[0] in ("--get", "--list", "-l", "--get-all", "--show-origin")
    return False


def looks_like_network_egress(command: str, *, cwd: str | None = None, root: str | None = None) -> bool:
    """Convenience for SEC-FLOW-01: does the shell command send data out / publish / install from a registry?"""
    return analyze_command(command, cwd=cwd, root=root).egress
