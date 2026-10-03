"""Shell command analysis for SEC-TOOL-01 and SEC-FLOW-01 (concept §9 "coding-agent specifics: Shell").

    analyze_command(command, cwd=, root=, untrusted=) -> CommandAnalysis

Three outcomes, in this order of precedence:
  * `deny`   deterministic deny classes → block: `rm -rf /`-class deletes, `curl|sh` / `wget|sh` / decode-to-shell,
             `terraform destroy`, `aws … delete-*`, "skip permission" flags, reverse shells, disk wipes, and any
             access to protected locations (`~/.ssh`, `.env`, cloud credentials, wallets, browser profiles);
  * safe     every segment is a known read-only command (`git status`, `ls`, test runners, …), no output
             redirection, no unresolved expansion, paths inside the workspace → allowed without approval;
  * otherwise → `approval` reasons (everything else requires a human).

`egress` marks commands that send data out or publish (curl, git push, scp, npm publish, …); SEC-FLOW-01 treats a
call with `egress` as a sink even when the tool itself (`opencode.bash`) is not labelled `external_egress`.

`runs_code` marks commands that execute repository / workspace code or an arbitrary program: test runners and build
tools (`pytest`, `make`, `npm test`, `cargo build`, …), interpreters on a file or inline code, scripts (`./x`,
`bash x.sh`), and options that run a program (`rg --pre`, `sort --compress-program`, `git grep -O`, `find -exec`,
`git -c …`). In a clean session the safe list still applies; with `untrusted=True` (the session has read untrusted
content, which may have planted that code) such a command is never safe (`UNTRUSTED_EXEC` → approval), and
SEC-FLOW-01 treats it as an egress-capable sink: the code can open its own connections.

Output files (redirections, `tee`, `sort -o`, `--output=…`, `cp … DEST`, …) go through the write rules of the file
tools: outside the workspace → deny, persistence locations (hooks, CI, shell startup, agent instructions) → approval.
Option names are matched the way GNU getopt / git parse them: `--opt=value`, unambiguous abbreviations (`--compress`
for `--compress-program`) and glued short options (`-ovalue`, `-O./x`, `-ruo/tmp/x`).

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
from acl.controls.tools.paths import (
    UNSET,
    canonical,
    classify_sensitive,
    is_persistence_path,
    within,
    workspace_root,
)

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
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "busybox", "toybox"})
_MULTICALL = frozenset({"busybox", "toybox"})  # `busybox wget …` runs the `wget` applet
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
        "osascript",
        "tclsh",
        "rscript",
        "julia",
        "groovy",
        "ts-node",
        "tsx",
        "pypy",
        "pypy3",
        "cscript",
        "wscript",
        "mshta",
    }
)
_VERSIONED_INTERPRETER = re.compile(r"^(?:python|pypy|ruby|perl|php|node)\d+(?:\.\d+)*$")
_VERSION_FLAGS = frozenset({"--version", "-V", "--help", "-h"})
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
_INLINE_NET_MORE = re.compile(
    r"(?i)(?:require\(\s*['\"](?:node:)?(?:https?|net|dgram|tls|http2|child_process)['\"]|\bhttps?\.(?:get|request)\b"
    r"|\bfrom\s+['\"](?:node:)?(?:https?|net|dgram|tls)['\"]|Net::HTTP|open-uri|LWP::|IO::Socket|fsockopen"
    r"|file_get_contents\s*\(\s*['\"]https?:|Invoke-(?:WebRequest|RestMethod)|WebClient|\bDeno\.connect)"
)
# Environment assignments that make an otherwise harmless program run something else.
_EXEC_ENV = frozenset(
    {
        "LESSOPEN", "LESSCLOSE", "PAGER", "GIT_PAGER", "MANPAGER", "GIT_EXTERNAL_DIFF", "GIT_SSH", "GIT_SSH_COMMAND",
        "GIT_EDITOR", "GIT_ASKPASS", "SSH_ASKPASS", "EDITOR", "VISUAL", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "NODE_OPTIONS",
        "NODE_PATH", "BASH_ENV", "ENV", "PROMPT_COMMAND", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB", "PATH",
        "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR", "SHELL", "IFS",
    }
)  # fmt: skip
# Programs that run repository code (build files, test suites, configs that are code, task runners).
_CODE_RUNNERS = frozenset(
    {
        "make", "gmake", "nmake", "cmake", "ninja", "just", "task", "rake", "invoke", "nox", "tox", "npx", "bunx",
        "pnpx", "jest", "vitest", "mocha", "ava", "karma", "playwright", "cypress", "pytest", "py.test", "rspec",
        "phpunit", "mvn", "mvnw", "gradle", "gradlew", "ant", "sbt", "bazel", "bazelisk", "buck", "meson", "scons",
        "pre-commit", "mypy", "pylint", "flake8", "eslint", "prettier", "webpack", "vite", "rollup", "nodemon",
        "behave", "robot", "ctest", "dune", "stack", "cabal", "lein", "ansible-playbook", "molecule", "vagrant",
    }
)  # fmt: skip
# Subcommands that run repository code (build scripts, test suites, project scripts, hooks).
_CODE_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "uv": frozenset({"run", "sync", "build", "tool"}),
    "poetry": frozenset({"run", "install", "build", "shell"}),
    "pipenv": frozenset({"run", "install", "shell", "sync"}),
    "pdm": frozenset({"run", "install", "build", "sync"}),
    "hatch": frozenset({"run", "build", "test", "shell"}),
    "cargo": frozenset({"run", "test", "build", "check", "clippy", "bench", "install", "doc", "b", "r", "t", "c"}),
    "go": frozenset({"run", "test", "generate", "build", "install", "tool"}),
    "dotnet": frozenset({"run", "test", "build", "msbuild", "pack", "publish", "watch"}),
    "terraform": frozenset({"plan", "apply", "console", "refresh", "import"}),
    "tofu": frozenset({"plan", "apply", "console", "refresh", "import"}),
    "terragrunt": frozenset({"plan", "apply", "console", "refresh", "import", "run-all"}),
    "docker": frozenset({"build", "compose", "buildx"}),
    "podman": frozenset({"build", "compose"}),
    "bundle": frozenset({"exec", "install"}),
    "composer": frozenset({"run", "run-script", "install", "update", "test", "exec"}),
    "mix": frozenset({"test", "run", "compile"}),
    "swift": frozenset({"run", "test", "build"}),
    "zig": frozenset({"build", "run", "test"}),
}
_JS_PACKAGE_MANAGERS = frozenset({"npm", "pnpm", "yarn", "bun"})
# npm/pnpm/yarn/bun subcommands that never run a project script / lifecycle hook (any other word may be a script name)
_JS_NO_EXEC = frozenset(
    {"view", "info", "show", "ls", "list", "outdated", "why", "explain", "audit", "help", "whoami", "ping", "search"}
)
_GIT_HOOK_SUBCOMMANDS = frozenset(
    {"commit", "merge", "rebase", "am", "cherry-pick", "revert", "checkout", "switch", "pull", "push", "clone"}
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
_FIND_UNSAFE = frozenset({"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"})
_FIND_EXEC = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_FIND_OUT = frozenset({"-fprint", "-fprint0", "-fprintf", "-fls"})
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
# write-a-file options of test runners / linters / build tools (exact long names; value = path)
_TOOL_OUT_LONG = frozenset(
    {
        "output", "output-file", "junitxml", "junit-xml", "basetemp", "html-report", "outdir", "out-dir", "outfile",
        "report-dir", "log-file", "result-log", "cache-dir", "coverage-directory", "target-dir",
    }
)  # fmt: skip
_TOOL_OUT_EXES = frozenset(
    {
        "pytest", "py.test", "mypy", "ruff", "eslint", "jest", "vitest", "tsc", "pylint", "flake8", "black", "isort",
        "tox", "rspec", "phpunit", "mvn", "gradle", "pyright", "prettier", "cargo",
    }
)  # fmt: skip


# ---------------------------------------------------------------- option grammar (per program)


@dataclass(frozen=True)
class _Opts:
    """How a program parses its options (enough to find the ones that run a program or write a file)."""

    value_short: str = ""  # short options that take a value (glued or the next argument)
    value_long: frozenset[str] = frozenset()  # long options that take a value
    exec_short: str = ""  # short options that run a program
    exec_long: frozenset[str] = frozenset()  # long options that run a program (abbreviations match)
    out_short: str = ""  # short options whose value is an output file
    out_long: frozenset[str] = frozenset()  # long options whose value is an output file (abbreviations match)
    allow_short: str | None = None  # allowlist of short options (None = no allowlist)
    allow_long: frozenset[str] | None = None  # allowlist of long options (exact names)


def _fs(*names: str) -> frozenset[str]:
    return frozenset(names)


_SORT_LONG_OK = _fs(
    "ignore-leading-blanks", "dictionary-order", "ignore-case", "general-numeric-sort", "ignore-nonprinting",
    "month-sort", "human-numeric-sort", "numeric-sort", "random-sort", "reverse", "version-sort", "sort", "check",
    "merge", "stable", "unique", "zero-terminated", "key", "field-separator", "buffer-size", "parallel", "debug",
    "help", "version",
)  # fmt: skip
_SORT_VALUE_LONG = _fs(
    "key", "field-separator", "buffer-size", "temporary-directory", "output", "parallel", "compress-program",
    "random-source", "files0-from", "batch-size", "sort",
)  # fmt: skip
_RG_VALUE_LONG = _fs(
    "regexp", "file", "glob", "iglob", "type", "type-not", "max-count", "after-context", "before-context", "context",
    "threads", "max-columns", "encoding", "replace", "max-depth", "pre", "pre-glob", "hostname-bin", "type-add",
    "type-clear", "colors", "color", "sort", "sortr", "path-separator", "engine", "max-filesize", "ignore-file",
    "context-separator", "field-context-separator", "field-match-separator", "generate", "hyperlink-format",
    "dfa-size-limit", "regex-size-limit",
)  # fmt: skip
_TAR_EXEC_LONG = _fs(
    "to-command", "use-compress-program", "checkpoint-action", "info-script", "new-volume-script", "rsh-command",
    "rmt-command",
)  # fmt: skip
_CURL_OUT_LONG = _fs(
    "output", "output-dir", "dump-header", "trace", "trace-ascii", "stderr", "cookie-jar", "libcurl"
)  # fmt: skip
_OPTS: dict[str, _Opts] = {
    "sort": _Opts(
        value_short="kStTo",
        value_long=_SORT_VALUE_LONG,
        exec_long=_fs("compress-program"),
        out_short="o",
        out_long=_fs("output"),
        allow_short="bdfgiMhnRrVcCmsuzktS",
        allow_long=_SORT_LONG_OK,
    ),
    "rg": _Opts(
        value_short="efgtTmACBjMrEd", value_long=_RG_VALUE_LONG, exec_long=_fs("pre", "pre-glob", "hostname-bin")
    ),
    "tree": _Opts(value_short="LPIHTo", value_long=_fs("charset", "filelimit", "timefmt", "sort"), out_short="o"),
    "tar": _Opts(value_short="fCIFTXbHgKLMNV", exec_short="IF", exec_long=_TAR_EXEC_LONG),
    "zip": _Opts(exec_long=_fs("unzip-command")),
    "rsync": _Opts(value_short="eB", exec_short="e", exec_long=_fs("rsh", "rsync-path")),
    "curl": _Opts(value_short="AbcCdDeEFHKmoPQrtTuUwxXYyz", out_short="oDc", out_long=_CURL_OUT_LONG),
    "wget": _Opts(
        value_short="OoaAeiBtTwlPUYQRDX",
        out_short="OoaP",
        out_long=_fs("output-document", "output-file", "append-output", "directory-prefix"),
    ),
    "uniq": _Opts(value_short="fsw", value_long=_fs("skip-fields", "skip-chars", "check-chars")),
    "eslint": _Opts(value_short="cfo", out_short="o", out_long=_fs("output-file")),
    "tee": _Opts(),
}
_GIT_OPTS = _Opts(
    exec_long=_fs("ext-diff", "textconv", "open-files-in-pager", "exec", "upload-pack", "receive-pack"),
    out_long=_fs("output"),
)
_GIT_GREP_OPTS = _Opts(
    value_short="eEfABCm", exec_short="O", exec_long=_GIT_OPTS.exec_long, out_long=_GIT_OPTS.out_long
)
_GIT_VALUE_GLOBALS = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--super-prefix", "--attr-source"}
)
_COPY_LIKE = _fs("cp", "mv", "install", "ln")
_NULL_DEVICES = _fs("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "nul", "con", "$null")


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
    runs_code: bool = False  # executes repository / workspace code or an arbitrary program (module docstring)

    def add_deny(self, code: str, reason: str) -> None:
        if all(h.code != code for h in self.deny):
            self.deny.append(DenyHit(code, reason))

    def need_approval(self, code: str) -> None:
        if code not in self.approval:
            self.approval.append(code)


@dataclass(frozen=True)
class _Ctx:
    cwd: str | None
    root: str | None
    ws: str | None
    extra_safe: tuple[str, ...]
    untrusted: bool


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
        if exe in _MULTICALL:
            if len(a) > 1 and not a[1].startswith("-"):
                a.pop(0)  # `busybox wget …` / `toybox nc …`: judge the applet
                wrapped = True
                continue
            break
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
    untrusted: bool = False,
) -> CommandAnalysis:
    res = CommandAnalysis()
    if len(command) > MAX_COMMAND_CHARS:
        # an approver only reads a preview: a payload hidden behind kilobytes of padding must not become an approval
        res.add_deny("TOO_LARGE", "shell command is too large to be analysed")
        res.egress = True
        res.runs_code = True
        return res
    ws: str | None = workspace_root(root, cwd) if workspace is UNSET else workspace  # type: ignore[assignment]
    c = _Ctx(cwd=cwd, root=root, ws=ws, extra_safe=extra_safe, untrusted=untrusted)
    _analyze(command, res, c, depth=0)
    res.safe = not res.deny and not res.approval
    return res


def _analyze(command: str, res: CommandAnalysis, c: _Ctx, *, depth: int) -> None:
    if depth > MAX_DEPTH:
        res.need_approval("TOO_DEEP")
        res.runs_code = True
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
            _analyze(inner, res, c, depth=depth + 1)
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
        if seg.pipe_in and (_seg_exe(seg) in _PIPE_SINKS or _is_interpreter(_seg_exe(seg))):
            res.runs_code = True
            upstream = " ".join(" ".join(s.argv) for s in chain[:-1]).lower()
            if any(_seg_exe(s) in _FETCHERS for s in chain[:-1]):
                res.add_deny("PIPE_TO_SHELL", "remote content piped into a shell/interpreter")
            elif _DECODERS.search(upstream):
                res.add_deny("DECODE_TO_SHELL", "decoded content piped into a shell/interpreter")
            else:
                res.need_approval("PIPE_TO_INTERPRETER")

    for seg in segs:
        _segment(seg, res, c, depth=depth)


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


def _segment(seg: _Segment, res: CommandAnalysis, c: _Ctx, *, depth: int) -> None:
    for op, target in seg.redirects:
        _redirect(op, target, res, c)
    argv, wrapped, elevated = _strip_wrappers(seg.argv)
    for tok in seg.argv:
        if _SKIP_PERMS.match(tok):
            res.add_deny("SKIP_PERMISSIONS", "flag that disables the permission checks of an AI tool")
    for tok in seg.argv[: len(seg.argv) - len(argv)]:  # `LESSOPEN='|./x %s' less f`, `env PAGER=./x git log`
        name = tok.split("=", 1)[0].upper() if _ENV_ASSIGN.match(tok) else ""
        if name in _EXEC_ENV or name.startswith(("GIT_CONFIG", "LD_", "DYLD_")):
            res.need_approval("EXEC_ENV")
            res.runs_code = True
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
    _token_paths(scan, res, cwd=c.cwd, root=c.root)
    _deny_classes(exe, args, res)
    _egress_flags(exe, args, res)
    for target in _output_targets(exe, args):
        _write_target(target, res, c, "OUTPUT_FILE")

    exec_option = _exec_option(exe, args)
    if exec_option:
        res.need_approval("EXEC_OPTION")
    if exec_option or _runs_code(exe, args, argv[0], c):
        res.runs_code = True
        if c.untrusted:
            # the session has read untrusted content that may have planted this code: never "safe", and SEC-FLOW-01
            # treats the call as an egress-capable sink (the code can open its own connections)
            res.need_approval("UNTRUSTED_EXEC")

    inline = _inline_code(exe, args) if (exe in _SHELLS or _is_interpreter(exe)) else None
    if inline is not None:
        if exe in _SHELLS:
            _analyze(inline, res, c, depth=depth + 1)
        else:
            if _INLINE_NET.search(inline) or _INLINE_NET_MORE.search(inline):
                res.egress = True
            res.need_approval("INLINE_CODE")
        return
    if exe in _SHELLS or not _is_safe(exe, args, argv, c.extra_safe):
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
        if c.ws is None:  # no workspace known: only plainly relative paths without `..` can be vouched for
            if _abs_like(tok) or ".." in tok.replace("\\", "/").split("/"):
                res.need_approval("OUTSIDE_WORKSPACE")
        elif not within(canonical(tok, c.cwd, c.root), c.ws):
            res.need_approval("OUTSIDE_WORKSPACE")  # also `../../etc/hosts`: `..` is resolved before comparing


def _abs_like(tok: str) -> bool:
    return tok.startswith(("/", "~")) or bool(re.match(r"^[A-Za-z]:[\\/]", tok))


def _redirect(op: str, target: str, res: CommandAnalysis, c: _Ctx) -> None:
    if target and not target.startswith("&"):
        cls = classify_sensitive(canonical(target, c.cwd, c.root), bare=True)
        if cls is not None:
            res.add_deny("SENSITIVE_PATH", f"redirection touches a protected location ({cls})")
    if ">" in op:
        _write_target(target, res, c, "OUTPUT_REDIRECT")


def _write_target(target: str, res: CommandAnalysis, c: _Ctx, code: str) -> None:
    """A file the command writes: the write rules of the file tools (outside the workspace → deny, protected → deny,
    persistence location → approval, anything else → approval `code`)."""
    t = target.strip()
    if t.casefold() in _NULL_DEVICES or re.fullmatch(r"/dev/fd/\d+", t):
        return
    res.need_approval(code)
    if not t:
        res.add_deny("WRITE_UNRESOLVED", "output file name is missing")
        return
    path = canonical(t, c.cwd, c.root)
    if "$" in path or "`" in path or "%" in path or _GLOB.search(path):
        res.add_deny("WRITE_UNRESOLVED", "output file name contains an unresolved expansion")
        return
    cls = classify_sensitive(path)
    if cls is not None:
        res.add_deny("SENSITIVE_PATH", f"command writes to a protected location ({cls})")
    if is_persistence_path(path):
        res.need_approval("WRITE_PERSISTENCE")
    plain_relative = not (_abs_like(t) or ".." in t.replace("\\", "/").split("/"))
    if not (plain_relative if c.ws is None else within(path, c.ws)):
        res.add_deny("WRITE_OUTSIDE_WORKSPACE", "command writes a file outside the workspace")


# ---------------------------------------------------------------- options, output files, code execution


@dataclass(frozen=True)
class _Opt:
    kind: str  # "long" | "short" | "pos"
    name: str  # long name without `--`, short letter, or the positional value
    value: str | None = None


def _abbrev(name: str, options: frozenset[str]) -> bool:
    """`name` is one of `options` or an abbreviation of one (GNU getopt_long / git parse-options accept those)."""
    return bool(name) and any(o.startswith(name) for o in options)


def _scan_opts(args: list[str], spec: _Opts) -> list[_Opt]:
    out: list[_Opt] = []
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--":
            out.extend(_Opt("pos", x) for x in args[i:])
            break
        if a.startswith("--") and len(a) > 2:
            name, eq, val = a[2:].partition("=")
            name = name.lower()
            value: str | None = val if eq else None
            takes = _abbrev(name, spec.value_long | spec.out_long | spec.exec_long)
            if not eq and takes and i < len(args):
                value = args[i]
                i += 1
            out.append(_Opt("long", name, value))
        elif a.startswith("-") and len(a) > 1 and a != "-":
            body = a[1:]
            for j, ch in enumerate(body):
                if ch in spec.value_short or ch in spec.out_short:
                    value = body[j + 1 :]
                    if not value and i < len(args):
                        value = args[i]
                        i += 1
                    out.append(_Opt("short", ch, value))
                    break
                out.append(_Opt("short", ch))
        else:
            out.append(_Opt("pos", a))
    return out


def _spec_exec(opts: list[_Opt], spec: _Opts) -> bool:
    return any(
        (o.kind == "long" and _abbrev(o.name, spec.exec_long)) or (o.kind == "short" and o.name in spec.exec_short)
        for o in opts
    )


def _spec_outputs(opts: list[_Opt], spec: _Opts) -> list[str]:
    return [
        o.value or ""
        for o in opts
        if (o.kind == "long" and _abbrev(o.name, spec.out_long)) or (o.kind == "short" and o.name in spec.out_short)
    ]


def _git_split(args: list[str]) -> tuple[list[str], str, list[str]]:
    """(global options incl. their values, subcommand, the rest): `git -C . -c a=b --no-pager push …` → push."""
    globs: list[str] = []
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        tok = args[i]
        globs.append(tok)
        i += 1
        if tok in _GIT_VALUE_GLOBALS and i < len(args):
            globs.append(args[i])
            i += 1
    if i < len(args) and args[i] == "--":
        i += 1
    sub = args[i].lower() if i < len(args) else ""
    return globs, sub, args[i + 1 :]


def _git_global_exec(globs: list[str]) -> bool:
    """`-c key=value` / `--config-env` can set core.pager, core.sshCommand, alias.x=!cmd, …; `--exec-path=dir` swaps
    git's helper programs. Any of them can run an arbitrary program."""
    for g in globs:
        if g in ("-c", "--config-env") or g.startswith(("--config-env=", "--exec-path=")):
            return True
        if g.startswith("-c") and not g.startswith("--"):  # glued `-ccore.pager=…`
            return True
    return False


_TOOL_SPEC = _Opts(value_long=_TOOL_OUT_LONG)
_GO_OUT = _fs("o", "coverprofile", "cpuprofile", "memprofile", "blockprofile", "mutexprofile", "trace", "outputdir")
_GO_EXEC = _fs("exec", "toolexec")


def _go_flags(args: list[str]) -> tuple[bool, list[str]]:
    """Go's flag package: single-dash long names (`-count=1`, `-o bin/x`, `-exec prog`). (runs a program?, outputs)"""
    runs, outs = False, []
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if not a.startswith("-") or a in ("-", "--"):
            continue
        name, eq, val = a.lstrip("-").partition("=")
        if name in _GO_EXEC:
            runs = True
        if name in _GO_OUT:
            if not eq and i < len(args):
                val = args[i]
                i += 1
            outs.append(val)
    return runs, outs


def _effective_tool(exe: str, args: list[str]) -> tuple[str, list[str]]:
    """`python -m pytest …` → pytest, `uv run [opts] mypy …` → mypy (for option analysis)."""
    if _is_interpreter(exe) and len(args) >= 2 and args[0] == "-m":
        return args[1].lower(), args[2:]
    if exe == "uv" and args[:1] == ["run"]:
        k = 1
        while k < len(args) and args[k].startswith("-"):
            k += 1
        if k < len(args):
            return _effective_tool(_exe_of(args[k]), args[k + 1 :])
    return exe, args


def _exec_option(exe: str, args: list[str]) -> bool:
    """An option that makes the program execute another program (`rg --pre`, `sort --compress-program`,
    `git grep -O`, `find -exec`, `tar --to-command`, `git -c …`, `go test -exec`)."""
    exe, args = _effective_tool(exe, args)
    if exe == "go":
        return _go_flags(args)[0]
    if exe == "find":
        return any(a.lower() in _FIND_EXEC for a in args)
    if exe == "git":
        globs, sub, rest = _git_split(args)
        if _git_global_exec(globs):
            return True
        spec = _GIT_GREP_OPTS if sub == "grep" else _GIT_OPTS
        return _spec_exec(_scan_opts(rest, spec), spec)
    spec = _OPTS.get(exe)
    return spec is not None and _spec_exec(_scan_opts(args, spec), spec)


def _output_targets(exe: str, args: list[str]) -> list[str]:
    """Files the command writes through its own options / arguments (redirections are handled separately)."""
    exe, args = _effective_tool(exe, args)
    if exe == "go":
        return _go_flags(args)[1]
    if exe == "git":
        _, _, rest = _git_split(args)
        return _spec_outputs(_scan_opts(rest, _GIT_OPTS), _GIT_OPTS)
    if exe == "find":
        return [args[k + 1] if k + 1 < len(args) else "" for k, a in enumerate(args) if a.lower() in _FIND_OUT]
    if exe == "dd":
        return [a.split("=", 1)[1] for a in args if a.lower().startswith("of=")]
    if exe in _COPY_LIKE:
        spec = _Opts(value_short="tSmog", value_long=_fs("target-directory", "suffix", "mode", "owner", "group"))
        opts = _scan_opts(args, spec)
        targets = [
            o.value or ""
            for o in opts
            if (o.kind == "short" and o.name == "t") or (o.kind == "long" and _abbrev(o.name, _fs("target-directory")))
        ]
        positional = [o.name for o in opts if o.kind == "pos"]
        if not targets and len(positional) >= 2:
            targets.append(positional[-1])
        return targets
    found: list[str] = []
    if exe in _TOOL_OUT_EXES:  # exact names only: `pytest --co` must not read as an abbreviation of an output option
        found = [o.value or "" for o in _scan_opts(args, _TOOL_SPEC) if o.kind == "long" and o.name in _TOOL_OUT_LONG]
    spec = _OPTS.get(exe)
    if spec is None:
        return found
    opts = _scan_opts(args, spec)
    found.extend(_spec_outputs(opts, spec))
    positional = [o.name for o in opts if o.kind == "pos"]
    if exe == "tee":
        found.extend(positional)
    elif exe == "uniq" and len(positional) >= 2:
        found.append(positional[1])  # `uniq INPUT OUTPUT`
    return found


def _is_interpreter(exe: str) -> bool:
    return exe in _INTERPRETERS or bool(_VERSIONED_INTERPRETER.match(exe))


def _first_positional(args: list[str]) -> str:
    return next((a.lower() for a in args if not a.startswith("-")), "")


def _local_install(args: list[str]) -> bool:
    """`pip install .` / `-e .` / `-r req.txt` builds or reads the workspace (runs setup.py / build backends)."""
    return any(
        a in (".", "..") or a.startswith(("./", "../", "/", "~", "-e", "--editable", "-r", "--requirement")) or "/" in a
        for a in args
    )


def _runs_code(exe: str, args: list[str], argv0: str, c: _Ctx) -> bool:
    """Does the command execute repository / workspace code (or code given inline)?"""
    tok = argv0.replace("\\", "/")
    if "/" in tok or tok.startswith("."):  # `./run.sh`, `scripts/x`, `~/bin/x`, `/work/proj/bin/x`
        if not _abs_like(tok) or tok.startswith("~"):
            return True
        if c.ws is None or within(canonical(tok, c.cwd, c.root), c.ws):
            return True
        # an absolute program outside the workspace (`/usr/bin/python3 x.py`) is judged by its name below
    if _is_interpreter(exe):
        if exe.startswith(("python", "py")) and [a.lower() for a in args[:2]] == ["-m", "pip"]:
            return _local_install(args[2:])
        return not (args and all(a in _VERSION_FLAGS for a in args))
    if exe in _SHELLS:
        return _inline_code(exe, args) is None  # `bash x.sh` / stdin; `bash -c '…'` is analysed recursively
    if exe in ("source", ".") or exe in _CODE_RUNNERS:
        return True
    first = _first_positional(args)
    if exe in _JS_PACKAGE_MANAGERS:
        if not first or first in _JS_NO_EXEC:
            return False
        named = [a for a in args[args.index(first) + 1 :] if not a.startswith("-")] if first in args else []
        if first in ("install", "i", "add") and named:
            return _local_install(named)  # a named dependency is the signature feed's job (SEC-SIG-01)
        return True  # a project script, or a lifecycle hook of the project (install / ci / version / pack, …)
    if exe in ("pip", "pip3"):
        return first == "install" and _local_install(args)
    if exe == "git":
        globs, sub, _ = _git_split(args)
        return _git_global_exec(globs) or sub in _GIT_HOOK_SUBCOMMANDS
    subs = _CODE_SUBCOMMANDS.get(exe)
    if subs is not None:
        if exe == "uv" and first == "pip":
            return _local_install(args)
        return first in subs
    return False


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


_SHELL_INLINE = frozenset({"-c", "/c", "/k", "-command", "--command"})
_INTERPRETER_INLINE = frozenset(
    {"-c", "-e", "-E", "-r", "-p", "--eval", "--print", "-command", "--command", "/c", "/k"}
)


def _inline_code(exe: str, args: list[str]) -> str | None:
    """The inline program of `bash -c …` / `python -c …` / `node -e …` (None: no inline code)."""
    shell = exe in _SHELLS
    for i, tok in enumerate(args):
        if i + 1 >= len(args):
            break
        if shell and (tok.lower() in _SHELL_INLINE or re.fullmatch(r"-[a-z]*c[a-z]*", tok)):
            return " ".join(args[i + 1 :])
        if not shell and (tok in _INTERPRETER_INLINE or tok.lower() in ("-command", "--command")):
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
    if exe == "git":
        _, sub, rest = _git_split(args)  # `git -C . push --force`: global options come before the subcommand
        if sub == "push" and _flag_cluster(rest) & {"--force", "-f", "--force-with-lease", "--mirror", "--delete"}:
            res.need_approval("GIT_FORCE_PUSH")


def _egress_flags(exe: str, args: list[str], res: CommandAnalysis) -> None:
    first = next((a for a in args if not a.startswith("-")), "")
    if exe == "git":
        first = _git_split(args)[1]  # `git -C . push`, `git -c a=b push`
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
    if _exec_option(exe, args) or _output_targets(exe, args):
        return False  # reported with their own codes (EXEC_OPTION, OUTPUT_FILE, WRITE_*)
    if exe == "sort":  # allowlist of options: anything else (-T, --random-source, --files0-from, …) needs a human
        spec = _OPTS["sort"]
        return all(
            o.kind == "pos"
            or (o.kind == "short" and o.name in (spec.allow_short or ""))
            or (o.kind == "long" and o.name in (spec.allow_long or frozenset()))
            for o in _scan_opts(args, spec)
        )
    if exe in _SAFE_SIMPLE:
        return True
    if exe == "find":
        return not ({a.lower() for a in args} & _FIND_UNSAFE)
    if exe == "git":
        return _git_safe(args)
    if exe == "aws":  # read-only verbs only: `s3 ls`, `describe-*`, `list-*`, `get-*`
        verbs = [a.lower() for a in args if not a.startswith("-")]
        return len(verbs) >= 2 and (verbs[:2] == ["s3", "ls"] or verbs[1].startswith(("describe-", "list-", "get-")))
    for prefix in _SAFE_PREFIXES:
        if low[: len(prefix)] == list(prefix) or named[: len(prefix)] == list(prefix):
            # `--fix=true` counts like `--fix`; for the inspection CLIs `--output` only picks a format (`-o json`)
            unsafe = (
                _PREFIX_UNSAFE - {"--output"} if exe in ("kubectl", "docker", "gh", "terraform") else _PREFIX_UNSAFE
            )
            return not any(a.split("=", 1)[0].lower() in unsafe for a in args)
    return False


def _git_safe(args: list[str]) -> bool:
    globs, sub, rest = _git_split(args)
    k = 0
    while k < len(globs):  # only harmless global options; `-c`, `--git-dir`, `--exec-path`, … are never "safe"
        if globs[k] in ("--no-pager", "--paginate", "-P", "--no-optional-locks"):
            k += 1
        elif globs[k] == "-C" and k + 1 < len(globs):
            k += 2
        else:
            return False
    if not sub:
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
