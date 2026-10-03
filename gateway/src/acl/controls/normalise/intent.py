"""Typed normalisation of tool calls → `ToolIntent` (concept §6.2 stage 0).

`validate_arguments` rejects malformed calls (fail closed); `build_intent` extracts canonical paths,
URLs, domains, argv, SQL, recipients and installed packages from the (already normalised) arguments.
Heuristics are key-name driven plus a shell-command parser; they are advisory inputs for the tool
policy checkers and for the signature feed, not an authorisation decision by themselves.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from typing import Any
from urllib.parse import urlsplit

from acl.contracts.inspection import Package, ToolCallPayload, ToolIntent

PATH_KEYS = frozenset(
    [
        "path",
        "paths",
        "file",
        "files",
        "file_path",
        "filepath",
        "filename",
        "filenames",
        "dir",
        "directory",
        "folder",
        "cwd",
        "workdir",
        "working_directory",
        "src",
        "dst",
        "dest",
        "destination",
        "old_path",
        "new_path",
        "output_path",
        "input_path",
    ]
)
URL_KEYS = frozenset(["url", "urls", "uri", "endpoint", "href", "link", "webhook", "base_url", "location"])
COMMAND_KEYS = frozenset(["command", "cmd", "script", "shell", "bash", "commandline", "command_line"])
SQL_KEYS = frozenset(["sql", "statement", "queries", "query"])
RECIPIENT_KEYS = frozenset(["to", "cc", "bcc", "recipient", "recipients", "email", "emails", "mailto"])
HOST_KEYS = frozenset(["host", "hostname", "domain", "server"])
PACKAGE_KEYS = frozenset(["packages", "package", "dependencies", "requirements"])

# keys whose value must be a string (or a list of strings); anything else is a malformed call
_STRICT_STRING_KEYS = frozenset(
    [
        "path",
        "file_path",
        "filepath",
        "filename",
        "cwd",
        "workdir",
        "dir",
        "directory",
        "url",
        "uri",
        "command",
        "cmd",
        "commandline",
        "command_line",
        "sql",
        "statement",
    ]
)

URL_RE = _URL = re.compile(r"(?i)\b(?:https?|ftps?|sftp|ssh|git|wss?|file)://[^\s\"'<>`]+")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_SQL_START = re.compile(
    r"(?is)^\s*(?:with|select|insert|update|delete|drop|alter|create|truncate|merge|explain|pragma)\b"
)
_WIN_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_RELPATH = re.compile(r"^[\w.@+\-]+(?:/[\w.@+\-]+)+/?$")
_ENV_PREFIX = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_NET_EXES = frozenset(
    [
        "curl",
        "wget",
        "nc",
        "ncat",
        "ssh",
        "scp",
        "sftp",
        "ftp",
        "telnet",
        "ping",
        "nslookup",
        "dig",
        "host",
        "rsync",
        "git",
    ]
)
_FILE_EXTENSIONS = frozenset(
    [
        "json",
        "txt",
        "log",
        "py",
        "js",
        "ts",
        "md",
        "yaml",
        "yml",
        "csv",
        "xml",
        "html",
        "htm",
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "zip",
        "tar",
        "gz",
        "tgz",
        "conf",
        "cfg",
        "ini",
        "toml",
        "sql",
        "db",
        "out",
        "bin",
        "sh",
        "rb",
        "pl",
        "php",
        "java",
        "c",
        "h",
        "cpp",
        "exe",
        "dll",
        "so",
        "whl",
        "lock",
        "tmp",
        "bak",
    ]
)
_SEGMENT_BREAKS = frozenset({";", "&&", "||", "|", "&", "(", ")", "|&", "&;"})
_WRAPPERS = frozenset({"sudo", "env", "time", "command", "nohup", "exec", "nice", "doas", "xargs"})


class MalformedCall(ValueError):
    """A tool call that cannot be normalised safely. `code` is a stable, value-free identifier."""

    def __init__(self, code: str, field: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.field = field


# --------------------------------------------------------------------------- validation


def _check_str_or_list(value: Any, field: str) -> None:
    if isinstance(value, str):
        _check_nul(value, field)
        return
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        for v in value:
            _check_nul(v, field)
        return
    raise MalformedCall("non_string_argument", field)


def _check_nul(s: str, field: str) -> None:
    if "\x00" in s:
        raise MalformedCall("nul_byte", field)


def validate_arguments(tool: str, arguments: Any, prefix: str = "arguments") -> None:
    """Fail closed on structurally invalid calls (raises `MalformedCall`)."""
    if not isinstance(tool, str) or not tool.strip():
        raise MalformedCall("empty_tool_name", "tool")
    if not isinstance(arguments, dict):
        raise MalformedCall("arguments_not_object", prefix)
    for key, value in arguments.items():
        if not isinstance(key, str):
            raise MalformedCall("non_string_key", prefix)
        lk = key.lower()
        field = f"{prefix}.{key}"
        if lk in _STRICT_STRING_KEYS:
            _check_str_or_list(value, field)


# --------------------------------------------------------------------------- paths


def canonical_path(raw: str, cwd: str | None, root: str | None) -> str:
    p = raw.strip()
    if p.lower().startswith("file://"):
        p = p[7:]
        if p.lower().startswith("localhost/"):
            p = p[9:]
        if _WIN_DRIVE.match(p[1:]) if p.startswith("/") else False:
            p = p[1:]
    p = p.replace("\\", "/")
    for home in ("$HOME", "${HOME}", "%USERPROFILE%", "%HOME%"):
        if p.startswith(home):
            p = "~" + p[len(home) :]
    if p.startswith("~"):
        head, sep, rest = p.partition("/")
        return head + (posixpath.normpath("/" + rest) if sep else "")
    if _WIN_DRIVE.match(p):
        return p[0].upper() + ":" + posixpath.normpath(p[2:])
    if not p.startswith("/"):
        base = (cwd or root or "").replace("\\", "/")
        if base and not (base.startswith("/") or _WIN_DRIVE.match(base)) and root:
            base = posixpath.join(root.replace("\\", "/"), base)
        p = posixpath.join(base, p) if base else p
        if _WIN_DRIVE.match(p):
            return p[0].upper() + ":" + posixpath.normpath(p[2:])
    return posixpath.normpath(p) if p else p


def _path_like(tok: str) -> bool:
    if "://" in tok:
        return False
    if tok.startswith(("/", "~", "./", "../", ".\\", "..\\", "$HOME", "${HOME}")) or _WIN_DRIVE.match(tok):
        return True
    return bool(_RELPATH.match(tok))


# --------------------------------------------------------------------------- hosts / urls


def _clean_url(u: str) -> str:
    return u.rstrip(".,;:!?)]}'\"")


def host_of_url(url: str) -> str | None:
    try:
        host = urlsplit(url if "://" in url else "//" + url).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def host_of_token(tok: str) -> str | None:
    """`user@host:path`, `host:port/x`, `host` → host if it looks like a domain or IPv4."""
    t = tok
    has_user = "@" in t
    if has_user:
        t = t.rsplit("@", 1)[1]
    t = re.split(r"[:/]", t, maxsplit=1)[0].lower().rstrip(".")
    if _IPV4.match(t):
        return t
    if _DOMAIN.match(t):
        # `out.json`, `run.py`: file names that happen to look like hostnames
        if not has_user and t.rsplit(".", 1)[1] in _FILE_EXTENSIONS:
            return None
        return t
    return None


# --------------------------------------------------------------------------- shell command parsing


def split_command(command: str) -> list[str]:
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.escape = ""  # keep backslashes literal (Windows paths)
        return list(lex)
    except ValueError:
        return command.split()


def _segments(argv: list[str]) -> list[list[str]]:
    segs: list[list[str]] = [[]]
    for tok in argv:
        if tok in _SEGMENT_BREAKS:
            segs.append([])
        else:
            segs[-1].append(tok)
    return [s for s in segs if s]


_PIP_VALUE_OPTS = frozenset(
    [
        "-r",
        "-c",
        "-e",
        "-i",
        "-f",
        "-t",
        "--requirement",
        "--constraint",
        "--editable",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--target",
        "--prefix",
        "--root",
        "--proxy",
        "--cache-dir",
        "--src",
        "--platform",
        "--python-version",
        "--implementation",
        "--abi",
        "--only-binary",
        "--no-binary",
        "--python",
    ]
)
_NPM_VALUE_OPTS = frozenset(["--registry", "--prefix", "--cache", "--userconfig", "--workspace", "-w", "--tag"])
_PY_REQ = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:(===|==|~=|>=|<=|!=|>|<)\s*([A-Za-z0-9.*+!_-]+))?(?:\s*[;,].*)?$"
)


def _pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _specs(tokens: list[str], value_opts: frozenset[str]) -> list[str]:
    out: list[str] = []
    skip = False
    for tok in tokens:
        if skip:
            skip = False
            continue
        if tok.startswith("-"):
            if tok in value_opts:
                skip = True
            continue
        out.append(tok)
    return out


def _parse_pypi(spec: str) -> Package | None:
    if "/" in spec or spec.startswith(".") or "://" in spec or spec.endswith((".whl", ".zip", ".tar.gz", ".txt")):
        return None
    m = _PY_REQ.match(spec)
    if not m:
        return None
    version = m.group(3) if m.group(2) in ("==", "===") else None
    return Package(ecosystem="pypi", name=_pypi_name(m.group(1)), version=version)


def _parse_npm(spec: str) -> Package | None:
    if spec.startswith((".", "/")) or "://" in spec or spec.startswith(("git+", "file:", "github:")):
        return None
    if spec.startswith("@"):
        if "/" not in spec:
            return None
        scope, _, rest = spec.partition("/")
        name_part, sep, version = rest.partition("@")
        name = f"{scope}/{name_part}"
    else:
        if "/" in spec:
            return None
        name, sep, version = spec.partition("@")
    if not name:
        return None
    return Package(ecosystem="npm", name=name.lower(), version=version if sep and version else None)


def packages_from_argv(argv: list[str]) -> list[Package]:
    pkgs: list[Package] = []
    for seg in _segments(argv):
        while seg and (_ENV_PREFIX.match(seg[0]) or seg[0] in _WRAPPERS):
            seg = seg[1:]
        if not seg:
            continue
        exe = posixpath.basename(seg[0].replace("\\", "/")).lower()
        exe = re.sub(r"\.(exe|cmd|bat)$", "", exe)
        rest = seg[1:]
        py_specs: list[str] | None = None
        npm_specs: list[str] | None = None
        if re.fullmatch(r"pip[\d.]*", exe) and rest[:1] == ["install"]:
            py_specs = _specs(rest[1:], _PIP_VALUE_OPTS)
        elif re.fullmatch(r"python[\d.]*|py", exe) and rest[:3] == ["-m", "pip", "install"]:
            py_specs = _specs(rest[3:], _PIP_VALUE_OPTS)
        elif exe == "uv" and rest[:2] == ["pip", "install"]:
            py_specs = _specs(rest[2:], _PIP_VALUE_OPTS)
        elif exe == "uv" and rest[:1] == ["add"]:
            py_specs = _specs(rest[1:], _PIP_VALUE_OPTS)
        elif exe == "uv" and rest[:2] == ["tool", "install"]:
            py_specs = _specs(rest[2:], _PIP_VALUE_OPTS)
        elif exe in ("pipx", "poetry", "pdm", "pipenv") and rest[:1] in (["install"], ["add"]):
            py_specs = _specs(rest[1:], _PIP_VALUE_OPTS)
        elif exe in ("uvx", "pipx") and rest[:1] == ["run"]:
            py_specs = _specs(rest[1:2], _PIP_VALUE_OPTS)
        elif exe in ("npm", "pnpm", "yarn", "bun") and rest[:1] in (["install"], ["i"], ["add"], ["install-test"]):
            npm_specs = _specs(rest[1:], _NPM_VALUE_OPTS)
        elif exe in ("npx", "bunx") or (exe == "pnpm" and rest[:1] == ["dlx"]):
            npm_specs = _specs(rest[1:] if exe == "pnpm" else rest, _NPM_VALUE_OPTS)[:1]
        for s in py_specs or []:
            p = _parse_pypi(s)
            if p:
                pkgs.append(p)
        for s in npm_specs or []:
            p = _parse_npm(s)
            if p:
                pkgs.append(p)
    return pkgs


# --------------------------------------------------------------------------- intent builder


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out: list[str] = []
        for v in value:
            out.extend(_strings(v))
        return out
    if isinstance(value, dict):
        out = []
        for v in value.values():
            out.extend(_strings(v))
        return out
    return []


def _walk(value: Any, key: str = ""):
    """Yield (nearest dict key lower-cased, string) for every string leaf, in document order."""
    if isinstance(value, str):
        yield key, value
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                yield from _walk(v, k.lower())
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v, key)


def _add(seq: list[str], item: str | None) -> None:
    if item and item not in seq:
        seq.append(item)


def build_intent(payload: ToolCallPayload) -> ToolIntent:
    """Typed intent of a tool call (arguments are expected to be normalised already)."""
    cwd, root = payload.cwd, payload.workspace_root
    paths: list[str] = []
    urls: list[str] = []
    domains: list[str] = []
    recipients: list[str] = []
    packages: list[Package] = []
    command: str | None = None
    argv: list[str] = []
    sql: list[str] = []
    tool_hint = payload.tool.lower()

    def add_path(raw: str) -> None:
        if raw.strip():
            _add(paths, canonical_path(raw, cwd, root))

    def add_url(raw: str) -> None:
        u = _clean_url(raw)
        _add(urls, u)
        _add(domains, host_of_url(u))
        if u.lower().startswith("file://"):
            add_path(u)

    def handle_command(cmd: str, tokens: list[str] | None = None) -> None:
        nonlocal command, argv
        toks = tokens if tokens is not None else split_command(cmd)
        if command is None:
            command, argv = cmd, toks
        packages.extend(packages_from_argv(toks))
        for u in _URL.findall(cmd):
            add_url(u)
        net = False
        for seg in _segments(toks):
            seg2 = [t for t in seg if not _ENV_PREFIX.match(t) and t not in _WRAPPERS]
            if seg2:
                net = posixpath.basename(seg2[0].lower()) in _NET_EXES
            for tok in seg2:
                if net and not tok.startswith("-"):
                    _add(domains, host_of_token(tok))
                value = tok.split("=", 1)[1] if tok.startswith("--") and "=" in tok else tok
                if _path_like(value):
                    add_path(value)

    plain = {}
    for k, v in payload.arguments.items():
        if k.lower() in COMMAND_KEYS and isinstance(v, list) and v and all(isinstance(t, str) for t in v):
            handle_command(" ".join(v), list(v))  # argv given directly
        else:
            plain[k] = v

    for key, value in _walk(plain):
        if key in COMMAND_KEYS:
            handle_command(value)
        elif key in PATH_KEYS:
            add_path(value)
        elif key in URL_KEYS:
            if "://" in value or value.startswith("//") or host_of_token(value):
                add_url(value if "://" in value else "http://" + value.lstrip("/"))
            else:
                add_path(value)
        elif key in HOST_KEYS:
            _add(domains, host_of_token(value) or host_of_url(value))
        elif key in RECIPIENT_KEYS:
            for e in _EMAIL.findall(value):
                _add(recipients, e.lower())
        elif key in SQL_KEYS and (key != "query" or _SQL_START.match(value)):
            sql.append(value.strip())
        elif key in PACKAGE_KEYS:
            eco_npm = any(h in tool_hint for h in ("npm", "node", "yarn", "pnpm"))
            p = _parse_npm(value) if eco_npm else _parse_pypi(value)
            if p:
                packages.append(p)
        else:
            for u in _URL.findall(value):
                add_url(u)

    # `name` + `version` pairs next to an install-ish tool name
    args = payload.arguments
    if any(w in tool_hint for w in ("install", "package", "pip", "npm")) and isinstance(args.get("version"), str):
        nm = args.get("package") or args.get("name")
        if isinstance(nm, str) and nm:
            eco = "npm" if any(h in tool_hint for h in ("npm", "node", "yarn", "pnpm")) else "pypi"
            packages.append(
                Package(ecosystem=eco, name=_pypi_name(nm) if eco == "pypi" else nm.lower(), version=args["version"])
            )

    uniq: list[Package] = []
    for p in packages:
        if p not in uniq:
            uniq.append(p)
    return ToolIntent(
        paths=paths,
        urls=urls,
        domains=domains,
        command=command,
        argv=argv,
        sql="\n".join(sql) if sql else None,
        recipients=recipients,
        packages=uniq,
    )
