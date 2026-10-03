"""Path canonicalisation and path policy for SEC-TOOL-01 (concept §9 "coding-agent specifics: Files").

Client-local tools (OpenCode `read`/`write`/`edit`/`bash`) act on the *user's* machine, so the gateway can only
reason about the path *string* (lexical canonicalisation against `workspace_root` / `cwd`). Symlink escape
detection is therefore N/A for client-local tools: the gateway host cannot `realpath` a path that lives on the
developer's laptop (and the files MCP server runs in its own container). The plugin must resolve symlinks
before calling `/v1/decide` (documented limitation); the lexical rules below are applied to whatever it sends.

Rules (all deterministic, no I/O):
  * `~/.ssh`, private keys, `.env*`, cloud/registry credentials, browser profiles and crypto wallets are denied
    wherever they sit (also inside the workspace): class codes `SENSITIVE:<class>`;
  * `workspace_only`: the canonical path must be inside `workspace_root` (else `cwd`); `..` is resolved
    lexically first, so `src/../../etc/passwd` escapes and is denied;
  * group `path_deny` globs always deny, group `path_allow` globs (when set) must match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import unquote

from acl.controls.normalise.intent import canonical_path

_WIN_DRIVE = re.compile(r"^[A-Za-z]:")
UNSET: object = object()  # "argument not given" (None already means "workspace unknown")

# ---------------------------------------------------------------- sensitive locations
# Patterns run on the casefolded canonical path with "/" separators.

_ENV_OK_SUFFIX = ("example", "sample", "template", "dist", "defaults", "default")

_DIR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ssh", re.compile(r"(?:^|/)\.ssh(?:/|$)")),
    ("cloud_creds", re.compile(r"(?:^|/)\.(?:aws|azure|kube|gnupg|oci|password-store)(?:/|$)")),
    ("cloud_creds", re.compile(r"(?:^|/)\.config/(?:gcloud|gh|op|rclone|doctl|heroku)(?:/|$)")),
    ("cloud_creds", re.compile(r"(?:^|/)\.(?:docker/config\.json|terraform\.d/credentials[^/]*)$")),
    ("cloud_creds", re.compile(r"^/etc/(?:shadow|gshadow|sudoers)(?:/|$)")),
    ("env_dump", re.compile(r"^/proc/[^/]+/environ$")),
    (
        "browser",
        re.compile(
            r"(?:^|/)(?:google/chrome|chromium|microsoft/edge|bravesoftware|vivaldi|opera software"
            r"|\.mozilla|mozilla/firefox)(?:/|$)"
        ),
    ),
    ("browser", re.compile(r"(?:^|/)library/application support/(?:google/chrome|firefox|microsoft edge|brave)")),
    ("browser", re.compile(r"(?:^|/)\.config/(?:google-chrome|chromium|microsoft-edge|brave)")),
    ("wallet", re.compile(r"(?:^|/)\.(?:bitcoin|electrum|exodus|monero|metamask)(?:/|$)")),
    ("wallet", re.compile(r"(?:^|/)\.(?:ethereum/keystore|config/solana)(?:/|$)")),
)

_BASENAME_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"^id_(?:rsa|dsa|ecdsa|ed25519)(?!.*\.pub$).*$")),
    ("private_key", re.compile(r"^.+\.(?:key|p12|pfx|ppk|jks|keystore)$")),
    ("private_key", re.compile(r"^(?:.*[-_.])?(?:priv|private|secret)[^/]*\.pem$")),
    ("env", re.compile(r"^\.env(?:\..+)?$")),
    (
        "cloud_creds",
        re.compile(
            r"^(?:\.npmrc|\.pypirc|\.netrc|_netrc|\.git-credentials|\.pgpass|\.my\.cnf|\.vault-token|\.databrickscfg"
            r"|credentials\.json|client_secret[^/]*\.json|service[-_]?account[^/]*\.json|secrets?\.(?:ya?ml|json|toml)"
            r"|.+\.tfstate(?:\.backup)?|terraform\.tfvars)$"
        ),
    ),
    ("browser", re.compile(r"^(?:login data|cookies|web data|key4\.db|logins\.json|cookies\.sqlite)$")),
    ("wallet", re.compile(r"^(?:wallet\.dat|utc--.+)$")),
)

# Files that make a write persistent or self-executing (hooks, CI, editor tasks, agent instructions, shell startup).
# A write there is not blocked but needs a human (concept §9: repo content is untrusted, and an injected instruction
# that plants itself in AGENTS.md or a hook outlives the session).
_PERSISTENCE = re.compile(
    r"(?:^|/)(?:\.git/(?:hooks/|config$)|\.github/(?:workflows|actions)/|\.gitlab-ci\.ya?ml$|\.husky/|\.vscode/"
    r"|\.idea/|\.envrc$|\.claude/|\.opencode/|opencode\.jsonc?$|agents\.md$|claude\.md$|\.cursor/|\.cursorrules$"
    r"|\.(?:bash|zsh)rc$|\.(?:bash_)?profile$|\.zprofile$|\.bash_login$|crontab$|authorized_keys$"
    r"|\.config/(?:autostart|systemd)/|start menu/programs/startup/)"
)


def is_persistence_path(path: str) -> bool:
    return bool(_PERSISTENCE.search(path.replace("\\", "/").casefold()))


# Basenames that are unambiguous even as a bare shell token (no directory part): `cat .env`, `scp id_rsa host:`.
_BARE_CLASSES = frozenset({"env", "private_key"})
_BARE_NAMES = re.compile(r"^(?:\.npmrc|\.pypirc|\.netrc|_netrc|\.git-credentials|\.pgpass|\.vault-token)$")


def classify_sensitive(path: str, *, bare: bool = False) -> str | None:
    """Sensitive-location class of a canonical path (None if not sensitive). `bare`: a lone token without `/`."""
    p = path.replace("\\", "/").casefold().rstrip("/")
    if not p:
        return None
    base = p.rsplit("/", 1)[-1]
    if bare and "/" not in p:
        for code, rx in _BASENAME_PATTERNS:
            if code in _BARE_CLASSES and rx.match(base) and not _env_template(base):
                return code
        return "cloud_creds" if _BARE_NAMES.match(base) else None
    for code, rx in _DIR_PATTERNS:
        if rx.search(p):
            return code
    for code, rx in _BASENAME_PATTERNS:
        if rx.match(base):
            if code == "env" and _env_template(base):
                continue
            return code
    return None


def _env_template(base: str) -> bool:
    return base.startswith(".env.") and base.rsplit(".", 1)[-1] in _ENV_OK_SUFFIX


# ---------------------------------------------------------------- canonicalisation


def is_windows_path(path: str) -> bool:
    return bool(_WIN_DRIVE.match(path))


def canonical(raw: str, cwd: str | None, root: str | None) -> str:
    """Lexically canonical form: `/` separators, `~`/`$HOME` kept symbolic, `..` resolved, joined to cwd/root."""
    p = canonical_path(raw, cwd, root)
    p = p.replace("\\", "/")
    if len(p) > 1:
        p = p.rstrip("/")
    return p


def within(path: str, root: str) -> bool:
    """Is `path` equal to or below `root` (both canonical; case-insensitive when a Windows drive is involved)."""
    a, b = path, root.rstrip("/") or "/"
    if is_windows_path(a) or is_windows_path(b):
        a, b = a.casefold(), b.casefold()
    if b == "/":
        return a.startswith("/")
    return a == b or a.startswith(b + "/")


@lru_cache(maxsize=512)
def glob_regex(pattern: str) -> re.Pattern[str]:
    """gitignore-flavoured glob → regex: `**` crosses `/`, `*` and `?` do not; `**/` and `/**` are optional."""
    i, out = 0, []
    pat = pattern.replace("\\", "/")
    while i < len(pat):
        c = pat[i]
        if c == "*":
            if pat[i : i + 2] == "**":
                i += 2
                if pat[i : i + 1] == "/":
                    i += 1
                    out.append("(?:.*/)?")
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out), re.IGNORECASE | re.DOTALL)


def glob_match(pattern: str, path: str, root: str | None = None) -> bool:
    """Match a group `path_allow`/`path_deny` glob against a canonical path."""
    pat = pattern.strip()
    if not pat:
        return False
    rx = glob_regex(pat)
    if "/" not in pat.strip("/") and not pat.startswith(("/", "~")) and not is_windows_path(pat):
        return bool(rx.fullmatch(path.rsplit("/", 1)[-1]))  # bare name: matches at any depth (gitignore)
    if pat.startswith(("/", "~")) or is_windows_path(pat):
        return bool(rx.fullmatch(path))
    if root and within(path, root):
        rel = path[len(root.rstrip("/")) :].lstrip("/")
        return bool(rx.fullmatch(rel)) or bool(rx.fullmatch(path.lstrip("/")))
    return bool(glob_regex("**/" + pat.lstrip("/")).fullmatch(path))


# ---------------------------------------------------------------- policy


@dataclass(frozen=True)
class PathViolation:
    code: str  # SENSITIVE | OUTSIDE_WORKSPACE | ROOT_UNKNOWN | DENIED | NOT_ALLOWED
    reason: str
    path_class: str | None = None


def workspace_root(root: str | None, cwd: str | None) -> str | None:
    base = root or cwd
    if not base or not base.strip():
        return None
    return canonical(base, None, None)


def check_path(
    raw: str,
    *,
    cwd: str | None,
    root: str | None,
    workspace_only: bool,
    allow: tuple[str, ...] = (),
    deny: tuple[str, ...] = (),
    bare: bool = False,
    workspace: str | object | None = UNSET,
) -> list[PathViolation]:
    """Violations for one path argument (empty = fine).

    `workspace` pins the containment root (None = "unknown"; UNSET = derive it from root/cwd). Callers pass it whenever
    `cwd` can be influenced by the model (a `workdir` argument): otherwise a missing `workspace_root` would let the
    model pick its own workspace."""
    out: list[PathViolation] = []
    ws: str | None = workspace_root(root, cwd) if workspace is UNSET else workspace  # type: ignore[assignment]
    variants = {raw}
    decoded = unquote(raw)
    if decoded != raw:
        variants.add(decoded)  # `%2e%2e/` style spellings are checked too
    for v in variants:
        path = canonical(v, cwd, root)
        cls = classify_sensitive(path, bare=bare)
        if cls is not None:
            out.append(PathViolation("SENSITIVE", f"access to a protected location ({cls})", cls))
            continue
        if any(glob_match(g, path, ws) for g in deny):
            out.append(PathViolation("DENIED", "path matches a group path_deny rule"))
        if allow and not any(glob_match(g, path, ws) for g in allow):
            out.append(PathViolation("NOT_ALLOWED", "path is outside the group's path_allow rules"))
        if workspace_only:
            rel = not path.startswith(("/", "~")) and not is_windows_path(path)
            if ws is None:
                if not rel or path == ".." or path.startswith("../"):
                    out.append(
                        PathViolation("ROOT_UNKNOWN", "workspace root unknown; cannot confirm the path is inside")
                    )
            elif rel or not within(path, ws):
                out.append(PathViolation("OUTSIDE_WORKSPACE", "path is outside the workspace"))
    seen: set[tuple[str, str]] = set()
    uniq = []
    for viol in out:
        key = (viol.code, viol.reason)
        if key not in seen:
            seen.add(key)
            uniq.append(viol)
    return uniq
