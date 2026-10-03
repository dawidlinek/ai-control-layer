"""Compile signature entries (RE2 / yara) into matchers (concept §9.2).

* `regex`, `arg_pattern`, `url_path`: RE2 (`google-re2`) — linear-time, no look-around. A pattern RE2
  rejects falls back to Python `re` (logged once per pattern); everything else is rejected.
* `yara`: `yara-python` with includes disabled.
* `ioc_domain`: RE2 domain regex matching the domain and its subdomains.
* `package_version`: `<ecosystem>:<name>` + `metadata.versions` (empty/missing = every version).
* `tool_desc_hash` / `manifest_hash`: sha256 sets.  `opcode`: `module.attr` globs (matched against
  `ctx.attributes["pickle_globals"]` if an artifact scanner publishes it).

Entries that fail to compile are skipped and reported (`CompiledBundle.errors`), never fatal.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from acl.contracts.common import InspectionPoint
from acl.contracts.feed import SignatureEntry, SignatureType

log = logging.getLogger(__name__)

try:  # google-re2 is a locked dependency; keep the import soft so a missing wheel degrades to `re`
    import re2  # type: ignore[import-not-found]

    _RE2_ERROR: tuple[type[BaseException], ...] = (re2.error,)
except ImportError:  # pragma: no cover
    re2 = None
    _RE2_ERROR = ()

_FALLBACK_LOGGED: set[str] = set()

# stages a type applies to when `entry.stages` is empty
DEFAULT_STAGES: dict[SignatureType, frozenset[InspectionPoint]] = {
    SignatureType.regex: frozenset(InspectionPoint),
    SignatureType.yara: frozenset(InspectionPoint),
    SignatureType.ioc_domain: frozenset(InspectionPoint),
    SignatureType.arg_pattern: frozenset({InspectionPoint.tool_call, InspectionPoint.mcp_tools_list}),
    SignatureType.url_path: frozenset({InspectionPoint.tool_call, InspectionPoint.tool_result}),
    SignatureType.package_version: frozenset({InspectionPoint.tool_call}),
    SignatureType.tool_desc_hash: frozenset({InspectionPoint.mcp_tools_list, InspectionPoint.mcp_initialize}),
    SignatureType.manifest_hash: frozenset({InspectionPoint.mcp_tools_list, InspectionPoint.mcp_initialize}),
    SignatureType.opcode: frozenset({InspectionPoint.artifact_load}),
}


class CompileError(ValueError):
    pass


class _Matcher:
    """`search(text) -> (start, end) | None` over RE2 or `re` (optionally reporting one group)."""

    __slots__ = ("_group", "_rx")

    def __init__(self, rx: Any, group: int = 0) -> None:
        self._rx = rx
        self._group = group

    def with_group(self, group: int) -> _Matcher:
        return _Matcher(self._rx, group)

    def search(self, text: str) -> tuple[int, int] | None:
        m = self._rx.search(text)
        return m.span(self._group) if m else None


def compile_regex(pattern: str, sig_id: str) -> _Matcher:
    if re2 is not None:
        try:
            return _Matcher(re2.compile(pattern))
        except _RE2_ERROR:
            if sig_id not in _FALLBACK_LOGGED:
                _FALLBACK_LOGGED.add(sig_id)
                log.warning("signature %s: pattern not supported by RE2, falling back to re", sig_id)
    if len(pattern) > 2000:
        raise CompileError("pattern too long for the re fallback")
    try:
        return _Matcher(re.compile(pattern))
    except re.error as exc:
        raise CompileError(f"invalid regex: {exc}") from exc


def _domain_matcher(domain: str, sig_id: str) -> _Matcher:
    d = re.escape(domain.strip().lower().rstrip("."))
    pattern = rf"(?i)(?:^|[^a-z0-9-])((?:[a-z0-9-]+\.)*{d})(?:$|[^a-z0-9.-]|\.(?:[^a-z0-9-]|$))"
    return compile_regex(pattern, sig_id).with_group(1)


@dataclass(frozen=True)
class CompiledEntry:
    entry: SignatureEntry
    stages: frozenset[InspectionPoint]
    matcher: _Matcher | None = None
    yara_rules: Any = None
    domain: str | None = None
    package: tuple[str, str] | None = None  # (ecosystem, normalised name)
    versions: frozenset[str] = frozenset()
    hashes: frozenset[str] = frozenset()
    opcode_globs: tuple[str, ...] = ()
    field_globs: tuple[str, ...] = ()  # metadata.fields: leaf key globs (arg_pattern)
    tool_globs: tuple[str, ...] = ()  # metadata.tools: tool-name globs
    expires_ts: float | None = None

    @property
    def id(self) -> str:
        return self.entry.id

    def live(self, now: float) -> bool:
        return self.expires_ts is None or now < self.expires_ts


@dataclass(frozen=True)
class CompiledBundle:
    version: int
    entries: tuple[CompiledEntry, ...]
    issued_at: datetime | None = None
    errors: tuple[str, ...] = ()
    digest: str = ""

    def for_stage(self, point: InspectionPoint, now: float) -> list[CompiledEntry]:
        return [e for e in self.entries if point in e.stages and e.live(now)]


def _norm_pkg(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name.lower()


def _globs(meta: dict[str, Any], key: str) -> tuple[str, ...]:
    v = meta.get(key)
    return tuple(str(x).lower() for x in v) if isinstance(v, list) else ()


def compile_entry(entry: SignatureEntry) -> CompiledEntry:
    stages = frozenset(entry.stages) if entry.stages else DEFAULT_STAGES[entry.type]
    expires_ts = entry.expires.timestamp() if entry.expires else None
    if entry.expires is not None and entry.expires.tzinfo is None:
        expires_ts = entry.expires.replace(tzinfo=UTC).timestamp()
    common: dict[str, Any] = {
        "entry": entry,
        "stages": stages,
        "expires_ts": expires_ts,
        "field_globs": _globs(entry.metadata, "fields"),
        "tool_globs": _globs(entry.metadata, "tools"),
    }
    t = entry.type
    if t in (SignatureType.regex, SignatureType.arg_pattern, SignatureType.url_path):
        return CompiledEntry(matcher=compile_regex(entry.pattern, entry.id), **common)
    if t == SignatureType.ioc_domain:
        return CompiledEntry(
            matcher=_domain_matcher(entry.pattern, entry.id), domain=entry.pattern.strip().lower().rstrip("."), **common
        )
    if t == SignatureType.yara:
        try:
            import yara  # type: ignore[import-not-found]

            rules = yara.compile(source=entry.pattern, includes=False)
        except Exception as exc:  # yara.SyntaxError / yara.Error
            raise CompileError(f"invalid yara rule: {type(exc).__name__}") from exc
        return CompiledEntry(yara_rules=rules, **common)
    if t == SignatureType.package_version:
        eco, _, name = entry.pattern.partition(":")
        if not name or eco not in ("pypi", "npm", "other"):
            raise CompileError("package_version pattern must be `<ecosystem>:<name>`")
        versions = entry.metadata.get("versions") or []
        return CompiledEntry(
            package=(eco, _norm_pkg(eco, name)), versions=frozenset(str(v) for v in versions), **common
        )
    if t in (SignatureType.tool_desc_hash, SignatureType.manifest_hash):
        h = entry.pattern.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", h):
            raise CompileError("hash pattern must be sha256 hex")
        return CompiledEntry(hashes=frozenset({h}), **common)
    if t == SignatureType.opcode:
        return CompiledEntry(opcode_globs=(entry.pattern.strip(),), **common)
    raise CompileError(f"unsupported signature type {t}")  # pragma: no cover


def compile_entries(entries: Iterable[SignatureEntry]) -> tuple[tuple[CompiledEntry, ...], tuple[str, ...]]:
    ok: list[CompiledEntry] = []
    errors: list[str] = []
    for e in entries:
        try:
            ok.append(compile_entry(e))
        except CompileError as exc:
            errors.append(f"{e.id}: {exc}")
            log.warning("signature %s skipped: %s", e.id, exc)
    return tuple(ok), tuple(errors)
