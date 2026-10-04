"""Admin view of the signature set and the "add a rule" path (panel: Known threats).

The feed server is the source of truth: a rule added in the panel is POSTed to the feed server's editing API
(`POST /entries`), which publishes it in a new, signed bundle; the gateway then syncs like for any other change, so
the rule is verified, versioned and audited exactly like a rule from the external system.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from acl.contracts.admin import FeedRuleCreate, FeedSignature
from acl.contracts.common import InspectionPoint
from acl.contracts.feed import SignatureEntry, SignatureType
from acl.feed.compile import DEFAULT_STAGES, CompiledEntry, CompileError, compile_entry

_FIXED_TARGET: dict[SignatureType, str] = {
    SignatureType.package_version: "package",
    SignatureType.ioc_domain: "domain",
    SignatureType.url_path: "url",
    SignatureType.arg_pattern: "command",
    SignatureType.tool_desc_hash: "tool_hash",
    SignatureType.manifest_hash: "manifest_hash",
    SignatureType.yara: "yara",
    SignatureType.opcode: "opcode",
}
_MCP = {InspectionPoint.mcp_tools_list, InspectionPoint.mcp_initialize}
_TOOL_IO = {InspectionPoint.tool_call, InspectionPoint.tool_result}
_REGEX_TYPES = (SignatureType.regex, SignatureType.arg_pattern, SignatureType.url_path)


def effective_stages(entry: SignatureEntry) -> frozenset[InspectionPoint]:
    return frozenset(entry.stages) if entry.stages else DEFAULT_STAGES[entry.type]


def target_of(entry: SignatureEntry) -> str:
    """What a signature looks at, derived from its matcher type and stages."""
    fixed = _FIXED_TARGET.get(entry.type)
    if fixed is not None:
        return fixed
    stages = effective_stages(entry)
    if stages <= _MCP:
        return "tool_description"
    if stages <= _TOOL_IO:
        return "command"
    if stages == {InspectionPoint.ingress}:
        return "prompt_text"
    if stages == {InspectionPoint.egress}:
        return "answer_text"
    return "any_text"


def _title(entry: SignatureEntry) -> str:
    text = entry.description.strip()
    if not text:
        return entry.id
    first = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
    return first if len(first) <= 120 else first[:119] + "…"


def describe(
    ce: CompiledEntry,
    *,
    origin: str,
    now: float | None = None,
    hits: tuple[int, datetime | None] | None = None,
) -> FeedSignature:
    e = ce.entry
    return FeedSignature(
        id=e.id,
        title=_title(e),
        description=e.description,
        target=target_of(e),  # type: ignore[arg-type]
        type=e.type,
        pattern=e.pattern,
        action=e.action,
        severity=e.severity,
        stages=sorted(ce.stages, key=lambda s: list(InspectionPoint).index(s)),
        source=e.source,
        reference=e.cve[0] if e.cve else None,
        cve=list(e.cve),
        owasp=list(e.owasp),
        atlas_technique=list(e.atlas_technique),
        origin=origin,  # type: ignore[arg-type]
        expires=e.expires,
        expired=not ce.live(time.time() if now is None else now),
        hits_24h=hits[0] if hits else None,
        last_hit_at=hits[1] if hits else None,
    )


class RuleInvalid(ValueError):
    """The submitted rule cannot be turned into a working signature (client-safe message)."""


def build_entry(body: FeedRuleCreate) -> SignatureEntry:
    """Map the panel's form onto a feed entry and prove that the gateway can compile it."""
    meta: dict[str, Any] = {}
    stages: list[InspectionPoint] = []
    t = body.target
    if t == "package":
        name = (body.package or "").strip()
        if not name:
            raise RuleInvalid("package: `package` is required")
        pattern = f"{body.ecosystem}:{name}"
        versions = [v.strip() for v in body.versions if v.strip() and v.strip() != "*"]
        if versions:
            meta["versions"] = versions
        stype = SignatureType.package_version
    else:
        pattern = (body.pattern or "").strip()
        if not pattern:
            raise RuleInvalid(f"{t}: `pattern` is required")
        stype = {
            "domain": SignatureType.ioc_domain,
            "url": SignatureType.url_path,
            "command": SignatureType.arg_pattern,
        }.get(t, SignatureType.regex)
        if t == "command":
            stages = [InspectionPoint.tool_call]
            if body.tools:
                meta["tools"] = [x.strip() for x in body.tools if x.strip()]
        elif t == "tool_description":
            stages = [InspectionPoint.mcp_tools_list, InspectionPoint.mcp_initialize]
        elif t == "prompt_text":
            stages = [InspectionPoint.ingress]
        elif t == "answer_text":
            stages = [InspectionPoint.egress]
    entry = SignatureEntry(
        id=body.id,
        type=stype,
        pattern=pattern,
        severity=body.severity,
        action=body.action,
        stages=stages,
        description=body.description.strip(),
        atlas_technique=list(body.atlas_technique),
        owasp=list(body.owasp),
        cve=list(body.cve),
        source=body.source.strip() or "panel",
        expires=body.expires,
        metadata=meta,
    )
    try:
        compiled = compile_entry(entry)
    except CompileError as exc:
        raise RuleInvalid(str(exc)) from exc
    if stype in _REGEX_TYPES and compiled.matcher is not None and compiled.matcher.search("") is not None:
        raise RuleInvalid("pattern matches the empty string, so it would hit every request")
    return entry


class FeedAdminError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class FeedAdminClient:
    """Calls the feed server's editing API. `base` and `token` are resolved per call (settings / policy can change)."""

    def __init__(
        self,
        base: Callable[[], str | None],
        token: Callable[[], str | None],
        *,
        timeout_s: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base = base
        self._token = token
        self._timeout_s = timeout_s
        self._transport = transport

    @property
    def configured(self) -> bool:
        return bool(self._base() and self._token())

    async def add_entry(self, entry: SignatureEntry) -> int | None:
        """Upsert one entry; returns the new bundle version the feed server published."""
        base, token = self._base(), self._token()
        if not base or not token:
            raise FeedAdminError(503, "adding rules is not configured (no feed URL or ACL_FEED_ADMIN_TOKEN)")
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout_s, follow_redirects=False, transport=self._transport
            ) as client:
                resp = await client.post(
                    f"{base.rstrip('/')}/entries",
                    json=entry.model_dump(mode="json"),
                    headers={"Authorization": f"Bearer {token}"},
                )
        except httpx.HTTPError as exc:
            raise FeedAdminError(502, f"feed server unreachable ({type(exc).__name__})") from exc
        if resp.status_code == 201:
            version = resp.json().get("bundle_version")
            return version if isinstance(version, int) else None
        if resp.status_code == 403:
            raise FeedAdminError(503, "the feed server has rule editing disabled")
        if resp.status_code == 401:
            raise FeedAdminError(502, "the feed server rejected the admin token")
        if resp.status_code == 422:
            raise FeedAdminError(422, f"the feed server rejected the rule: {_error_text(resp)}")
        raise FeedAdminError(502, f"feed server answered {resp.status_code}")


def _error_text(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return ""
    return str(body.get("error", ""))[:300] if isinstance(body, dict) else ""


def admin_base(feed_url: str | None, override: str | None) -> str | None:
    """Origin of the feed server (`http://feed-server:8080/bundle.json` -> `http://feed-server:8080`)."""
    if override:
        return override
    if not feed_url:
        return None
    parts = urlsplit(feed_url)
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else None
