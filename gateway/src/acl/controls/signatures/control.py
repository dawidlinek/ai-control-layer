"""SEC-SIG-01: signature matching against the active feed bundle + `policy.signatures.local_rules`.

The store (`deps.get("signatures")`) is read on every inspection, so a feed swap applies to the very next
request. Without a store only `local_rules` apply (offline baseline). The verdict carries the signature
ids as rule ids; action / severity / taxonomy come from the entries; any `block` match is `final`.

Matching by type:
    regex / arg_pattern   normalised text, decoded views, line-joined text (arg_pattern: argument fields only;
                          optional `metadata.fields` key globs and `metadata.tools` tool-name globs)
    url_path              path(+query) and full text of URLs (intent URLs and URLs found in the text)
    ioc_domain            domain or subdomain in intent domains, URLs, or anywhere in the text
    package_version       intent packages (pip/npm installs); `metadata.versions` exact versions
    yara                  compiled rule over each text
    tool_desc_hash        sha256(description) of each MCP tool;  manifest_hash: sha256(canonical manifest JSON)
                          of the tool list, or of any single tool entry
    opcode                `module.attr` globs against `ctx.attributes["pickle_globals"]` (artifact scanner)
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from acl.contracts.canonical import canonical_json
from acl.contracts.common import ACTION_SEVERITY, Action, Phase, Severity, Taxonomy
from acl.contracts.decision import Finding, Verdict
from acl.contracts.feed import SignatureEntry, SignatureType
from acl.contracts.inspection import InspectionContext, ToolCallPayload, ToolIntent
from acl.controls.base import Control, ControlDeps, register_control
from acl.controls.normalise.intent import URL_RE, build_intent
from acl.controls.normalise.scan import ScanText, hash_value, normalised_payload, scan_texts, value_salt
from acl.feed.compile import CompiledEntry, compile_entries
from acl.policy.models import ControlConfig

log = logging.getLogger(__name__)

_SEVERITY_SCORE = {
    Severity.info: 0.1,
    Severity.low: 0.3,
    Severity.medium: 0.5,
    Severity.high: 0.8,
    Severity.critical: 1.0,
}
_MAX_RULE_IDS = 25
_TRAILING_INDEX = re.compile(r"(?:\[\d+\])+$")


class SignaturesParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    use_local_rules: bool = True


@dataclass(frozen=True, slots=True)
class Match:
    entry: CompiledEntry
    field: str = ""
    start: int | None = None
    end: int | None = None
    snippet: str | None = None


def _is_arg_field(field: str) -> bool:
    return field.startswith(("arguments", "params")) or field.endswith("function.arguments")


def _leaf_key(field: str) -> str:
    seg = field.rsplit(".", 1)[-1]
    return _TRAILING_INDEX.sub("", seg).lower()


def _add_taxonomy(tax: Taxonomy, entry: SignatureEntry) -> None:
    for tag in entry.owasp:
        bucket = (
            tax.owasp_llm if tag.startswith("LLM") else tax.owasp_agentic if tag.startswith("ASI") else tax.owasp_mcp
        )
        if tag not in bucket:
            bucket.append(tag)
    for tag in entry.atlas_technique:
        if tag not in tax.atlas:
            tax.atlas.append(tag)
    for tag in entry.cve:
        if tag not in tax.cve:
            tax.cve.append(tag)


@register_control
class SignaturesControl(Control):
    type = "signatures"
    phase = Phase.deterministic
    Params = SignaturesParams
    cacheable = False  # the active bundle can change between identical requests

    def __init__(self, config: ControlConfig, params: BaseModel, deps: ControlDeps) -> None:
        super().__init__(config, params, deps)
        self._salt = value_salt(deps)
        policy = deps.get("policy")
        local = list(policy.signatures.local_rules) if policy is not None and params.use_local_rules else []  # type: ignore[attr-defined]
        self._local, errors = compile_entries(local)
        if errors:
            log.warning("%d local signature(s) failed to compile", len(errors))

    # ------------------------------------------------------------------ entries

    def _entries(self, ctx: InspectionContext) -> tuple[list[CompiledEntry], int | None]:
        store = self.deps.get("signatures")
        bundle = store.current() if store is not None else None
        now = time.time()
        merged: dict[str, CompiledEntry] = {e.id: e for e in self._local}
        if bundle is not None:
            merged.update({e.id: e for e in bundle.entries})  # the feed overrides a local rule of the same id
        entries = [e for e in merged.values() if ctx.point in e.stages and e.live(now)]
        return entries, (bundle.version if bundle is not None else None)

    # ------------------------------------------------------------------ inspect

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        entries, feed_version = self._entries(ctx)
        outputs = {"signature_bundle_version": feed_version}
        if not entries:
            return self.verdict(outputs=outputs)

        payload = normalised_payload(ctx)
        intent: ToolIntent | None = ctx.attributes.get("intent")
        if intent is None and isinstance(payload, ToolCallPayload):
            try:
                intent = build_intent(payload)
            except (ValueError, TypeError):
                intent = None
        texts = scan_texts(ctx, views=True, joined=True)
        urls = self._urls(intent, texts)
        tool = payload.tool.lower() if isinstance(payload, ToolCallPayload) else ""

        matches: list[Match] = []
        for ce in entries:
            matches.extend(self._match(ce, ctx, payload, texts, urls, intent, tool))
        if not matches:
            return self.verdict(outputs=outputs)

        by_id: dict[str, Match] = {}
        for m in matches:
            by_id.setdefault(m.entry.id, m)
        ordered = sorted(by_id.values(), key=lambda m: (-ACTION_SEVERITY[m.entry.entry.action], m.entry.id))
        top = ordered[0].entry.entry
        action = top.action
        taxonomy = Taxonomy(**self.config.taxonomy.model_dump())
        score = 0.0
        findings: list[Finding] = []
        for m in ordered:
            e = m.entry.entry
            _add_taxonomy(taxonomy, e)
            score = max(score, _SEVERITY_SCORE[e.severity])
            findings.append(
                Finding(
                    entity_type="SIGNATURE",
                    field=m.field,
                    start=m.start,
                    end=m.end,
                    score=_SEVERITY_SCORE[e.severity],
                    value_hash=hash_value(self._salt, m.snippet) if m.snippet else None,
                    rule_id=e.id,
                )
            )
        block = any(m.entry.entry.action == Action.block for m in ordered)
        ids = [m.entry.id for m in ordered][:_MAX_RULE_IDS]
        return self.verdict(
            action=action,
            final=block,
            rule_ids=ids,
            findings=findings[:_MAX_RULE_IDS],
            score=score,
            taxonomy=taxonomy,
            reason=f"signature match: {', '.join(ids[:5])}{' …' if len(ids) > 5 else ''}; action {action.value}",
            outputs=outputs,
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _urls(intent: ToolIntent | None, texts: list[ScanText]) -> list[tuple[str, str, int | None, int | None]]:
        """(url, field, start, end) from the intent and from URLs in the scanned texts."""
        out: list[tuple[str, str, int | None, int | None]] = []
        seen: set[str] = set()
        if intent is not None:
            for u in intent.urls:
                if u not in seen:
                    seen.add(u)
                    out.append((u, "", None, None))
        for st in texts:
            if st.kind == "joined" or "://" not in st.text:
                continue
            for m in URL_RE.finditer(st.text):
                u = m.group(0).rstrip(".,;:!?)]}'\"")
                a, b = st.locate(m.start(), m.start() + len(u))
                out.append((u, st.field, a, b))
        return out

    def _match(
        self,
        ce: CompiledEntry,
        ctx: InspectionContext,
        payload,
        texts: list[ScanText],
        urls: list[tuple[str, str, int | None, int | None]],
        intent: ToolIntent | None,
        tool: str,
    ) -> list[Match]:
        t = ce.entry.type
        if t in (SignatureType.regex, SignatureType.arg_pattern, SignatureType.yara):
            if (
                t == SignatureType.arg_pattern
                and ce.tool_globs
                and not any(fnmatch.fnmatchcase(tool, g) for g in ce.tool_globs)
            ):
                return []
            for st in texts:
                if t == SignatureType.arg_pattern:
                    if not _is_arg_field(st.field):
                        continue
                    if ce.field_globs and not any(fnmatch.fnmatchcase(_leaf_key(st.field), g) for g in ce.field_globs):
                        continue
                span = self._search(ce, st)
                if span is not None:
                    a, b = st.locate(*span)
                    return [Match(ce, st.field, a, b, st.text[span[0] : span[1]])]
            return []
        if t == SignatureType.ioc_domain:
            assert ce.domain is not None
            for st in texts:
                if st.kind == "joined":
                    continue
                span = ce.matcher.search(st.text) if ce.matcher else None
                if span is not None:
                    a, b = st.locate(*span)
                    return [Match(ce, st.field, a, b, ce.domain)]
            if intent is not None:
                for d in intent.domains:
                    if d == ce.domain or d.endswith("." + ce.domain):
                        return [Match(ce, "", None, None, d)]
            return []
        if t == SignatureType.url_path:
            for url, field, a, b in urls:
                try:
                    parts = urlsplit(url)
                except ValueError:
                    continue
                path = parts.path + (("?" + parts.query) if parts.query else "")
                if ce.matcher and (ce.matcher.search(path) or ce.matcher.search(url)):
                    return [Match(ce, field, a, b, url)]
            return []
        if t == SignatureType.package_version:
            if intent is None or ce.package is None:
                return []
            for pkg in intent.packages:
                if (pkg.ecosystem, _norm(pkg)) == ce.package and (not ce.versions or pkg.version in ce.versions):
                    return [Match(ce, "arguments", None, None, f"{pkg.name}=={pkg.version}")]
            return []
        if t in (SignatureType.tool_desc_hash, SignatureType.manifest_hash):
            return self._match_hash(ce, payload)
        if t == SignatureType.opcode:
            seen = ctx.attributes.get("pickle_globals") or []
            for g in seen:
                if any(fnmatch.fnmatchcase(str(g), pat) for pat in ce.opcode_globs):
                    return [Match(ce, "", None, None, str(g))]
        return []

    @staticmethod
    def _search(ce: CompiledEntry, st: ScanText) -> tuple[int, int] | None:
        if ce.entry.type == SignatureType.yara:
            if ce.yara_rules is None:
                return None
            try:
                hit = ce.yara_rules.match(data=st.text.encode("utf-8", "ignore"), timeout=2)
            except Exception:  # yara.TimeoutError / yara.Error: treat as no match, never crash the request
                return None
            if not hit:
                return None
            span = (0, len(st.text))
        else:
            span = ce.matcher.search(st.text) if ce.matcher else None
            if span is None:
                return None
        if st.kind == "joined" and not st.crosses_break(*span):
            return None
        return span

    @staticmethod
    def _match_hash(ce: CompiledEntry, payload) -> list[Match]:
        if getattr(payload, "kind", None) != "mcp":
            return []
        tools = [t.model_dump(mode="json", exclude_none=True) for t in payload.tools]
        if ce.entry.type == SignatureType.tool_desc_hash:
            for i, t in enumerate(payload.tools):
                if t.description and hashlib.sha256(t.description.encode("utf-8")).hexdigest() in ce.hashes:
                    return [Match(ce, f"tools[{i}].description")]
            return []
        candidates = [canonical_json(sorted(tools, key=lambda x: x["name"]))] + [canonical_json(t) for t in tools]
        for c in candidates:
            if hashlib.sha256(c.encode("utf-8")).hexdigest() in ce.hashes:
                return [Match(ce, "tools")]
        return []


def _norm(pkg) -> str:
    return re.sub(r"[-_.]+", "-", pkg.name).lower() if pkg.ecosystem == "pypi" else pkg.name.lower()
