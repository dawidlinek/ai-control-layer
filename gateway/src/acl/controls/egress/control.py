"""SEC-EXFIL-01: markdown-image / link exfiltration and data-in-URL checks (concept §6.2, §9.2).

Applies at `egress` (model text) and `tool_call` (arguments). Each URL is classified:

* host matches `allow_domains` (fnmatch globs; `*.x` also matches `x`) → ignored;
* otherwise it is checked for *data in the URL*: session placeholders, PII, secrets, Base64/hex values,
  high-entropy query values (`max_query_entropy`), random-looking hostnames (DNS exfiltration);
* a markdown image / `<img>` to a non-allow-listed host is an auto-fetched channel even without
  visible data (EchoLeak-style) and is stripped when `strip_markdown_images` is on (egress only).

Action mapping (documented contract):

    finding                         tool_call        egress, lenient presets          egress, strict presets
    data in URL (any construct)     block (final)    redact → `[link removed]`        block (final)
    image to non-allow-listed host  –                redact → `[link removed]`        redact → `[link removed]`
    plain link, no data             allow            allow                            allow

Lenient presets are `monitor` and `balanced`; `strict_presets` (default strict, paranoid) block.
Offsets refer to the whole markdown construct / URL, so a redact removes it as a unit.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from acl.contracts.common import Action, DataClass, InspectionPoint, Phase, Preset
from acl.contracts.decision import Finding, Verdict
from acl.contracts.inspection import InspectionContext
from acl.controls.base import Control, ControlDeps, register_control
from acl.controls.egress.urls import exfil_indicators, extract_urls, host_allowed, host_of
from acl.controls.normalise.scan import hash_value, scan_texts, value_salt
from acl.policy.models import ControlConfig

LINK_REMOVED = "[link removed]"


class UrlEgressParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow_domains: list[str] = Field(default_factory=list)
    strip_markdown_images: bool = True
    max_query_entropy: float = Field(default=3.5, ge=1.0, le=8.0)
    min_entropy_len: int = Field(default=20, ge=8, le=256)
    strict_presets: list[Preset] = Field(default_factory=lambda: [Preset.strict, Preset.paranoid])


@register_control
class UrlEgressControl(Control):
    type = "url_egress"
    phase = Phase.deterministic
    Params = UrlEgressParams
    cacheable = True

    def __init__(self, config: ControlConfig, params: BaseModel, deps: ControlDeps) -> None:
        super().__init__(config, params, deps)
        self._salt = value_salt(deps)

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        p: UrlEgressParams = self.params  # type: ignore[assignment]
        strict = ctx.preset in p.strict_presets
        at_egress = ctx.point == InspectionPoint.egress

        findings: list[Finding] = []
        worst = Action.allow
        has_secret = False
        data_hit = False
        seen: set[tuple[str, int, int]] = set()
        for st in scan_texts(ctx, views=True, joined=False):
            if "//" not in st.text and "](" not in st.text and "][" not in st.text:
                continue
            for ref in extract_urls(st.text):
                host = host_of(ref.url)
                if host is None or host_allowed(host, p.allow_domains):
                    continue
                ind = exfil_indicators(
                    ref.url, max_query_entropy=p.max_query_entropy, min_entropy_len=p.min_entropy_len
                )
                is_image = ref.kind == "image"
                if ind.kinds:
                    data_hit = True
                    has_secret = has_secret or ind.has_secret
                    action = Action.redact if (at_egress and not strict) else Action.block
                    entity = "URL_EXFIL"
                elif is_image and at_egress and p.strip_markdown_images:
                    action, entity = Action.redact, "MARKDOWN_IMAGE"
                else:
                    continue
                start, end = st.locate(ref.start, ref.end)
                if (st.field, start, end) in seen:
                    continue
                seen.add((st.field, start, end))
                if action == Action.block:
                    worst = Action.block
                elif worst != Action.block:
                    worst = action
                findings.append(
                    Finding(
                        entity_type=entity,
                        field=st.field,
                        start=start,
                        end=end,
                        score=0.95 if ind.kinds else 0.8,
                        value_hash=hash_value(self._salt, ref.url),
                        replacement=LINK_REMOVED if at_egress else None,
                        rule_id=self.id,
                    )
                )
        if not findings:
            return self.verdict()
        return self.verdict(
            action=worst,
            final=worst == Action.block,
            rule_ids=[self.id],
            findings=findings,
            data_class=(DataClass.restricted if has_secret else DataClass.confidential) if data_hit else None,
            reason=(
                f"{len(findings)} outbound URL finding(s) "
                f"({'data in URL' if data_hit else 'external image'}); action {worst.value}"
            ),
        )
