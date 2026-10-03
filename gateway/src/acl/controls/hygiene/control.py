"""SEC-HYG-01: egress hygiene (concept §6.2 stage 5).

* reasoning traces (`payload.reasoning`, `<think>…</think>` in the content) and logprobs: 1A strips them,
  this control reports and, for text, produces redact findings with an empty replacement so the shared
  transform machinery removes them too (`logprobs` is reported only);
* system-prompt canary leakage: canary tokens from `params.canaries` or `ctx.attributes["canaries"]`
  (case-insensitive, also when split by spaces/punctuation) → block, final;
* hallucinated placeholders: `<PESEL_7>`-style placeholders in the completion that the session vault did not
  issue (`vault.placeholders(session)` ∪ `ctx.attributes["issued_placeholders"]`) → redact (balanced) or
  block (strict presets). Without a vault the check is skipped (nothing to compare with).
"""

from __future__ import annotations

import hashlib
import hmac
import re

from pydantic import BaseModel, ConfigDict, Field

from acl.contracts.common import Action, Phase, Preset
from acl.contracts.decision import Finding, Verdict
from acl.contracts.inspection import CompletionPayload, InspectionContext
from acl.controls.base import Control, ControlDeps, register_control
from acl.controls.normalise.scan import hash_value, normalised_payload, scan_texts, value_salt
from acl.controls.pii.vault import PLACEHOLDER_RE
from acl.policy.models import ControlConfig

_THINK = re.compile(r"(?is)<think(?:ing)?>.*?(?:</think(?:ing)?>|\Z)")
_COMPACT = re.compile(r"[^0-9a-z]+")
DEFAULT_PLACEHOLDER_TYPES = [
    "PESEL",
    "NIP",
    "REGON",
    "PL_ID_CARD",
    "IBAN",
    "CREDIT_CARD",
    "EMAIL",
    "PHONE",
    "PERSON",
    "ORG",
    "LOCATION",
    "ADDRESS",
    "DATE_OF_BIRTH",
    "ID",
    "SECRET",
]


def canary_token(salt: str, session_id: str) -> str:
    """Deterministic per-session canary the gateway can plant in a system prompt (HMAC, not guessable)."""
    mac = hmac.new(salt.encode(), f"canary:{session_id}".encode(), hashlib.sha256).hexdigest()[:20]
    return f"ACL-CANARY-{mac.upper()}"


class HygieneParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canaries: list[str] = Field(default_factory=list)
    strip_reasoning: bool = True
    check_canary: bool = True
    check_placeholders: bool = True
    placeholder_types: list[str] = Field(default_factory=lambda: list(DEFAULT_PLACEHOLDER_TYPES))
    hallucinated_action: Action | None = Field(
        default=None, description="Override: default is redact under balanced/monitor, block under strict presets."
    )
    strict_presets: list[Preset] = Field(default_factory=lambda: [Preset.strict, Preset.paranoid])


@register_control
class EgressHygieneControl(Control):
    type = "egress_hygiene"
    phase = Phase.egress_hygiene
    Params = HygieneParams
    cacheable = False  # depends on the vault and per-session canaries

    def __init__(self, config: ControlConfig, params: BaseModel, deps: ControlDeps) -> None:
        super().__init__(config, params, deps)
        self._salt = value_salt(deps)

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        p: HygieneParams = self.params  # type: ignore[assignment]
        payload = normalised_payload(ctx)
        original = ctx.payload
        findings: list[Finding] = []
        actions: list[Action] = []
        notes: list[str] = []

        # ---- reasoning traces / logprobs ---------------------------------------------------------
        if isinstance(original, CompletionPayload) and p.strip_reasoning:
            if original.reasoning:
                norm_reasoning = payload.reasoning if isinstance(payload, CompletionPayload) else None
                findings.append(
                    Finding(
                        entity_type="REASONING_TRACE",
                        field="reasoning",
                        start=0,
                        end=len(norm_reasoning or original.reasoning),
                        score=1.0,
                        replacement="",
                        rule_id=self.id,
                    )
                )
                actions.append(Action.redact)
                notes.append("reasoning trace present")
            if original.has_logprobs:
                findings.append(Finding(entity_type="LOGPROBS", field="has_logprobs", score=1.0, rule_id=self.id))
                actions.append(Action.monitor)
                notes.append("logprobs present")
            body = payload.content if isinstance(payload, CompletionPayload) else None
            if body and ("<think" in body.lower()):
                for m in _THINK.finditer(body):
                    findings.append(
                        Finding(
                            entity_type="REASONING_TRACE",
                            field="content",
                            start=m.start(),
                            end=m.end(),
                            score=0.9,
                            replacement="",
                            rule_id=self.id,
                        )
                    )
                    actions.append(Action.redact)
                    notes.append("inline reasoning block")

        # ---- canary leakage ----------------------------------------------------------------------
        canaries = [c for c in [*p.canaries, *(ctx.attributes.get("canaries") or [])] if c]
        leaked = False
        if p.check_canary and canaries:
            texts = scan_texts(ctx, views=True, joined=False)
            compact_canaries = {c: _COMPACT.sub("", c.lower()) for c in canaries}
            for st in texts:
                low = st.text.lower()
                compact = None
                for canary, cc in compact_canaries.items():
                    idx = low.find(canary.lower())
                    if idx >= 0:
                        a, b = st.locate(idx, idx + len(canary))
                    else:
                        if compact is None:
                            compact = _COMPACT.sub("", low)
                        if len(cc) < 12 or cc not in compact:
                            continue
                        a, b = st.locate(0, len(st.text))
                    leaked = True
                    findings.append(
                        Finding(
                            entity_type="CANARY_LEAK",
                            field=st.field,
                            start=a,
                            end=b,
                            score=1.0,
                            value_hash=hash_value(self._salt, canary),
                            rule_id=self.id,
                        )
                    )
            if leaked:
                actions.append(Action.block)
                notes.append("system-prompt canary leaked")

        # ---- hallucinated placeholders -----------------------------------------------------------
        vault = self.deps.get("vault")
        if p.check_placeholders and (vault is not None or "issued_placeholders" in ctx.attributes):
            issued: set[str] = set(ctx.attributes.get("issued_placeholders") or ())
            if vault is not None:
                issued |= vault.placeholders(ctx.session_id)
            allowed_types = set(p.placeholder_types)
            hallu_action = p.hallucinated_action or (Action.block if ctx.preset in p.strict_presets else Action.redact)
            count = 0
            for st in scan_texts(ctx, views=False, joined=False):
                if "<" not in st.text or st.field == "reasoning":
                    continue
                for m in PLACEHOLDER_RE.finditer(st.text):
                    if m.group(1) not in allowed_types or m.group(0) in issued:
                        continue
                    count += 1
                    findings.append(
                        Finding(
                            entity_type="HALLUCINATED_PLACEHOLDER",
                            field=st.field,
                            start=m.start(),
                            end=m.end(),
                            score=1.0,
                            replacement="[REDACTED:PLACEHOLDER]",
                            rule_id=self.id,
                        )
                    )
            if count:
                actions.append(hallu_action)
                notes.append(f"{count} placeholder(s) not issued for this session")

        if not findings:
            return self.verdict()
        worst = max(actions, key=lambda a: {Action.monitor: 0, Action.redact: 1, Action.block: 3}.get(a, 2))
        return self.verdict(
            action=worst,
            final=worst == Action.block,
            rule_ids=[self.id],
            findings=findings,
            reason="; ".join(dict.fromkeys(notes)) + f"; action {worst.value}",
        )
