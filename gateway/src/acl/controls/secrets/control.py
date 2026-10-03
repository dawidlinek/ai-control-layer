"""SEC-SECRET-01: secrets and credentials never leave (concept §6.2 stage 1).

Rules are gitleaks-style (provider key prefixes, JWTs, private-key blocks, `password=` assignments) plus
a high-entropy token heuristic; they run on the normalised payload, on decoded views (Base64/hex/URL)
and on text re-joined across line breaks. `data_class` is `restricted`. Action: `preset.secret_action`
(default block, final); a `redact` action produces typed masks. Findings carry `value_hash` only.
"""

from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, ConfigDict, Field

from acl.contracts.common import Action, DataClass, Phase
from acl.contracts.decision import Finding, Verdict
from acl.contracts.inspection import InspectionContext
from acl.controls.base import Control, ControlDeps, register_control
from acl.controls.normalise.scan import ScanText, decoded_views, hash_value, scan_texts, value_salt
from acl.controls.secrets.rules import find_secrets
from acl.policy.models import ControlConfig


class SecretsParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entropy_enabled: bool = True
    entropy_threshold: float = Field(default=4.3, ge=1.0, le=8.0)
    entropy_min_len: int = Field(default=32, ge=16, le=256)
    scan_line_joined: bool = True


@register_control
class SecretsControl(Control):
    type = "secrets"
    phase = Phase.deterministic
    Params = SecretsParams
    cacheable = True

    def __init__(self, config: ControlConfig, params: BaseModel, deps: ControlDeps) -> None:
        super().__init__(config, params, deps)
        self._salt = value_salt(deps)

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        p: SecretsParams = self.params  # type: ignore[assignment]
        settings = self.preset_settings(ctx)
        action = settings.secret_action if settings is not None else Action.block

        view_spans: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for v in decoded_views(ctx):
            view_spans[v["field"]].append((v["start"], v["end"]))

        findings: list[Finding] = []
        seen: set[tuple[str, int, int]] = set()
        for st in scan_texts(ctx, views=True, joined=p.scan_line_joined):
            for h in find_secrets(
                st.text,
                entropy=p.entropy_enabled and st.kind != "joined",  # glued lines would invent "tokens"
                entropy_threshold=p.entropy_threshold,
                entropy_min_len=p.entropy_min_len,
                skip_spans=view_spans.get(st.field, ()) if st.kind == "text" else (),
            ):
                if st.kind == "joined" and not st.crosses_break(h.start, h.end):
                    continue
                start, end = st.locate(h.start, h.end)
                if (st.field, start, end) in seen:
                    continue
                seen.add((st.field, start, end))
                findings.append(self._finding(st, h.entity, start, end, h.value, h.score, action))
        if not findings:
            return self.verdict()
        kinds = sorted({f.entity_type for f in findings})
        return self.verdict(
            action=action,
            final=action == Action.block,
            rule_ids=[self.id],
            findings=findings,
            data_class=DataClass.restricted,
            reason=f"{len(findings)} secret(s) detected ({', '.join(kinds)}); action {action.value}",
        )

    def _finding(
        self, st: ScanText, entity: str, start: int, end: int, value: str, score: float, action: Action
    ) -> Finding:
        return Finding(
            entity_type=entity,
            field=st.field,
            start=start,
            end=end,
            score=score,
            value_hash=hash_value(self._salt, value),
            replacement=f"[REDACTED:{entity}]"
            if action in (Action.redact, Action.pseudonymise, Action.block)
            else None,
            rule_id=self.id,
        )
