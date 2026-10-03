"""SEC-SESSION-01 `session_label`: confidential sessions stay local (HANDOFF §7.2, inspired by OpenAPPA).

Every session carries a monotonic high-water mark (`SessionLabels.confidentiality`, raised by `compose_decision` and
joined by `merge_labels`). Once it is at or above `threshold` (confidential by default; restricted is the laxer
setting), every later request in the session gets `route_local`: the router then serves it from a local model only.
This closes the gap where a later message without PII would send the whole (pseudonymised) history to a cloud model.

The control only reads the session state loaded before this request, so the request that first raises the label is
handled by the data-class routing of that request itself (sensitivity → local_only, LOCK-01); this rule covers every
request after it. It never relaxes anything: `route_local` is stricter than allow and leaves blocks untouched.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from acl.contracts.common import DATA_CLASS_ORDER, Action, DataClass, Phase
from acl.contracts.decision import Verdict
from acl.contracts.inspection import InspectionContext
from acl.controls.base import Control, register_control


class SessionLabelParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threshold: DataClass = Field(
        default=DataClass.confidential,
        description="Lowest session data class that keeps the rest of the session on local models.",
    )

    @field_validator("threshold")
    @classmethod
    def _sensitive_only(cls, v: DataClass) -> DataClass:
        if DATA_CLASS_ORDER[v] < DATA_CLASS_ORDER[DataClass.confidential]:
            raise ValueError("threshold must be confidential or restricted")
        return v


def _hhmm(ctx: InspectionContext) -> str:
    since = ctx.session.labels.since
    return f" since {since.strftime('%H:%M')} UTC" if since is not None else ""


@register_control
class SessionLabelControl(Control):
    type = "session_label"
    phase = Phase.deterministic
    Params = SessionLabelParams
    cacheable = False  # depends on session state

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        p: SessionLabelParams = self.params  # type: ignore[assignment]
        level = ctx.session.labels.confidentiality
        if DATA_CLASS_ORDER[level] < DATA_CLASS_ORDER[p.threshold]:
            return self.verdict()
        return self.verdict(
            action=Action.route_local,
            rule_ids=[self.id],
            data_class=level,
            reason=(
                f"This session is {level.value}{_hhmm(ctx)}: every later request stays on local models "
                f"(threshold {p.threshold.value})"
            ),
        )
