"""Verdict (one control's result) and Decision (the composed outcome)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from .common import (
    Action,
    ApprovalStatus,
    ConnectorTier,
    CostTier,
    DataClass,
    FailMode,
    InspectionPoint,
    Phase,
    RiskFactorName,
    RuleId,
    Score,
    StrictModel,
    Taxonomy,
    VerdictStatus,
    Versions,
)
from .inspection import SessionLabels


class Finding(StrictModel):
    """A detected span. Never contains the raw value."""

    entity_type: str = Field(examples=["PESEL", "IBAN", "AWS_ACCESS_KEY", "INJECTION"])
    field: str = Field(
        default="",
        description="Location in the payload, e.g. `messages[2].content`, `arguments.command`.",
    )
    start: int | None = Field(default=None, ge=0)
    end: int | None = Field(default=None, ge=0)
    score: Score | None = None
    value_hash: str | None = Field(
        default=None, description="Salted SHA-256 (truncated hex) of the value, for correlation without exposure."
    )
    replacement: str | None = Field(
        default=None, description="Mask or placeholder to substitute, e.g. `<PESEL_1>` or `[REDACTED:IBAN]`."
    )
    rule_id: RuleId | None = None


class RiskFactor(StrictModel):
    factor: RiskFactorName
    value: Score
    weight: float = Field(default=1.0, ge=0.0)
    contribution: float = Field(default=0.0, ge=0.0, description="weight × value, after normalisation.")
    source: str | None = Field(default=None, description="Control id that produced the factor.")


class LabelUpdate(StrictModel):
    """Monotonic raise of session labels requested by a control (taint, data class)."""

    integrity_untrusted: bool = False
    confidentiality: DataClass | None = None
    taint: list[str] = Field(default_factory=list)


class Verdict(StrictModel):
    control_id: str
    control_type: str
    phase: Phase
    cost_tier: CostTier
    action: Action = Action.allow
    final: bool = Field(
        default=False, description="Deterministic denial: cannot be relaxed by any later stage or score."
    )
    score: Score | None = None
    rule_ids: list[RuleId] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    labels: LabelUpdate | None = None
    data_class: DataClass | None = Field(default=None, description="Sensitivity class detected by this control.")
    taxonomy: Taxonomy = Field(default_factory=Taxonomy)
    reason: str | None = Field(default=None, description="Human-readable explanation. Must not contain raw values.")
    status: VerdictStatus = VerdictStatus.ok
    fail_mode_applied: FailMode | None = None
    latency_ms: float = Field(default=0.0, ge=0.0)
    outputs: dict[str, Any] = Field(
        default_factory=dict,
        exclude=True,
        description="In-process only (merged into ctx.attributes for later phases). Never serialised.",
    )


class RouteInfo(StrictModel):
    model_requested: str | None = None
    model: str = Field(description="Resolved public model id, e.g. `local/qwen3.8-27b`.")
    connector: str
    tier: ConnectorTier
    reason: str = Field(examples=["auto → local/loan-memo: task=loan_memo (0.91), data=confidential → local"])
    degraded: bool = False
    factors: dict[str, Any] = Field(default_factory=dict)


class ApprovalRef(StrictModel):
    approval_id: str
    status: ApprovalStatus = ApprovalStatus.pending
    expires_at: datetime | None = None
    approver_scope: str = Field(default="admin", examples=["user", "admin"])


class Decision(StrictModel):
    decision_id: str
    trace_id: str
    point: InspectionPoint
    action: Action = Field(description="Primary (most severe) action actually enforced.")
    applied: list[Action] = Field(
        default_factory=list, description="All non-allow actions applied, e.g. [pseudonymise, route_local]."
    )
    would_action: Action | None = Field(
        default=None, description="What enforce mode would have done (set when running in monitor mode)."
    )
    final: bool = False
    decided_by: str | None = Field(default=None, description="Control id that determined the primary action.")
    decided_phase: Phase | None = None
    rule_ids: list[RuleId] = Field(default_factory=list)
    risk_score: Score = 0.0
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    reason: str = ""
    verdicts: list[Verdict] = Field(default_factory=list)
    route: RouteInfo | None = None
    approval: ApprovalRef | None = None
    labels_after: SessionLabels = Field(default_factory=SessionLabels)
    taxonomy: Taxonomy = Field(default_factory=Taxonomy)
    versions: Versions
    latency_ms: float = 0.0
