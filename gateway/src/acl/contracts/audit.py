"""Audit / event record (concept §13). One JSON object per line in the hash-chained log.

Hash chain:
    record_hash = sha256( prev_hash_hex + "\\n" + canonical_json(record without "hash") )
    canonical_json = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                     with datetimes as RFC 3339 UTC strings ("...Z") and None fields included.
    The first record uses prev_hash = "0" * 64. `seq` starts at 0 and increments by 1.

No raw sensitive values: findings carry entity type, location and a salted value hash only;
`redacted_payload` holds the already redacted/pseudonymised text and only when policy allows.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field

from .common import (
    Action,
    AuthMethod,
    InspectionPoint,
    Phase,
    PrincipalKind,
    RuleId,
    Score,
    Severity,
    Sha256Hex,
    StrictModel,
    Taxonomy,
    VerdictStatus,
    Versions,
)
from .decision import ApprovalRef, RiskFactor, RouteInfo
from .inspection import ClientInfo, SessionLabels

GENESIS_HASH = "0" * 64


class EventType(StrEnum):
    decision = "decision"
    policy_change = "policy_change"
    policy_reload_failed = "policy_reload_failed"
    grant_change = "grant_change"
    incident = "incident"
    approval = "approval"
    breakglass = "breakglass"
    feed_update = "feed_update"
    feed_verify_failed = "feed_verify_failed"
    artifact_scan = "artifact_scan"
    mcp_drift = "mcp_drift"
    budget_breach = "budget_breach"
    auth_failure = "auth_failure"
    system_alert = "system_alert"


class AuditPrincipal(StrictModel):
    subject: str
    kind: PrincipalKind
    username: str | None = None
    groups: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    client_id: str | None = None
    auth_method: AuthMethod = AuthMethod.none
    api_key_id: str | None = None
    delegation_chain: list[str] = Field(default_factory=list)


class AuditFinding(StrictModel):
    entity_type: str
    field: str = ""
    start: int | None = None
    end: int | None = None
    value_hash: str | None = None
    rule_id: RuleId | None = None


class AuditVerdict(StrictModel):
    control_id: str
    control_type: str
    phase: Phase
    action: Action
    final: bool = False
    score: Score | None = None
    status: VerdictStatus = VerdictStatus.ok
    latency_ms: float = 0.0
    rule_ids: list[RuleId] = Field(default_factory=list)
    findings: list[AuditFinding] = Field(default_factory=list)
    reason: str | None = None


class AuditDecision(StrictModel):
    action: Action
    applied: list[Action] = Field(default_factory=list)
    would_action: Action | None = None
    final: bool = False
    decided_by: str | None = None
    decided_phase: Phase | None = None
    rule_ids: list[RuleId] = Field(default_factory=list)
    risk_score: Score = 0.0
    reason: str = ""


class Usage(StrictModel):
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    usd: float = 0.0
    gpu_seconds: float = 0.0
    guard_tokens: int = 0
    guard_gpu_seconds: float = 0.0
    cache_hit: bool = False


class LatencyBreakdown(StrictModel):
    total_ms: float = 0.0
    pipeline_ms: float = 0.0
    upstream_ms: float = 0.0


class AuditEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: str
    seq: int = Field(ge=0)
    timestamp: datetime
    event_type: EventType
    severity: Severity = Severity.info

    trace_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None

    principal: AuditPrincipal | None = None
    client: ClientInfo | None = None

    point: InspectionPoint | None = None
    tool: str | None = None
    server: str | None = None
    model_requested: str | None = None
    model: str | None = None
    connector: str | None = None

    args_hash: str | None = Field(default=None, description="Salted hash of canonical tool arguments.")
    payload_hash: str | None = Field(default=None, description="Salted hash of the inspected payload.")
    response_hash: str | None = None

    decision: AuditDecision | None = None
    verdicts: list[AuditVerdict] = Field(default_factory=list)
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    route: RouteInfo | None = None
    approval: ApprovalRef | None = None
    labels_after: SessionLabels | None = None

    versions: Versions
    taxonomy: Taxonomy = Field(default_factory=Taxonomy)
    usage: Usage | None = None
    latency: LatencyBreakdown | None = None
    seed: int | None = None

    redacted_payload: str | None = Field(
        default=None, description="Redacted/pseudonymised text only; present only if policy enables it."
    )
    detail: dict[str, Any] = Field(
        default_factory=dict, description="Event-type-specific details (no raw sensitive values)."
    )

    prev_hash: Sha256Hex
    hash: Sha256Hex
