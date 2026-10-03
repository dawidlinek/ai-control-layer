"""Admin API models (`/admin/v1/...`). Consumed by the panel via a generated client."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from .common import (
    Action,
    ApprovalStatus,
    ConnectorTier,
    DataClass,
    GrantResourceType,
    InspectionPoint,
    Preset,
    PrincipalKind,
    RuleId,
    Score,
    Severity,
    StrictModel,
    ToolLabel,
    ToolTier,
)
from .decide import Elevation

# ---------------------------------------------------------------- generic


class ErrorResponse(StrictModel):
    error: str = Field(examples=["stale_version", "validation_failed", "forbidden_model", "not_implemented"])
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class Health(StrictModel):
    status: Literal["ok", "degraded", "down"]
    version: str
    checks: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------- policy


class PolicyError(StrictModel):
    file: str | None = None
    path: str | None = Field(default=None, description="Location inside the document, e.g. `groups.developers.preset`.")
    line: int | None = None
    column: int | None = None
    message: str


class PolicyFileInfo(StrictModel):
    name: str = Field(examples=["controls.yaml"])
    version: str = Field(description="Content hash; use as `base_version` for optimistic locking.")
    size: int
    modified_at: datetime


class PolicyFileContent(PolicyFileInfo):
    content: str


class PolicyFileWrite(StrictModel):
    content: str
    base_version: str = Field(description="Version the edit was based on; stale → 409.")
    message: str = Field(default="", max_length=500)


class PolicyStatus(StrictModel):
    version: str
    loaded_at: datetime
    source: Literal["file", "panel", "rollback", "startup"]
    files: list[PolicyFileInfo]
    last_error: list[PolicyError] = Field(default_factory=list, description="Errors from the last failed reload.")
    locked_controls: list[str] = Field(default_factory=list)


class ValidateRequest(StrictModel):
    files: dict[str, str] = Field(description="Candidate file contents by name; omitted files use the current version.")


class ValidateResponse(StrictModel):
    valid: bool
    errors: list[PolicyError] = Field(default_factory=list)
    candidate_version: str | None = None


class DryRunRequest(ValidateRequest):
    last_n: int = Field(default=500, ge=1, le=10000)
    point: InspectionPoint | None = None


class DryRunChange(StrictModel):
    event_id: str
    timestamp: datetime
    subject: str | None = None
    before_action: Action
    after_action: Action
    before_rule_ids: list[RuleId] = Field(default_factory=list)
    after_rule_ids: list[RuleId] = Field(default_factory=list)


class DryRunResponse(StrictModel):
    candidate_version: str
    evaluated: int
    changed: int
    transitions: dict[str, int] = Field(default_factory=dict, description="`allow->block` → count.")
    samples: list[DryRunChange] = Field(default_factory=list)
    errors: list[PolicyError] = Field(default_factory=list)


class PolicyVersion(StrictModel):
    id: int
    version: str
    created_at: datetime
    author: str | None = None
    source: Literal["file", "panel", "rollback", "startup"]
    message: str = ""
    files_changed: list[str] = Field(default_factory=list)


class PolicyVersionDetail(PolicyVersion):
    diff: str = Field(description="Unified diff against the previous version.")
    files: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------- grants & access


class GrantConstraints(StrictModel):
    data_classes: list[DataClass] | None = None
    budget_share: float | None = Field(default=None, ge=0.0, le=1.0)
    preset: Preset | None = None


class GrantCreate(StrictModel):
    subject_type: Literal["user", "group"]
    subject: str = Field(description="User subject/username or group path.")
    resource_type: GrantResourceType
    resource: str = Field(examples=["smart", "gemini/flash", "opencode.bash", "mcp:jira"])
    effect: Literal["allow", "deny"] = "allow"
    constraints: GrantConstraints = Field(default_factory=GrantConstraints)
    expires_at: datetime | None = None
    reason: str = Field(min_length=3, max_length=500)


class Grant(GrantCreate):
    id: str
    created_by: str
    created_at: datetime
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    active: bool


class GrantChange(StrictModel):
    id: int
    grant_id: str
    change: Literal["create", "revoke", "expire"]
    actor: str
    reason: str
    at: datetime
    snapshot: Grant


class EffectiveAccessItem(StrictModel):
    resource_type: GrantResourceType
    resource: str
    effect: Literal["allow", "deny"]
    source: Literal["org_lock", "group", "user", "default"]
    source_ref: str = Field(description="Lock id, group name, or grant id.")
    expires_at: datetime | None = None
    constraints: GrantConstraints = Field(default_factory=GrantConstraints)
    capped_by_lock: str | None = Field(default=None, description="Org lock that narrowed this grant, if any.")


class EffectiveAccess(StrictModel):
    subject: str
    username: str | None = None
    groups: list[str]
    preset: Preset
    preset_source: str
    items: list[EffectiveAccessItem]
    budgets: dict[str, dict[str, float]] = Field(default_factory=dict)
    policy_version: str
    grants_version: str


# ---------------------------------------------------------------- users & keys


class User(StrictModel):
    id: str
    subject: str
    username: str
    email: str | None = None
    display_name: str | None = None
    kind: PrincipalKind = PrincipalKind.user
    groups: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime | None = None
    disabled: bool = False


class Group(StrictModel):
    name: str
    description: str = ""
    preset: Preset | None = None
    members: int = 0
    source: Literal["keycloak", "policy", "both"] = "both"


class ApiKeyCreate(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    expires_at: datetime | None = None


class ApiKey(StrictModel):
    id: str
    user_id: str
    name: str
    prefix: str = Field(description="First characters of the key, for identification.")
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class ApiKeyCreated(ApiKey):
    key: str = Field(description="Full key. Returned exactly once; only a hash is stored.")


class BreakGlassRequest(StrictModel):
    event_id: str
    reason: str = Field(min_length=10, max_length=1000)


class BreakGlassResponse(StrictModel):
    event_id: str
    audit_event_id: str
    raw_payload: str | None = Field(description="Null when raw retention is disabled or expired.")
    available: bool


# ---------------------------------------------------------------- events & incidents


class EventSummary(StrictModel):
    event_id: str
    seq: int
    timestamp: datetime
    event_type: str
    severity: Severity
    trace_id: str | None = None
    session_id: str | None = None
    subject: str | None = None
    username: str | None = None
    groups: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    point: InspectionPoint | None = None
    model: str | None = None
    tool: str | None = None
    action: Action | None = None
    rule_ids: list[RuleId] = Field(default_factory=list)
    risk_score: Score | None = None
    latency_ms: float | None = None


class IncidentNote(StrictModel):
    author: str
    at: datetime
    text: str


class Incident(StrictModel):
    id: str
    title: str
    category: str = Field(examples=["forbidden_model", "mcp_rug_pull", "exfiltration_attempt", "budget_breach"])
    severity: Severity
    status: Literal["open", "triaged", "resolved", "false_positive"]
    created_at: datetime
    updated_at: datetime
    assignee: str | None = None
    subject: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    rule_ids: list[RuleId] = Field(default_factory=list)
    notes: list[IncidentNote] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict, description="e.g. rug-pull description diff.")


class IncidentPatch(StrictModel):
    status: Literal["open", "triaged", "resolved", "false_positive"] | None = None
    assignee: str | None = None
    note: str | None = Field(default=None, max_length=4000)


# ---------------------------------------------------------------- approvals


class Approval(StrictModel):
    id: str
    status: ApprovalStatus
    approver_scope: Literal["user", "admin"]
    created_at: datetime
    expires_at: datetime
    requested_by: str
    session_id: str
    trace_id: str
    tool: str | None = None
    server: str | None = None
    arguments_preview: str = Field(default="", description="Redacted preview (command, diff, recipients).")
    reason: str = ""
    rule_ids: list[RuleId] = Field(default_factory=list)
    risk_score: Score = 0.0
    decided_by: str | None = None
    decided_at: datetime | None = None
    elevation: Elevation | None = None


# ---------------------------------------------------------------- budgets


class BreakerState(StrictModel):
    id: str
    state: Literal["closed", "open", "half_open"]
    opened_at: datetime | None = None
    cooldown_until: datetime | None = None
    reason: str | None = None


class BudgetNode(StrictModel):
    id: str = Field(examples=["org", "group:developers", "user:jan", "agent:research-bot", "session:s-1"])
    level: Literal["org", "group", "user", "agent", "session"]
    parent: str | None = None
    limits: dict[str, float] = Field(default_factory=dict, description="Meter → limit, e.g. `usd_day`.")
    usage: dict[str, float] = Field(default_factory=dict)
    breaker: BreakerState | None = None


class BudgetTree(StrictModel):
    generated_at: datetime
    nodes: list[BudgetNode]


# ---------------------------------------------------------------- models & connectors


class ConnectorStatus(StrictModel):
    id: str
    type: str
    tier: ConnectorTier
    enabled: bool
    kill_switch: bool
    healthy: bool | None = None
    latency_ms_p50: float | None = None
    last_error: str | None = None
    spend_usd_day: float = 0.0


class KillSwitchRequest(StrictModel):
    engaged: bool
    reason: str = Field(min_length=3, max_length=500)


class ModelInfo(StrictModel):
    id: str
    connector: str
    tier: ConnectorTier
    aliases: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    data_classes: list[DataClass] = Field(default_factory=list)
    pricing: dict[str, float] = Field(default_factory=dict)
    artifact_status: Literal["n/a", "scanned_ok", "scanned_bad", "unscanned"] = "n/a"
    enabled: bool = True
    available: bool = Field(default=True, description="False when e.g. an env-referenced upstream name is unset.")


# ---------------------------------------------------------------- MCP


class McpServerInfo(StrictModel):
    id: str
    transport: Literal["streamable_http", "stdio"]
    origin: str | None = None
    allowed: bool
    status: Literal["ok", "unreachable", "blocked", "unknown"] = "unknown"
    tools_count: int = 0
    protocol_version: str | None = None
    last_seen: datetime | None = None


class McpToolInfo(StrictModel):
    id: str = Field(examples=["mail.send"])
    server: str
    name: str
    status: Literal["pinned", "pending_approval", "drifted", "quarantined"]
    pinned_hash: str | None = None
    current_hash: str | None = None
    labels: list[ToolLabel] = Field(default_factory=list)
    tier: ToolTier | None = None
    first_seen: datetime | None = None
    drift_detected_at: datetime | None = None
    description_diff: str | None = None


class McpToolApprovalRequest(StrictModel):
    reason: str = Field(min_length=3, max_length=500)


# ---------------------------------------------------------------- feed & artifacts


class FeedStatus(StrictModel):
    source_url: str | None = None
    bundle_version: int | None = None
    issued_at: datetime | None = None
    loaded_at: datetime | None = None
    entries: int = 0
    verified: bool = False
    last_sync_at: datetime | None = None
    last_error: str | None = None


class ArtifactFinding(StrictModel):
    rule_id: str
    severity: Severity
    message: str
    detail: str | None = Field(
        default=None, description="Technical detail: opcode listing excerpt, header dump (never raw file content)."
    )
    cve: list[str] = Field(default_factory=list, description="Related advisories (verified ids only).")


class ArtifactScanResult(StrictModel):
    id: str
    filename: str
    sha256: str
    size: int
    format_detected: str
    verdict: Literal["safe", "malicious", "blocked_format", "suspicious"]
    findings: list[ArtifactFinding] = Field(default_factory=list)
    scanned_at: datetime
    source: str | None = Field(default=None, examples=["upload", "hf:org/repo@<40-hex revision sha>"])
    exception: str | None = Field(default=None, description="Policy exception that admitted a blocked format.")
    model_ids: list[str] = Field(default_factory=list, description="Registered models whose artifact ref is this file.")
    decision_id: str | None = Field(default=None, description="Decision of the `artifact_load` inspection.")
    scanned_by: str | None = None


# ---------------------------------------------------------------- insights


class InsightCluster(StrictModel):
    id: str
    group: str
    label: str
    size: int
    distinct_users: int
    recurrence: Literal["daily", "weekly", "adhoc"]
    est_minutes_per_day: float = 0.0
    est_usd_month: float = 0.0
    examples_redacted: list[str] = Field(default_factory=list)
    task_card: str = ""
    draft_skill: dict[str, Any] = Field(default_factory=dict)
    status: Literal["new", "published", "dismissed"] = "new"


class PublishSkillRequest(StrictModel):
    skill_id: str = Field(pattern=r"^skill/[a-z0-9][a-z0-9-]*$")
    model: str
    preset: Preset = Preset.strict
    groups: list[str] = Field(min_length=1)
    reason: str = Field(min_length=3)


# ---------------------------------------------------------------- metrics & audit


class RateWithCI(StrictModel):
    value: float
    ci_low: float
    ci_high: float
    n: int


class MutantResult(StrictModel):
    control_id: str
    enabled: bool = Field(description="Enabled in policy; disabled controls cannot be mutated (reported, not scored).")
    killed: bool = Field(description="At least one test failed with this control switched off.")
    failing_cells: int = 0
    failing_examples: list[str] = Field(default_factory=list)


class MutationCoverage(StrictModel):
    """Mutation testing: every enabled control is switched off in turn; the suite must notice."""

    generated_at: datetime
    suite: str
    controls_mutated: int
    controls_killed: int
    score: float = Field(ge=0, le=1)
    survivors: list[str] = Field(default_factory=list)
    results: list[MutantResult] = Field(default_factory=list)


class AdaptiveTierSummary(StrictModel):
    """Detection of deterministic variants (paraphrase, encodings, Polish, split) of the attack cases."""

    generated_at: datetime
    variants: int
    detection: RateWithCI | None = None
    by_technique: dict[str, RateWithCI] = Field(default_factory=dict)
    by_control: dict[str, RateWithCI] = Field(default_factory=dict)
    by_preset: dict[str, RateWithCI] = Field(default_factory=dict)
    layer_attribution: dict[str, int] = Field(default_factory=dict)


class ControlQuality(StrictModel):
    control_id: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    detection_rate: RateWithCI | None = None
    fpr: RateWithCI | None = None


class GuardQualitySummary(StrictModel):
    generated_at: datetime
    suite: str
    mode: Literal["deterministic", "live"]
    per_control: list[ControlQuality] = Field(default_factory=list)
    per_preset: dict[str, dict[str, float]] = Field(default_factory=dict)
    asr: RateWithCI | None = None
    fpr_per_call: RateWithCI | None = None
    fpr_per_task: RateWithCI | None = None
    layer_attribution: dict[str, int] = Field(default_factory=dict)
    leak_rate_by_channel: dict[str, float] = Field(default_factory=dict)
    judge_kappa: dict[str, float] = Field(default_factory=dict)
    shadow_miss_rate: float | None = None
    mutation: MutationCoverage | None = None
    adaptive: AdaptiveTierSummary | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class StageLatency(StrictModel):
    phase: str
    control_id: str | None = None
    count: int
    p50_ms: float
    p95_ms: float
    p99_ms: float


class PerformanceSummary(StrictModel):
    generated_at: datetime
    stages: list[StageLatency] = Field(default_factory=list)
    cache_hit_rate: float = 0.0
    judge_escalation_rate: float = 0.0
    fail_open_count: int = 0


class OverviewSummary(StrictModel):
    generated_at: datetime
    window: str = "24h"
    posture_score: float = Field(ge=0, le=100)
    decisions_by_action: dict[str, int] = Field(default_factory=dict)
    top_rules: dict[str, int] = Field(default_factory=dict)
    top_taxonomy: dict[str, int] = Field(default_factory=dict)
    external_routing_rate: float = 0.0
    spend_usd: float = 0.0
    savings_usd_vs_external: float = 0.0
    open_incidents: int = 0
    pending_approvals: int = 0


class ChainVerifyResult(StrictModel):
    ok: bool
    records: int
    head_seq: int | None = None
    head_hash: str | None = None
    first_bad_seq: int | None = None
    message: str = ""
