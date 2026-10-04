"""Admin API models (`/admin/v1/...`). Consumed by the panel via a generated client."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints

from .audit import AuditEvent
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


class PolicyRollbackRequest(StrictModel):
    """Optional body of `POST /policy/versions/{id}/rollback` (the route still works with no body)."""

    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)] = Field(
        description="Why the policy is rolled back (audit trail)."
    )


class PolicyVersion(StrictModel):
    id: int
    version: str
    created_at: datetime
    author: str | None = None
    source: Literal["file", "panel", "rollback", "startup"]
    message: str = ""
    reason: str | None = Field(default=None, description="Rollback reason given by the admin (source `rollback`).")
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


class UsageStats(StrictModel):
    """Traffic of one principal or group over a window (decision events only)."""

    window: str = Field(examples=["7d", "today"])
    requests: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    blocks: int = Field(default=0, description="Decisions enforced as `block`.")
    usd: float = 0.0
    gpu_seconds: float = 0.0
    last_active: datetime | None = None


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
    preset: Preset | None = Field(default=None, description="Effective preset (strictest of groups and grants).")
    stats_7d: UsageStats | None = None


CloudDataCeiling = Literal["none", "public", "internal"]


class GroupSettings(StrictModel):
    """The panel-editable part of a policy group (`groups.yaml` + the group's `usd_day` in `budgets.yaml`)."""

    preset: Preset | None = None
    models: list[str] = Field(default_factory=list, description="Model ids, aliases or skills granted to the group.")
    tools: list[str] = Field(default_factory=list, description="Tool ids granted to the group, e.g. `opencode.bash`.")
    max_cloud_data_class: CloudDataCeiling = Field(
        default="internal",
        description="Highest data class cloud models may receive. `none`: the group has no cloud model at all. "
        "Confidential and above never go to the cloud (LOCK-01).",
    )
    daily_budget_usd: float | None = Field(default=None, ge=0)


class Group(StrictModel):
    name: str
    description: str = ""
    preset: Preset | None = None
    members: int = 0
    source: Literal["keycloak", "policy", "both"] = "both"
    settings: GroupSettings | None = Field(default=None, description="Null for groups that exist only in Keycloak.")
    stats_today: UsageStats | None = None
    policy_file: str | None = Field(default=None, examples=["groups.yaml"])
    policy_line: int | None = Field(default=None, description="Line of the group's block in the policy file.")


class GroupSettingsUpdate(StrictModel):
    settings: GroupSettings
    base_version: str = Field(description="Policy version (`PolicyStatus.version`) the edit was based on; stale → 409.")
    message: str = Field(default="", max_length=500)


class GroupSettingsPreview(StrictModel):
    """Draft → validate → impact: what saving these settings would change. Nothing is written."""

    valid: bool
    errors: list[PolicyError] = Field(default_factory=list)
    changes: list[str] = Field(default_factory=list, examples=[["+ model smart", "- tool opencode.bash"]])
    files_changed: list[str] = Field(default_factory=list)
    diff: str = ""
    candidate_version: str | None = None
    impact: DryRunResponse | None = None


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


class SessionLabelInfo(StrictModel):
    """The session's high-water mark after this event (labels only rise within a session)."""

    data_class: DataClass
    trust: Literal["trusted", "untrusted"]
    since: datetime | None = Field(default=None, description="When the data class reached its current level.")
    local_only: bool = Field(default=False, description="At or above the SEC-SESSION-01 threshold: local models only.")


class ClientRef(StrictModel):
    """The client conversation (LibreChat) or session (OpenCode / agent) an event belongs to."""

    kind: Literal["conversation", "session"]
    id: str = Field(description="Gateway session id (principal-namespaced); use with the transcript endpoint.")
    client: str = Field(examples=["librechat", "opencode", "research-bot"])
    message_count: int = 0
    started_at: datetime


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
    applied: list[Action] = Field(default_factory=list, description="Every non-allow action applied (decision chips).")
    client_app: str | None = None
    data_class: DataClass | None = None
    tier: ConnectorTier | None = None
    degraded: bool = False
    tokens_in: int = 0
    tokens_out: int = 0
    summary: str = Field(
        default="",
        description="One plain-language sentence, filled from a template per rule / decision type (never an LLM).",
    )
    changed_steps: dict[str, str] = Field(
        default_factory=dict, description="Trace step → one-line result, only for steps that changed something."
    )
    session_label: SessionLabelInfo | None = None
    client_ref: ClientRef | None = None


TraceStepName = Literal[
    "identity", "normalise", "rules", "similarity", "classifier", "judge", "decide", "approval", "route", "output"
]


class TraceControl(StrictModel):
    control_id: str
    control_type: str
    action: Action
    rule_ids: list[RuleId] = Field(default_factory=list)
    score: Score | None = None
    threshold: float | None = None
    status: str = "ok"
    latency_ms: float = 0.0
    findings: list[str] = Field(default_factory=list, description="Entity types found (never values).")
    reason: str | None = None


class TraceStep(StrictModel):
    step: TraceStepName
    result: str = Field(description="One-line result, e.g. `2 entities pseudonymised`.")
    ms: float | None = None
    changed: bool = False
    controls: list[TraceControl] = Field(default_factory=list)


class EventTrace(StrictModel):
    """Everything the trace sidebar needs for one event."""

    event: EventSummary
    steps: list[TraceStep] = Field(default_factory=list)
    model_saw: str | None = Field(
        default=None, description="Redacted text the model received; only when content was changed."
    )
    model_saw_note: str = ""
    record: AuditEvent


class TranscriptTurn(StrictModel):
    event_id: str
    trace_id: str | None = None
    seq: int
    timestamp: datetime
    point: InspectionPoint | None = None
    role: Literal["user", "assistant", "tool_call", "tool_result", "system"]
    text: str | None = Field(default=None, description="Redacted text only; null when content is not retained.")
    retained: bool = False
    model: str | None = None
    tool: str | None = None
    action: Action | None = None
    applied: list[Action] = Field(default_factory=list)
    rule_ids: list[RuleId] = Field(default_factory=list)
    summary: str = ""


class SessionTranscript(StrictModel):
    """Read-only session view: redacted turns with the decision per turn. Raw content is never returned."""

    session_id: str
    client_ref: ClientRef | None = None
    subject: str | None = None
    username: str | None = None
    groups: list[str] = Field(default_factory=list)
    session_label: SessionLabelInfo | None = None
    started_at: datetime | None = None
    last_at: datetime | None = None
    turns: list[TranscriptTurn] = Field(default_factory=list)
    truncated: bool = False


class IncidentNote(StrictModel):
    author: str
    at: datetime
    text: str


class _EvidenceBase(StrictModel):
    summary: str | None = Field(default=None, description="One plain sentence written from a template, no raw values.")


class McpRugPullEvidence(_EvidenceBase):
    """A pinned MCP tool changed after approval."""

    kind: Literal["mcp_rug_pull"] = "mcp_rug_pull"
    server: str
    tool: str
    tool_id: str
    status: str | None = Field(default=None, description="Pin status after the change: quarantined | drifted.")
    approved_hash: str | None = Field(default=None, description="Pinned (approved) hash.")
    approved_at: datetime | None = None
    new_hash: str | None = None
    changed_at: datetime | None = None
    description_diff: str | None = Field(default=None, description="Unified-style diff, lines start with + - or space.")
    findings: list[str] = Field(default_factory=list, description="Value-free flag labels.")


class McpToolFlaggedEvidence(_EvidenceBase):
    """A new MCP tool was quarantined as poisoned, or collides with an existing tool name."""

    kind: Literal["mcp_tool_poisoning", "mcp_name_collision"]
    server: str
    tool: str
    tool_id: str
    status: str | None = None
    new_hash: str | None = None
    findings: list[str] = Field(default_factory=list)


class McpProtocolViolationEvidence(_EvidenceBase):
    kind: Literal["mcp_protocol_violation"] = "mcp_protocol_violation"
    server: str | None = None
    violations: list[str] = Field(default_factory=list, description="Violation codes, e.g. `MCP_ORIGIN_MISMATCH`.")


class CanaryEvidence(_EvidenceBase):
    kind: Literal["canary_triggered"] = "canary_triggered"
    tool: str | None = None
    server: str | None = None
    occurrences: int | None = Field(default=None, description="Canary values found (and redacted) in the result.")


class BudgetBreachEvidence(_EvidenceBase):
    kind: Literal["budget_breach"] = "budget_breach"
    level: Literal["soft", "hard", "loop"] | None = None
    node: str | None = Field(default=None, examples=["user:jan", "session:s-1"])
    scope: str | None = None
    session_id: str | None = Field(default=None, description="Set when the node is a session.")
    meter: str | None = Field(default=None, examples=["usd_day", "gpu_seconds_session"])
    limit: float | None = None
    used: float | None = None
    projected: float | None = None
    action: str | None = Field(default=None, description="alert | block | degrade_to_local | require_approval ...")
    breaker: Literal["closed", "open", "half_open"] | None = None
    cooldown_s: int | None = None
    loop_rule: str | None = Field(default=None, description="Runaway-signal rule id when `level` is `loop`.")


class ForbiddenModelEvidence(_EvidenceBase):
    kind: Literal["forbidden_model"] = "forbidden_model"
    model: str | None = None


class BlockedEvidence(_EvidenceBase):
    """Enforced block that opened a grouped incident (`blocked_request` / `blocked_response`)."""

    kind: Literal["blocked_request", "blocked_response"]
    point: str | None = None
    decided_by: str | None = Field(default=None, description="Control id that decided the block.")


class PluginBypassEvidence(_EvidenceBase):
    kind: Literal["plugin_bypass"] = "plugin_bypass"
    tool: str | None = None
    tool_call_id_hash: str | None = None
    explanation: str | None = None


class GenericEvidence(_EvidenceBase):
    """Fallback for categories without a dedicated shape: scalar facts copied from `detail`."""

    kind: Literal["generic"] = "generic"
    category: str
    facts: dict[str, str | int | float | bool] = Field(default_factory=dict)


IncidentEvidence = Annotated[
    McpRugPullEvidence
    | McpToolFlaggedEvidence
    | McpProtocolViolationEvidence
    | CanaryEvidence
    | BudgetBreachEvidence
    | ForbiddenModelEvidence
    | BlockedEvidence
    | PluginBypassEvidence
    | GenericEvidence,
    Field(discriminator="kind"),
]


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
    detail: dict[str, Any] = Field(default_factory=dict, description="Raw producer detail (free-form; see `evidence`).")
    evidence: IncidentEvidence | None = Field(
        default=None, description="Typed view of `detail`, discriminated on `kind` (the incident category)."
    )


class IncidentPatch(StrictModel):
    status: Literal["open", "triaged", "resolved", "false_positive"] | None = None
    assignee: str | None = None
    note: str | None = Field(default=None, max_length=4000)


# ---------------------------------------------------------------- approvals


class ApprovalPreview(StrictModel):
    """Redacted preview of what the held call would do (never raw secrets or personal data)."""

    type: Literal["diff", "email", "plan", "text"]
    body: str


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
    approver_label: str | None = Field(default=None, examples=["Security team", "Team lead"])
    data_class: str | None = Field(
        default=None, description="Session confidentiality when held: public | internal | confidential | restricted."
    )
    client: str | None = Field(default=None, description="Client app that issued the call.", examples=["opencode"])
    flags: list[str] = Field(
        default_factory=list, description="Red flags, e.g. `untrusted input`, `sensitive data`, `external egress`."
    )
    preview: ApprovalPreview | None = None
    reasons: list[str] = Field(default_factory=list, description="Why it was held: one line per holding control.")


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
    role: str | None = Field(default=None, examples=["fast cloud", "strong cloud", "local, all confidential work"])
    requests_day: int = 0
    tokens_in_day: int = 0
    tokens_out_day: int = 0
    usd_day: float = 0.0
    gpu_seconds_day: float = 0.0


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


class ArtifactScanResult(StrictModel):
    id: str
    filename: str
    sha256: str
    size: int
    format_detected: str
    verdict: Literal["safe", "malicious", "blocked_format", "suspicious"]
    findings: list[ArtifactFinding] = Field(default_factory=list)
    scanned_at: datetime


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


class DecisionBucket(StrictModel):
    start: datetime
    counts: dict[str, int] = Field(default_factory=dict, description="Action → decisions in this bucket.")


class ModelCost(StrictModel):
    model: str
    tier: ConnectorTier
    tokens_in: int = 0
    tokens_out: int = 0
    usd: float = 0.0
    gpu_seconds: float = 0.0
    share: float = Field(default=0.0, ge=0.0, le=1.0, description="Share of all tokens in the window.")


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
    decisions_total: int = 0
    timeline: list[DecisionBucket] = Field(default_factory=list, description="Decisions per time bucket by action.")
    incidents_by_severity: dict[str, int] = Field(default_factory=dict, description="Open incidents by severity.")
    cost_by_model: list[ModelCost] = Field(default_factory=list)
    usd_today: float = 0.0
    usd_limit_day: float | None = None
    usd_forecast_day: float | None = None
    gpu_seconds_today: float = 0.0
    gpu_seconds_limit_day: float | None = None


class ChainVerifyResult(StrictModel):
    ok: bool
    records: int
    head_seq: int | None = None
    head_hash: str | None = None
    first_bad_seq: int | None = None
    message: str = ""
