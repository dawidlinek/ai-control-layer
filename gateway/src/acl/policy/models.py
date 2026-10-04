"""Policy models (concept §11). Source of `contracts/policy.schema.json`.

CONTRACT FILE (orchestrator-owned). The policy directory holds several YAML files, each a
`PolicyDocument` (every section optional). The loader merges them into one `Policy`; a section
may appear in only one file. `Policy` performs cross-reference validation.

Strings of the form `env:NAME` are resolved from the gateway environment at compile time
(never stored resolved). Allowed in: connector `base_url`/`api_key`/`headers`, model
`upstream_model`, feed `url`/`public_key`, audit `value_hash_salt`.
"""

from __future__ import annotations

import fnmatch
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator

from acl.contracts.common import (
    Action,
    Capability,
    ConnectorTier,
    ControlId,
    CostTier,
    DataClass,
    FailMode,
    GrantResourceType,
    InspectionPoint,
    PolicyMode,
    Preset,
    StrictModel,
    Taxonomy,
    ToolLabel,
    ToolTier,
)
from acl.contracts.feed import SignatureEntry

EnvRef = Annotated[str, Field(pattern=r"^env:[A-Z_][A-Z0-9_]*$")]
ModelId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]*/[A-Za-z0-9._:/-]+$", examples=["local/qwen3.8-27b"])]
ToolId = Annotated[str, Field(pattern=r"^[a-z0-9_-]+\.[a-z0-9_./-]+$", examples=["opencode.bash", "mail.send"])]
GroupName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$")]

# ---------------------------------------------------------------- controls.yaml


class FailModeSettings(StrictModel):
    deterministic: FailMode = FailMode.closed
    semantic: FailMode = FailMode.open_with_alert


class LatencyBudget(StrictModel):
    semantic: int = Field(default=150, ge=1)
    total: int = Field(default=400, ge=1)


class GlobalSettings(StrictModel):
    mode: PolicyMode = PolicyMode.enforce
    default_preset: Preset = Preset.balanced
    fail_mode: FailModeSettings = Field(default_factory=FailModeSettings)
    latency_budget_ms: LatencyBudget = Field(default_factory=LatencyBudget)
    store_redacted_payloads: bool = True
    unknown_principal: Literal["deny"] = "deny"


class RiskCutoffs(StrictModel):
    """Composite risk score → graded action (concept §6.5). Must be ascending."""

    sanitize: float = Field(default=0.4, ge=0, le=1)
    approval: float = Field(default=0.7, ge=0, le=1)
    block: float = Field(default=0.9, ge=0, le=1)

    @model_validator(mode="after")
    def _ascending(self) -> RiskCutoffs:
        if not (self.sanitize <= self.approval <= self.block):
            raise ValueError("risk_cutoffs must satisfy sanitize <= approval <= block")
        return self


class PresetSettings(StrictModel):
    injection_threshold: float = Field(ge=0, le=1)
    judge_band: tuple[float, float] = (0.3, 0.8)
    judge_on: Literal["none", "sinks", "outbound", "all"] = "sinks"
    pii_action: Action = Action.pseudonymise
    secret_action: Action = Action.block
    sensitive_external_action: Action = Field(
        default=Action.route_local, description="Sensitive data sent to a model not allowed for its class."
    )
    risk_cutoffs: RiskCutoffs = Field(default_factory=RiskCutoffs)
    tool_mode: Literal["tiers", "allowlist"] = "tiers"
    taint_mode: Literal["rule_of_two", "full"] = "rule_of_two"
    rule_of_two_action: Action = Action.require_approval
    never_block: bool = Field(default=False, description="True for `monitor`: log + tag only.")
    shadow_sample_rate: float = Field(default=0.0, ge=0, le=1)
    approval_on_writes: bool = False

    @field_validator("judge_band")
    @classmethod
    def _band(cls, v: tuple[float, float]) -> tuple[float, float]:
        lo, hi = v
        if not (0 <= lo <= hi <= 1):
            raise ValueError("judge_band must be [lo, hi] with 0 <= lo <= hi <= 1")
        return v


class ControlConfig(StrictModel):
    """One configured control instance. `type` selects the implementation in the registry."""

    id: ControlId
    type: str = Field(pattern=r"^[a-z][a-z0-9_]*$", examples=["pii", "secrets", "rule_of_two"])
    enabled: bool = True
    description: str = ""
    stages: list[InspectionPoint] = Field(min_length=1)
    cost_tier: CostTier
    fail_mode: FailMode | None = Field(default=None, description="Null → global.fail_mode by cost tier.")
    timeout_ms: int = Field(ge=1, le=60000)
    action: Action | None = Field(default=None, description="Override the action the control emits on a hit.")
    mode: PolicyMode | None = Field(default=None, description="Per-control shadow mode.")
    presets: list[Preset] | None = Field(default=None, description="Only active under these presets; null = all.")
    locked: bool = Field(default=False, description="Cannot be disabled or edited from the panel.")
    taxonomy: Taxonomy = Field(default_factory=Taxonomy)
    params: dict[str, Any] = Field(
        default_factory=dict, description="Type-specific parameters, validated by the control's Params model."
    )


class FeedSettings(StrictModel):
    url: str
    poll_s: int = Field(default=30, ge=1)
    verify: Literal["sha256", "ed25519"] = "sha256"
    public_key: str | None = None
    on_fail: Literal["keep_last_good"] = "keep_last_good"


class SignatureSettings(StrictModel):
    feed: FeedSettings | None = None
    local_rules: list[SignatureEntry] = Field(
        default_factory=list, description="Rules that apply even when the feed is unreachable."
    )


class AuditSettings(StrictModel):
    path: str = "logs/audit.jsonl"
    format: Literal["jsonl", "ocsf"] = "jsonl"
    hash_chain: Literal[True] = True
    store_raw_payloads: bool = False
    raw_retention_hours: int = Field(default=24, ge=0)
    value_hash_salt: str = "env:ACL_VALUE_HASH_SALT"


class ReportingSettings(StrictModel):
    audit_log: AuditSettings = Field(default_factory=AuditSettings)


# ---------------------------------------------------------------- models.yaml


class ConnectorConfig(StrictModel):
    type: Literal["ollama", "openai_compatible", "mock"]
    base_url: str | None = None
    api_key: EnvRef | None = None
    tier: ConnectorTier
    enabled: bool = True
    timeout_s: float = Field(default=60, gt=0)
    headers: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _needs_url(self) -> ConnectorConfig:
        if self.type != "mock" and not self.base_url:
            raise ValueError(f"connector type {self.type!r} requires base_url")
        return self


class Pricing(StrictModel):
    in_per_1k: float = Field(default=0.0, ge=0)
    out_per_1k: float = Field(default=0.0, ge=0)
    usd_per_gpu_second: float = Field(default=0.0, ge=0)
    gpu_seconds_per_1k_tokens: float | None = Field(
        default=None, ge=0, description="Estimate used when the upstream reports no timings (vLLM/SGLang)."
    )


class SpecialistConfig(StrictModel):
    task: str = Field(examples=["loan_memo"])
    min_confidence: float = Field(default=0.8, ge=0, le=1)
    examples: list[str] = Field(default_factory=list, description="Example prompts for kNN task matching.")


class ArtifactRef(StrictModel):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scan_id: str | None = None


class ModelEntry(StrictModel):
    id: ModelId
    connector: str
    upstream_model: str = Field(description="Name sent upstream, or `env:NAME`.")
    aliases: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    capabilities: list[Literal["chat", "tools", "embeddings", "vision", "reasoning"]] = Field(
        default_factory=lambda: ["chat"]
    )
    data_classes: list[DataClass] = Field(min_length=1)
    pricing: Pricing = Field(default_factory=Pricing)
    specialist: SpecialistConfig | None = None
    system_prompt: str | None = Field(
        default=None, description="Prepended system prompt (prompt-configured specialist stand-ins)."
    )
    artifact: ArtifactRef | None = None
    enabled: bool = True
    context_window: int | None = Field(default=None, ge=1)
    max_output_tokens: int | None = Field(default=None, ge=1)
    request_defaults: dict[str, Any] = Field(
        default_factory=dict,
        description="Upstream request parameters set when the client did not send them "
        "(e.g. `reasoning_effort: low` for Gemini's OpenAI endpoint).",
    )
    reasoning_headroom_tokens: int = Field(
        default=0,
        ge=0,
        description="Reasoning models count hidden thinking tokens against max_tokens: this many tokens are added "
        "to the client's max_tokens / max_completion_tokens upstream so a short answer is not cut off mid-thought.",
    )


class AliasConfig(StrictModel):
    strategy: Literal["fixed", "rules", "specialist_then_rules"]
    target: str | None = Field(default=None, description="Model id for `fixed`.")
    description: str = ""

    @model_validator(mode="after")
    def _fixed_target(self) -> AliasConfig:
        if self.strategy == "fixed" and not self.target:
            raise ValueError("alias strategy 'fixed' requires target")
        return self


class SkillConfig(StrictModel):
    description: str = ""
    template: str = Field(description="Prompt template with `{field}` placeholders from input_schema.")
    input_schema: dict[str, Any] = Field(default_factory=dict)
    model: str
    tools: list[ToolId] = Field(default_factory=list)
    preset: Preset = Preset.strict
    data_classes: list[DataClass] = Field(default_factory=lambda: [DataClass.public, DataClass.internal])


# ---------------------------------------------------------------- groups.yaml


class DataClassTierLock(StrictModel):
    kind: Literal["data_class_tier"] = "data_class_tier"
    id: ControlId
    description: str = ""
    data_classes: list[DataClass] = Field(min_length=1)
    allowed_tiers: list[ConnectorTier] = Field(min_length=1)


class ControlLock(StrictModel):
    kind: Literal["control_locked"] = "control_locked"
    id: ControlId
    description: str = ""
    controls: list[ControlId] = Field(min_length=1)


class DenyResourceLock(StrictModel):
    kind: Literal["deny_resource"] = "deny_resource"
    id: ControlId
    description: str = ""
    resource_type: GrantResourceType
    resources: list[str] = Field(min_length=1, description="Glob patterns.")
    except_groups: list[GroupName] = Field(default_factory=list)


OrgLock = Annotated[DataClassTierLock | ControlLock | DenyResourceLock, Field(discriminator="kind")]


class ToolGrant(StrictModel):
    tier: ToolTier | None = Field(default=None, description="Override the tool's default tier for this group.")
    path_allow: list[str] = Field(default_factory=list)
    path_deny: list[str] = Field(default_factory=list)
    recipients_allow: list[str] = Field(default_factory=list)
    domains_allow: list[str] = Field(default_factory=list)
    max_calls_session: int | None = Field(default=None, ge=0)


class RepeatCall(StrictModel):
    count: int = Field(default=3, ge=1)
    window_s: int = Field(default=60, ge=1)


class GroupLimits(StrictModel):
    max_steps: int | None = Field(default=None, ge=1)
    max_tool_depth: int | None = Field(default=None, ge=1)
    max_fanout: int | None = Field(default=None, ge=1)
    repeat_call: RepeatCall | None = None
    requests_per_minute: int | None = Field(default=None, ge=1)


class RepoRule(StrictModel):
    models: list[str] = Field(default_factory=list)
    data_class: DataClass = DataClass.confidential


class GroupPolicy(StrictModel):
    description: str = ""
    preset: Preset | None = None
    models: list[str] = Field(default_factory=list, description="Model ids, aliases, skills, or `connector:<id>`.")
    skills: list[str] = Field(default_factory=list)
    tools: dict[ToolId, ToolGrant] = Field(default_factory=dict)
    mcp_servers: list[str] = Field(default_factory=list)
    max_external_data_class: DataClass = DataClass.internal
    limits: GroupLimits | None = None
    repos: dict[str, RepoRule] = Field(default_factory=dict)

    @field_validator("tools", mode="before")
    @classmethod
    def _tools_list(cls, v: Any) -> Any:
        if isinstance(v, list):  # shorthand: [fs.read, shell]
            return {t: {} for t in v}
        return v


# ---------------------------------------------------------------- tools.yaml


class McpServerConfig(StrictModel):
    transport: Literal["streamable_http", "stdio"]
    url: str | None = None
    command: list[str] | None = None
    origin: str | None = Field(default=None, description="Expected server identity/origin bound at initialize.")
    allowed: bool = True
    description: str = ""
    egress_allow: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _endpoint(self) -> McpServerConfig:
        if self.transport == "streamable_http" and not self.url:
            raise ValueError("streamable_http server requires url")
        if self.transport == "stdio" and not self.command:
            raise ValueError("stdio server requires command")
        return self


class ArgChecker(StrictModel):
    type: Literal["path", "sql", "command", "url", "recipient", "package"]
    field: str = Field(description="Argument name (dot path) the checker applies to.")
    params: dict[str, Any] = Field(default_factory=dict)


class ToolDef(StrictModel):
    server: str | None = Field(default=None, description="MCP server id; null = client built-in tool.")
    name: str | None = Field(default=None, description="Upstream tool name if different from the id suffix.")
    description: str = ""
    labels: list[ToolLabel] = Field(default_factory=list)
    capabilities: list[Capability] = Field(default_factory=list)
    default_tier: ToolTier = ToolTier.confirm
    schema_pin: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    arguments_schema: dict[str, Any] | None = Field(
        default=None, description="Pinned argument JSON Schema; unknown fields are always rejected."
    )
    checkers: list[ArgChecker] = Field(default_factory=list)


# ---------------------------------------------------------------- budgets.yaml


class BudgetLimits(StrictModel):
    tokens_minute: int | None = Field(default=None, ge=0)
    tokens_day: int | None = Field(default=None, ge=0)
    tokens_month: int | None = Field(default=None, ge=0)
    tokens_session: int | None = Field(default=None, ge=0)
    usd_day: float | None = Field(default=None, ge=0)
    usd_month: float | None = Field(default=None, ge=0)
    usd_session: float | None = Field(default=None, ge=0)
    gpu_seconds_day: float | None = Field(default=None, ge=0)
    gpu_seconds_month: float | None = Field(default=None, ge=0)
    gpu_seconds_session: float | None = Field(default=None, ge=0)
    requests_per_minute: int | None = Field(default=None, ge=0)
    tool_calls_session: int | None = Field(default=None, ge=0)


class BreakerSettings(StrictModel):
    cooldown_s: int = Field(default=300, ge=1)
    half_open_probes: int = Field(default=1, ge=1)


class OnExceed(StrictModel):
    soft_pct: int = Field(default=80, ge=1, le=100)
    soft_action: Literal["alert"] = "alert"
    hard_action: Literal["block", "degrade_to_local"] = "block"
    circuit_breaker: BreakerSettings = Field(default_factory=BreakerSettings)


class RepeatNgram(StrictModel):
    n: int = Field(default=8, ge=2)
    max_repeats: int = Field(default=6, ge=2)


class StreamCaps(StrictModel):
    max_output_tokens: int = Field(default=4096, ge=1)
    max_reasoning_tokens: int = Field(default=2048, ge=0)
    repeat_ngram: RepeatNgram = Field(default_factory=RepeatNgram)
    holdback_chars: int = Field(default=256, ge=0, description="Egress hold-back window for streaming moderation.")


class LoopSettings(StrictModel):
    repeat_call: RepeatCall = Field(default_factory=RepeatCall)
    max_steps: int = Field(default=50, ge=1)
    max_tool_depth: int = Field(default=8, ge=1)
    spend_spike_factor: float = Field(default=5.0, gt=1)


class GuardBudget(StrictModel):
    tokens_per_request: int = Field(default=4000, ge=0)
    gpu_seconds_per_request: float = Field(default=5.0, ge=0)


class CacheSettings(StrictModel):
    enabled: bool = True
    ttl_s: int = Field(default=300, ge=0)


class Budgets(StrictModel):
    org: BudgetLimits = Field(default_factory=BudgetLimits)
    groups: dict[GroupName, BudgetLimits] = Field(default_factory=dict)
    users: dict[str, BudgetLimits] = Field(default_factory=dict)
    agents: dict[str, BudgetLimits] = Field(default_factory=dict)
    default_user: BudgetLimits = Field(default_factory=BudgetLimits)
    on_exceed: OnExceed = Field(default_factory=OnExceed)
    stream: StreamCaps = Field(default_factory=StreamCaps)
    loops: LoopSettings = Field(default_factory=LoopSettings)
    guard: GuardBudget = Field(default_factory=GuardBudget)
    cache: CacheSettings = Field(default_factory=CacheSettings)


# ---------------------------------------------------------------- routing.yaml


SensitivityLevel = Literal["high", "medium", "low"]


class ComplexityBands(StrictModel):
    local_max: float = Field(default=0.3, ge=0, le=1)
    ext_small_max: float = Field(default=0.7, ge=0, le=1)


class RoutingTargets(StrictModel):
    local: str
    ext_small: str
    ext_large: str
    degraded: str = Field(description="Local fallback when budgets are exhausted or a cloud connector is down.")
    embeddings: str | None = None
    judge: str | None = None


class SpecialistRouting(StrictModel):
    enabled: bool = True
    method: Literal["tags", "knn", "classifier"] = "knn"
    default_min_confidence: float = Field(default=0.8, ge=0, le=1)


class TaskScopedPolicy(StrictModel):
    presets: list[Preset] = Field(default_factory=lambda: [Preset.strict, Preset.paranoid])
    planner_model: str | None = None
    on_violation: Action = Action.block


class RoutingSettings(StrictModel):
    sensitivity: dict[SensitivityLevel, Literal["local_only", "redact_then_external", "by_complexity"]] = Field(
        default_factory=lambda: {"high": "local_only", "medium": "redact_then_external", "low": "by_complexity"}
    )
    data_class_sensitivity: dict[DataClass, SensitivityLevel] = Field(
        default_factory=lambda: {
            DataClass.public: "low",
            DataClass.internal: "low",
            DataClass.confidential: "high",
            DataClass.restricted: "high",
        }
    )
    complexity_bands: ComplexityBands = Field(default_factory=ComplexityBands)
    targets: RoutingTargets
    escalation_scales_with_remaining_budget: bool = True
    on_budget_exhausted: Literal["degrade_to_local", "block"] = "degrade_to_local"
    specialist: SpecialistRouting = Field(default_factory=SpecialistRouting)
    task_scoped_policy: TaskScopedPolicy = Field(default_factory=TaskScopedPolicy)


# ---------------------------------------------------------------- documents


class PolicyDocument(StrictModel):
    """One policy file. Every section is optional; a section may appear in only one file."""

    schema_: str | None = Field(default=None, alias="$schema")
    global_: GlobalSettings | None = Field(default=None, alias="global")
    presets: dict[Preset, PresetSettings] | None = None
    controls: list[ControlConfig] | None = None
    signatures: SignatureSettings | None = None
    reporting: ReportingSettings | None = None
    connectors: dict[str, ConnectorConfig] | None = None
    models: list[ModelEntry] | None = None
    aliases: dict[str, AliasConfig] | None = None
    skills: dict[str, SkillConfig] | None = None
    org_locks: list[OrgLock] | None = None
    groups: dict[GroupName, GroupPolicy] | None = None
    mcp_servers: dict[str, McpServerConfig] | None = None
    tools: dict[ToolId, ToolDef] | None = None
    budgets: Budgets | None = None
    routing: RoutingSettings | None = None


SECTIONS: tuple[str, ...] = tuple(n for n in PolicyDocument.model_fields if n != "schema_")


class Policy(StrictModel):
    """The merged, cross-validated policy. Built by the loader from all PolicyDocuments."""

    global_: GlobalSettings = Field(default_factory=GlobalSettings, alias="global")
    presets: dict[Preset, PresetSettings]
    controls: list[ControlConfig] = Field(default_factory=list)
    signatures: SignatureSettings = Field(default_factory=SignatureSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)
    connectors: dict[str, ConnectorConfig]
    models: list[ModelEntry]
    aliases: dict[str, AliasConfig] = Field(default_factory=dict)
    skills: dict[str, SkillConfig] = Field(default_factory=dict)
    org_locks: list[OrgLock] = Field(default_factory=list)
    groups: dict[GroupName, GroupPolicy] = Field(default_factory=dict)
    mcp_servers: dict[str, McpServerConfig] = Field(default_factory=dict)
    tools: dict[ToolId, ToolDef] = Field(default_factory=dict)
    budgets: Budgets = Field(default_factory=Budgets)
    routing: RoutingSettings

    # ------------------------------------------------------------ helpers

    def model_by_id(self) -> dict[str, ModelEntry]:
        return {m.id: m for m in self.models}

    def alias_names(self) -> set[str]:
        names = set(self.aliases)
        for m in self.models:
            names.update(m.aliases)
        return names

    def resolvable_names(self) -> set[str]:
        """Everything a group may list under `models`."""
        names = {m.id for m in self.models} | self.alias_names() | set(self.skills)
        names |= {f"connector:{c}" for c in self.connectors}
        return names

    # ------------------------------------------------------------ cross validation

    @model_validator(mode="after")
    def _cross_refs(self) -> Policy:
        errors: list[str] = []

        missing = [p for p in Preset if p not in self.presets]
        if missing:
            errors.append(f"presets: missing definitions for {', '.join(missing)}")

        ids = [c.id for c in self.controls]
        dup = sorted({i for i in ids if ids.count(i) > 1})
        if dup:
            errors.append(f"controls: duplicate ids {dup}")

        model_ids = [m.id for m in self.models]
        dup_m = sorted({i for i in model_ids if model_ids.count(i) > 1})
        if dup_m:
            errors.append(f"models: duplicate ids {dup_m}")
        for m in self.models:
            if m.connector not in self.connectors:
                errors.append(f"models[{m.id}]: unknown connector {m.connector!r}")

        alias_owner: dict[str, str] = {}
        for m in self.models:
            for a in m.aliases:
                if a in alias_owner:
                    errors.append(f"alias {a!r} defined by both {alias_owner[a]} and {m.id}")
                alias_owner[a] = m.id
        mids = set(model_ids)
        for name, a in self.aliases.items():
            if a.target and a.target not in mids:
                errors.append(f"aliases[{name}]: unknown target {a.target!r}")

        for sid, s in self.skills.items():
            if not sid.startswith("skill/"):
                errors.append(f"skills[{sid}]: id must start with 'skill/'")
            if s.model not in mids and s.model not in self.alias_names():
                errors.append(f"skills[{sid}]: unknown model {s.model!r}")

        names = self.resolvable_names()
        for g, gp in self.groups.items():
            for ref in gp.models:
                if ref not in names:
                    errors.append(f"groups[{g}].models: unknown {ref!r}")
            for ref in gp.skills:
                if ref not in self.skills:
                    errors.append(f"groups[{g}].skills: unknown {ref!r}")
            for t in gp.tools:
                if t not in self.tools:
                    errors.append(f"groups[{g}].tools: unknown tool {t!r}")
            for s in gp.mcp_servers:
                if s not in self.mcp_servers:
                    errors.append(f"groups[{g}].mcp_servers: unknown server {s!r}")
            for pattern, rule in gp.repos.items():
                for ref in rule.models:
                    if ref not in names:
                        errors.append(f"groups[{g}].repos[{pattern}]: unknown model {ref!r}")

        for tid, t in self.tools.items():
            if t.server is not None and t.server not in self.mcp_servers:
                errors.append(f"tools[{tid}]: unknown server {t.server!r}")

        control_ids = set(ids)
        for lock in self.org_locks:
            if isinstance(lock, ControlLock):
                for cid in lock.controls:
                    if cid not in control_ids:
                        errors.append(f"org_locks[{lock.id}]: unknown control {cid!r}")
            if isinstance(lock, DenyResourceLock):
                for pat in lock.resources:
                    if not pat or fnmatch.translate(pat) is None:  # pragma: no cover - defensive
                        errors.append(f"org_locks[{lock.id}]: bad pattern {pat!r}")

        r = self.routing
        for slot in ("local", "ext_small", "ext_large", "degraded", "embeddings", "judge"):
            ref = getattr(r.targets, slot)
            if ref is not None and ref not in mids and ref not in self.alias_names():
                errors.append(f"routing.targets.{slot}: unknown model {ref!r}")
        degraded = self.model_by_id().get(r.targets.degraded)
        if degraded is not None and self.connectors[degraded.connector].tier != ConnectorTier.local:
            errors.append("routing.targets.degraded must be a local-tier model")
        if r.complexity_bands.local_max > r.complexity_bands.ext_small_max:
            errors.append("routing.complexity_bands: local_max must be <= ext_small_max")

        if errors:
            raise ValueError("; ".join(errors))
        return self

    def locked_control_ids(self) -> set[str]:
        locked = {c.id for c in self.controls if c.locked}
        for lock in self.org_locks:
            if isinstance(lock, ControlLock):
                locked.update(lock.controls)
        return locked
