"""Shared enums and small value types used across all contracts.

This module is part of the *contract surface* (owned by the orchestrator). Changing
anything here changes `contracts/*.json`; run `make contracts` and get the change reviewed.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

CONTRACT_VERSION = "1.0.0"


class StrictModel(BaseModel):
    """Base for contract models: unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class InspectionPoint(StrEnum):
    """Where in the traffic flow a payload is inspected (concept §6.1)."""

    ingress = "ingress"  # user/agent -> model (prompt, history, attachments)
    egress = "egress"  # model -> user/agent (answer text + tool_calls)
    tool_call = "tool_call"  # agent -> tool (name + arguments)
    tool_result = "tool_result"  # tool -> agent (untrusted by default)
    embeddings = "embeddings"  # text sent to an embedding model
    agent_message = "agent_message"  # agent -> agent / memory write (stretch)
    artifact_load = "artifact_load"  # model file entering the registry/runtime
    mcp_initialize = "mcp_initialize"  # MCP initialize handshake
    mcp_tools_list = "mcp_tools_list"  # MCP tools/list and list_changed


class Phase(StrEnum):
    """Pipeline phases, executed in this order (concept §6.2)."""

    normalise = "normalise"  # stage 0
    deterministic = "deterministic"  # stage 1
    similarity = "similarity"  # stage 1b
    semantic_l1 = "semantic_l1"  # stage 2
    semantic_l2 = "semantic_l2"  # stage 3 (escalation only)
    decide = "decide"  # stage 4
    egress_hygiene = "egress_hygiene"  # stage 5


PHASE_ORDER: tuple[Phase, ...] = tuple(Phase)


class CostTier(StrEnum):
    deterministic = "deterministic"
    similarity = "similarity"
    l1 = "l1"
    l2 = "l2"


class FailMode(StrEnum):
    closed = "closed"  # error/timeout -> block (final)
    open = "open"  # error/timeout -> ignore the control
    open_with_alert = "open_with_alert"  # ignore + emit a system_alert event


class Action(StrEnum):
    """Decision actions (concept §6.3)."""

    allow = "allow"
    monitor = "monitor"
    redact = "redact"
    pseudonymise = "pseudonymise"
    sanitize = "sanitize"
    route_local = "route_local"
    downgrade = "downgrade"
    require_approval = "require_approval"
    block = "block"


# Higher = more severe. Used to pick the primary action; transforms
# (redact/pseudonymise/sanitize/route_local/downgrade) are also kept as obligations.
ACTION_SEVERITY: dict[Action, int] = {
    Action.allow: 0,
    Action.monitor: 1,
    Action.redact: 2,
    Action.pseudonymise: 2,
    Action.sanitize: 3,
    Action.route_local: 3,
    Action.downgrade: 4,
    Action.require_approval: 5,
    Action.block: 6,
}


class Preset(StrEnum):
    monitor = "monitor"
    balanced = "balanced"
    strict = "strict"
    paranoid = "paranoid"


class DataClass(StrEnum):
    """Confidentiality classes, ordered from least to most sensitive."""

    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"


DATA_CLASS_ORDER: dict[DataClass, int] = {c: i for i, c in enumerate(DataClass)}


class Integrity(StrEnum):
    trusted = "trusted"
    untrusted = "untrusted"


class PolicyMode(StrEnum):
    enforce = "enforce"
    monitor = "monitor"  # evaluate everything, never block; record would_action


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class PrincipalKind(StrEnum):
    user = "user"
    agent = "agent"
    service = "service"
    anonymous = "anonymous"


class AuthMethod(StrEnum):
    jwt = "jwt"
    api_key = "api_key"
    client_credentials = "client_credentials"
    none = "none"


class ConnectorTier(StrEnum):
    local = "local"
    cloud = "cloud"


class ToolTier(StrEnum):
    """Tool policy tiers (concept §9)."""

    deny = "deny"
    must = "must"
    allow = "allow"
    confirm = "confirm"


class ToolLabel(StrEnum):
    reads_untrusted = "reads_untrusted"
    touches_sensitive = "touches_sensitive"
    external_egress = "external_egress"
    irreversible = "irreversible"


class Capability(StrEnum):
    network = "network"
    filesystem = "filesystem"
    env = "env"
    exec = "exec"
    libraries = "libraries"


class TaintFlag(StrEnum):
    untrusted = "untrusted"  # session has ingested untrusted content
    sensitive = "sensitive"  # session holds confidential/restricted data
    egress_used = "egress_used"  # an external-egress tool already ran


class VerdictStatus(StrEnum):
    ok = "ok"
    cached = "cached"
    timeout = "timeout"
    error = "error"
    skipped = "skipped"


class ApprovalStatus(StrEnum):
    pending = "pending"
    approved = "approved"
    denied = "denied"
    expired = "expired"


class GrantResourceType(StrEnum):
    model = "model"
    alias = "alias"
    connector = "connector"
    skill = "skill"
    tool = "tool"
    mcp_server = "mcp_server"


class RiskFactorName(StrEnum):
    """Graded risk-score factors (concept §6.5)."""

    intent_deviation = "intent_deviation"
    tool_sensitivity = "tool_sensitivity"
    data_sensitivity = "data_sensitivity"
    chain_anomaly = "chain_anomaly"
    parameter_risk = "parameter_risk"


ControlId = Annotated[
    str,
    Field(
        pattern=r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$",
        description="Stable rule/control identifier, e.g. SEC-PII-01.",
        examples=["SEC-PII-01"],
    ),
]
RuleId = Annotated[
    str,
    Field(
        pattern=r"^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$",
        description="Rule identifier (control id, or control id + sub-rule, or signature id).",
    ),
]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Score = Annotated[float, Field(ge=0.0, le=1.0)]


class Taxonomy(StrictModel):
    """Framework tags attached to rules and events (concept §13)."""

    owasp_llm: list[str] = Field(default_factory=list, examples=[["LLM01:2025"]])
    owasp_agentic: list[str] = Field(default_factory=list, examples=[["ASI01"]])
    owasp_mcp: list[str] = Field(default_factory=list, examples=[["MCP03"]])
    atlas: list[str] = Field(default_factory=list, examples=[["AML.T0051"]])
    cve: list[str] = Field(default_factory=list)


class Versions(StrictModel):
    """Everything needed to replay a decision (concept §13)."""

    policy: str = Field(description="Compiled policy version id.")
    grants: str = Field(default="0", description="Grants-table version (monotonic).")
    signatures: str = Field(default="0", description="Signature bundle version.")
    classifiers: dict[str, str] = Field(default_factory=dict)
    judges: dict[str, str] = Field(default_factory=dict)
    gateway: str = Field(default="0.1.0")
