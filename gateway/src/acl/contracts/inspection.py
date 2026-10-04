"""InspectionContext: the single input every control receives (concept §6).

One context is built per inspection point (ingress, egress, tool_call, ...). Payloads are a
discriminated union on `kind`. Contexts carry raw content and therefore are NEVER written to
the audit log as-is; the audit record (`acl.contracts.audit.AuditEvent`) stores hashes,
entity types and offsets only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .common import (
    AuthMethod,
    DataClass,
    InspectionPoint,
    Integrity,
    PolicyMode,
    Preset,
    PrincipalKind,
    StrictModel,
    TaintFlag,
    Versions,
)


class Principal(StrictModel):
    """Who is acting. Built by `acl.identity` from a JWT or an API key."""

    subject: str = Field(description="Stable id (Keycloak `sub` or internal agent id).")
    kind: PrincipalKind = PrincipalKind.user
    username: str | None = None
    groups: list[str] = Field(
        default_factory=list, description="Normalised group paths, e.g. `developers`, `agents/research-bot`."
    )
    roles: list[str] = Field(default_factory=list, description="Realm roles, e.g. `acl-admin`.")
    agent_id: str | None = None
    client_id: str | None = Field(default=None, description="OIDC client (azp) that obtained the token.")
    auth_method: AuthMethod = AuthMethod.none
    api_key_id: str | None = None
    delegation_chain: list[str] = Field(
        default_factory=list, description="Subjects from the originating user to this actor (RFC 8693 act chain)."
    )


class ClientInfo(StrictModel):
    app: str = Field(default="unknown", examples=["opencode", "librechat", "sdk", "agent"])
    version: str | None = None
    device_id: str | None = None


# ---------------------------------------------------------------- chat shapes (OpenAI-compatible)


class FunctionCall(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str
    arguments: str = Field(default="{}", description="JSON-encoded arguments, as sent by the model.")


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str
    type: Literal["function"] = "function"
    function: FunctionCall


class ChatMessage(BaseModel):
    """OpenAI chat message. `content` may be a string or a list of content parts."""

    model_config = ConfigDict(extra="allow")
    role: Literal["system", "developer", "user", "assistant", "tool"]
    content: str | list[dict[str, Any]] | None = None
    name: str | None = None
    tool_calls: list[ToolCall] | None = None
    tool_call_id: str | None = None


# ---------------------------------------------------------------- payloads


class ChatPayload(StrictModel):
    kind: Literal["chat"] = "chat"
    messages: list[ChatMessage]
    tools: list[dict[str, Any]] | None = None
    params: dict[str, Any] = Field(
        default_factory=dict, description="Sampling params (max_tokens, temperature, stream, ...)."
    )


class CompletionPayload(StrictModel):
    """Model output inspected at egress (buffered window when streaming)."""

    kind: Literal["completion"] = "completion"
    content: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)
    finish_reason: str | None = None
    reasoning: str | None = Field(default=None, description="Upstream reasoning trace, if any (stripped by default).")
    has_logprobs: bool = False
    is_partial: bool = Field(default=False, description="True for a streaming hold-back window.")


class Package(StrictModel):
    ecosystem: Literal["pypi", "npm", "other"]
    name: str
    version: str | None = None


class ToolIntent(StrictModel):
    """Typed normalisation of a tool call (concept §6.2 stage 0). Malformed calls fail closed."""

    paths: list[str] = Field(default_factory=list, description="Canonicalised absolute paths.")
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    command: str | None = None
    argv: list[str] = Field(default_factory=list)
    sql: str | None = None
    recipients: list[str] = Field(default_factory=list)
    packages: list[Package] = Field(default_factory=list)


class ToolCallPayload(StrictModel):
    kind: Literal["tool_call"] = "tool_call"
    tool: str = Field(description="Policy tool id, e.g. `opencode.bash`, `mail.send`.")
    server: str | None = Field(default=None, description="MCP server id; null for client-local tools.")
    tool_call_id: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    intent: ToolIntent | None = None
    cwd: str | None = None
    workspace_root: str | None = None


class ToolResultPayload(StrictModel):
    kind: Literal["tool_result"] = "tool_result"
    tool: str
    server: str | None = None
    tool_call_id: str | None = None
    content: str
    is_error: bool = False


class EmbeddingsPayload(StrictModel):
    kind: Literal["embeddings"] = "embeddings"
    inputs: list[str]


class McpToolDescriptor(StrictModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] | None = None


class McpPayload(StrictModel):
    kind: Literal["mcp"] = "mcp"
    server: str
    method: str = Field(examples=["initialize", "tools/list", "tools/call", "sampling/createMessage"])
    params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict, description="Mcp-Method / Mcp-Name etc. (2026-07-28).")
    protocol_version: str | None = None
    tools: list[McpToolDescriptor] = Field(default_factory=list)


class ArtifactPayload(StrictModel):
    kind: Literal["artifact"] = "artifact"
    filename: str
    sha256: str
    size: int
    declared_format: str | None = None
    source: str | None = Field(default=None, description="e.g. `hf:org/repo@<revision-sha>`.")
    local_path: str | None = Field(default=None, description="Server-side path of the uploaded file.")


Payload = Annotated[
    ChatPayload
    | CompletionPayload
    | ToolCallPayload
    | ToolResultPayload
    | EmbeddingsPayload
    | McpPayload
    | ArtifactPayload,
    Field(discriminator="kind"),
]


# ---------------------------------------------------------------- session state


class SessionLabels(StrictModel):
    """IFC labels carried by a session (concept §9). Only ever raised without approval."""

    integrity: Integrity = Integrity.trusted
    confidentiality: DataClass = DataClass.public
    taint: list[TaintFlag] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list, description="Rule ids that raised the labels.")
    since: datetime | None = Field(
        default=None, description="When `confidentiality` rose to its current level (the high-water mark time)."
    )


class SessionState(StrictModel):
    session_id: str
    labels: SessionLabels = Field(default_factory=SessionLabels)
    step: int = 0
    tool_depth: int = 0
    downgraded: bool = False
    allowed_tools: list[str] | None = Field(
        default=None, description="Monotonically narrowed tool set; null = not narrowed."
    )
    plan_id: str | None = None


class InspectionContext(StrictModel):
    trace_id: str
    request_id: str
    session_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    point: InspectionPoint
    principal: Principal
    client: ClientInfo = Field(default_factory=ClientInfo)
    preset: Preset = Preset.balanced
    mode: PolicyMode = PolicyMode.enforce
    model_requested: str | None = None
    payload: Payload
    session: SessionState
    versions: Versions
    user_request: str | None = Field(
        default=None, description="Trusted original user request (for alignment / task-scoped policy)."
    )
    seed: int | None = None
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="In-process scratch space: outputs of earlier phases (e.g. normalised text). Never audited.",
    )
