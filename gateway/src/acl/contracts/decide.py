"""`/v1/decide` API: clients (the OpenCode plugin) ask about a local action before running it."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from .common import Action, ApprovalStatus, RuleId, Score, StrictModel
from .decision import ApprovalRef
from .inspection import ClientInfo, SessionLabels


class DecideAction(StrictModel):
    kind: Literal["tool_call"] = "tool_call"
    tool: str = Field(
        description="Tool id: client built-ins as `opencode.<name>` (read, write, edit, bash, webfetch), "
        "MCP tools as `<server>.<tool>`.",
        examples=["opencode.bash", "opencode.read", "files.read_file"],
    )
    arguments: dict[str, Any] = Field(default_factory=dict)
    tool_call_id: str | None = Field(
        default=None, description="Id of the model tool_call this action executes (used for bypass detection)."
    )
    server: str | None = None
    cwd: str | None = None
    workspace_root: str | None = None


class DecideRequest(StrictModel):
    session_id: str
    action: DecideAction
    client: ClientInfo | None = None
    user_request: str | None = Field(default=None, description="Trusted original user request, if the client knows it.")


class DecideResponse(StrictModel):
    decision_id: str
    trace_id: str
    action: Action = Field(
        description="Clients must treat anything other than allow/redact/monitor as not-allowed. "
        "`require_approval` → poll the approval; `redact` → run with `modified_arguments`."
    )
    rule_ids: list[RuleId] = Field(default_factory=list)
    reason: str = ""
    risk_score: Score = 0.0
    modified_arguments: dict[str, Any] | None = None
    approval: ApprovalRef | None = None
    labels: SessionLabels = Field(default_factory=SessionLabels)
    policy_version: str


class Elevation(StrictModel):
    scope: str = Field(examples=["tool:opencode.write"])
    until: datetime


class ApprovalStatusResponse(StrictModel):
    approval_id: str
    status: ApprovalStatus
    tool: str | None = None
    rule_ids: list[RuleId] = Field(default_factory=list)
    reason: str = ""
    decided_by: str | None = None
    decided_at: datetime | None = None
    expires_at: datetime | None = None
    elevation: Elevation | None = None
    note: str | None = None


class ApprovalDecisionRequest(StrictModel):
    decision: Literal["approve", "deny"]
    elevation_minutes: int | None = Field(default=None, ge=0, le=240)
    note: str | None = Field(default=None, max_length=2000)
