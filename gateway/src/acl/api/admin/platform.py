"""Admin: approvals (2B), budgets (2D), models/connectors (1A/3B), MCP (2A), feed (1D),
artifacts (4A), insights (4B).

Each section is owned by the phase noted; the route signatures are the contract.
"""

from __future__ import annotations

from fastapi import APIRouter, UploadFile

from acl.api.deps import ERROR_RESPONSES, Admin, Analyst, Viewer, not_implemented
from acl.contracts.admin import (
    Approval,
    ArtifactScanResult,
    BreakerState,
    BudgetTree,
    ConnectorStatus,
    FeedStatus,
    InsightCluster,
    KillSwitchRequest,
    McpServerInfo,
    McpToolApprovalRequest,
    McpToolInfo,
    ModelInfo,
    PublishSkillRequest,
)
from acl.contracts.common import ApprovalStatus
from acl.contracts.decide import ApprovalDecisionRequest

router = APIRouter(responses=ERROR_RESPONSES)

# ---------------------------------------------------------------- approvals (2B)


@router.get("/approvals", response_model=list[Approval], tags=["approvals"], operation_id="listApprovals")
async def list_approvals(p: Viewer, status: ApprovalStatus | None = ApprovalStatus.pending) -> list[Approval]:
    not_implemented("approvals")


@router.get("/approvals/{approval_id}", response_model=Approval, tags=["approvals"], operation_id="getApprovalAdmin")
async def get_approval(approval_id: str, p: Viewer) -> Approval:
    not_implemented("approvals")


@router.post(
    "/approvals/{approval_id}/decision", response_model=Approval, tags=["approvals"], operation_id="decideApproval"
)
async def decide_approval(approval_id: str, body: ApprovalDecisionRequest, p: Analyst) -> Approval:
    """Approve (optionally with time-boxed elevation) or deny. Audited."""
    not_implemented("approvals")


# ---------------------------------------------------------------- budgets (2D)


@router.get("/budgets", response_model=BudgetTree, tags=["budgets"], operation_id="getBudgets")
async def budgets(p: Viewer) -> BudgetTree:
    not_implemented("budgets")


@router.get("/budgets/breakers", response_model=list[BreakerState], tags=["budgets"], operation_id="listBreakers")
async def breakers(p: Viewer) -> list[BreakerState]:
    not_implemented("breakers")


@router.post(
    "/budgets/breakers/{breaker_id}/reset", response_model=BreakerState, tags=["budgets"], operation_id="resetBreaker"
)
async def reset_breaker(breaker_id: str, p: Admin) -> BreakerState:
    not_implemented("breakers")


# ---------------------------------------------------------------- models & connectors (1A / 3B)


@router.get("/connectors", response_model=list[ConnectorStatus], tags=["models"], operation_id="listConnectors")
async def connectors(p: Viewer) -> list[ConnectorStatus]:
    not_implemented("connectors")


@router.post(
    "/connectors/{connector_id}/kill-switch",
    response_model=ConnectorStatus,
    tags=["models"],
    operation_id="setKillSwitch",
)
async def kill_switch(connector_id: str, body: KillSwitchRequest, p: Admin) -> ConnectorStatus:
    not_implemented("kill switch")


@router.get("/models", response_model=list[ModelInfo], tags=["models"], operation_id="listModelsAdmin")
async def models(p: Viewer) -> list[ModelInfo]:
    not_implemented("models")


# ---------------------------------------------------------------- MCP (2A)


@router.get("/mcp/servers", response_model=list[McpServerInfo], tags=["mcp"], operation_id="listMcpServers")
async def mcp_servers(p: Viewer) -> list[McpServerInfo]:
    not_implemented("mcp")


@router.get("/mcp/tools", response_model=list[McpToolInfo], tags=["mcp"], operation_id="listMcpTools")
async def mcp_tools(p: Viewer, server: str | None = None) -> list[McpToolInfo]:
    not_implemented("mcp")


@router.post("/mcp/tools/{tool_id}/approve", response_model=McpToolInfo, tags=["mcp"], operation_id="approveMcpTool")
async def approve_tool(tool_id: str, body: McpToolApprovalRequest, p: Admin) -> McpToolInfo:
    """Re-pin a drifted/pending tool to its current hash."""
    not_implemented("mcp")


@router.post(
    "/mcp/tools/{tool_id}/quarantine", response_model=McpToolInfo, tags=["mcp"], operation_id="quarantineMcpTool"
)
async def quarantine_tool(tool_id: str, body: McpToolApprovalRequest, p: Analyst) -> McpToolInfo:
    not_implemented("mcp")


# ---------------------------------------------------------------- feed (1D)


@router.get("/feed", response_model=FeedStatus, tags=["feed"], operation_id="getFeedStatus")
async def feed_status(p: Viewer) -> FeedStatus:
    not_implemented("feed")


@router.post("/feed/sync", response_model=FeedStatus, tags=["feed"], operation_id="syncFeed")
async def feed_sync(p: Admin) -> FeedStatus:
    not_implemented("feed")


# ---------------------------------------------------------------- artifacts (4A)


@router.post("/artifacts/scan", response_model=ArtifactScanResult, tags=["artifacts"], operation_id="scanArtifact")
async def scan_artifact(file: UploadFile, p: Admin) -> ArtifactScanResult:
    not_implemented("artifact scan")


@router.get("/artifacts", response_model=list[ArtifactScanResult], tags=["artifacts"], operation_id="listArtifacts")
async def list_artifacts(p: Viewer) -> list[ArtifactScanResult]:
    not_implemented("artifacts")


# ---------------------------------------------------------------- insights (4B)


@router.get("/insights/clusters", response_model=list[InsightCluster], tags=["insights"], operation_id="listInsights")
async def insights(p: Viewer, group: str | None = None) -> list[InsightCluster]:
    not_implemented("insights")


@router.post(
    "/insights/clusters/{cluster_id}/publish",
    response_model=InsightCluster,
    tags=["insights"],
    operation_id="publishSkill",
)
async def publish(cluster_id: str, body: PublishSkillRequest, p: Admin) -> InsightCluster:
    not_implemented("insights publish")
