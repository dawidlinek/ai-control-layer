"""Admin: approvals (2B), budgets (2D), models/connectors (1A/3B), MCP (2A), feed (1D),
artifacts (4A), insights (4B).

Each section is owned by the phase noted; the route signatures are the contract.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request, UploadFile

from acl.api.deps import ERROR_RESPONSES, Admin, Analyst, Viewer, not_implemented
from acl.audit.queries import spend_by_connector
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
from acl.contracts.audit import EventType
from acl.contracts.common import ApprovalStatus, Severity
from acl.contracts.decide import ApprovalDecisionRequest
from acl.policy.models import Policy
from acl.routing.registry import RoutingTable

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


def _policy_and_table(request: Request) -> tuple[Policy, RoutingTable]:
    engine = request.app.state.engine
    if engine is None:
        raise HTTPException(503, detail="policy not loaded")
    return engine.policy, request.app.state.connectors.table_for(engine.policy, engine.policy_version)


async def _connector_status(
    request: Request, cid: str, policy: Policy, table: RoutingTable, spend: dict[str, float]
) -> ConnectorStatus:
    registry = request.app.state.connectors
    cfg = policy.connectors[cid]
    handle = table.connectors[cid]
    killed = registry.is_killed(cid)
    healthy: bool | None = None
    last_error = registry.last_error(cid)
    if handle.unavailable:
        healthy, last_error = False, last_error or handle.unavailable
    elif not killed and cfg.enabled:
        healthy = await registry.healthy(cid)
    if killed:
        info = registry.kill_info(cid)
        last_error = f"kill switch: {info.reason}" if info else last_error
    return ConnectorStatus(
        id=cid,
        type=cfg.type,
        tier=cfg.tier,
        enabled=cfg.enabled,
        kill_switch=killed,
        healthy=healthy,
        latency_ms_p50=registry.latency_p50(cid),
        last_error=last_error,
        spend_usd_day=round(spend.get(cid, 0.0), 6),
    )


async def _spend_day(request: Request) -> dict[str, float]:
    sessions = getattr(request.app.state, "db", None)
    if sessions is None:
        return {}
    try:
        return await spend_by_connector(sessions, datetime.now(UTC) - timedelta(days=1))
    except Exception:
        return {}


@router.get("/connectors", response_model=list[ConnectorStatus], tags=["models"], operation_id="listConnectors")
async def connectors(request: Request, p: Viewer) -> list[ConnectorStatus]:
    policy, table = _policy_and_table(request)
    spend = await _spend_day(request)
    return list(
        await asyncio.gather(*(_connector_status(request, cid, policy, table, spend) for cid in policy.connectors))
    )


@router.post(
    "/connectors/{connector_id}/kill-switch",
    response_model=ConnectorStatus,
    tags=["models"],
    operation_id="setKillSwitch",
)
async def kill_switch(request: Request, connector_id: str, body: KillSwitchRequest, p: Admin) -> ConnectorStatus:
    # In-memory, per connector; survives policy reloads. Routes to the degraded local target meanwhile.
    policy, table = _policy_and_table(request)
    if connector_id not in policy.connectors:
        raise HTTPException(404, detail="unknown connector")
    request.app.state.connectors.set_kill_switch(connector_id, body.engaged, body.reason, by=p.username or p.subject)
    audit = getattr(request.app.state, "audit", None)
    if audit is not None:
        await audit.record_event(
            EventType.system_alert,
            severity=Severity.high if body.engaged else Severity.info,
            detail={
                "event": "kill_switch",
                "connector": connector_id,
                "engaged": body.engaged,
                "reason": body.reason,
            },
            principal=p,
        )
    return await _connector_status(request, connector_id, policy, table, await _spend_day(request))


@router.get("/models", response_model=list[ModelInfo], tags=["models"], operation_id="listModelsAdmin")
async def models(request: Request, p: Viewer) -> list[ModelInfo]:
    policy, table = _policy_and_table(request)
    fixed_aliases: dict[str, list[str]] = {}
    for name, alias in policy.aliases.items():
        if alias.strategy == "fixed" and alias.target:
            fixed_aliases.setdefault(alias.target, []).append(name)
    out = []
    for m in policy.models:
        cfg = policy.connectors[m.connector]
        handle = table.models[m.id]
        artifact = "n/a" if m.artifact is None else "scanned_ok" if m.artifact.scan_id else "unscanned"
        out.append(
            ModelInfo(
                id=m.id,
                connector=m.connector,
                tier=cfg.tier,
                aliases=[*m.aliases, *fixed_aliases.get(m.id, [])],
                tags=dict(m.tags),
                data_classes=list(m.data_classes),
                pricing=m.pricing.model_dump(exclude_none=True),
                artifact_status=artifact,  # type: ignore[arg-type]
                enabled=m.enabled and cfg.enabled and not request.app.state.connectors.is_killed(m.connector),
                available=handle.unavailable is None and table.connectors[m.connector].unavailable is None,
            )
        )
    return out


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
