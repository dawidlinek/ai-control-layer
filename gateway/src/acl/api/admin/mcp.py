"""Admin: mcp (owner: Phase 2A). Route signatures are the contract."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from acl.api.deps import ERROR_RESPONSES, Admin, Analyst, Viewer
from acl.contracts.admin import (
    McpServerInfo,
    McpToolApprovalRequest,
    McpToolInfo,
)
from acl.contracts.audit import EventType
from acl.contracts.common import Severity
from acl.contracts.inspection import Principal
from acl.mcp_proxy.db_models import McpToolRow
from acl.mcp_proxy.store import McpStore

router = APIRouter(responses=ERROR_RESPONSES)

# ---------------------------------------------------------------- MCP (2A)


def _store(request: Request) -> McpStore:
    store = getattr(request.app.state, "mcp_store", None)
    if store is None:
        raise HTTPException(503, detail="MCP proxy is not installed")
    return store


def _tool_info(request: Request, row: McpToolRow) -> McpToolInfo:
    engine = request.app.state.engine
    defn = engine.policy.tools.get(row.policy_tool_id) if engine is not None and row.policy_tool_id else None
    return McpToolInfo(
        id=row.tool_id,
        server=row.server_id,
        name=row.name,
        status=row.status,  # type: ignore[arg-type]
        pinned_hash=row.pinned_hash,
        current_hash=row.current_hash,
        labels=list(defn.labels) if defn else [],
        tier=defn.default_tier if defn else None,
        first_seen=row.first_seen,
        drift_detected_at=row.drift_detected_at,
        description_diff=row.description_diff,
    )


async def _row_or_404(store: McpStore, tool_id: str) -> McpToolRow:
    row = await store.get_by_tool_id(tool_id)
    if row is None:
        raise HTTPException(404, detail="MCP tool not found")
    return row


async def _decision_event(
    request: Request, principal: Principal, action: str, row: McpToolRow, reason: str, severity: Severity
) -> None:
    audit = getattr(request.app.state, "audit", None)
    if audit is None:
        return
    await audit.record_event(
        EventType.mcp_drift,
        severity=severity,
        detail={
            "event": action,
            "server": row.server_id,
            "tool": row.name,
            "tool_id": row.tool_id,
            "status": row.status,
            "pinned_hash": row.pinned_hash,
            "current_hash": row.current_hash,
            "reason": reason,
            "rule_ids": ["SEC-MCP-01"],
        },
        principal=principal,
    )


@router.get("/mcp/servers", response_model=list[McpServerInfo], tags=["mcp"], operation_id="listMcpServers")
async def mcp_servers(request: Request, p: Viewer) -> list[McpServerInfo]:
    store = _store(request)
    engine = request.app.state.engine
    if engine is None:
        raise HTTPException(503, detail="policy not loaded yet")
    states = await store.server_rows()
    counts: dict[str, int] = {}
    for row in await store.all_tools():
        counts[row.server_id] = counts.get(row.server_id, 0) + 1
    out: list[McpServerInfo] = []
    for sid, cfg in sorted(engine.policy.mcp_servers.items()):
        st = states.get(sid)
        if not cfg.allowed:
            status = "blocked"
        elif st is None:
            status = "unknown"
        else:
            status = st.status if st.status in ("ok", "unreachable", "blocked") else "unknown"
        out.append(
            McpServerInfo(
                id=sid,
                transport=cfg.transport,
                origin=cfg.origin or (st.bound_origin if st else None),
                allowed=cfg.allowed,
                status=status,  # type: ignore[arg-type]
                tools_count=counts.get(sid, 0),
                protocol_version=st.protocol_version if st else None,
                last_seen=st.last_seen if st else None,
            )
        )
    return out


@router.get("/mcp/tools", response_model=list[McpToolInfo], tags=["mcp"], operation_id="listMcpTools")
async def mcp_tools(request: Request, p: Viewer, server: str | None = None) -> list[McpToolInfo]:
    store = _store(request)
    return [_tool_info(request, r) for r in await store.all_tools(server)]


@router.post("/mcp/tools/{tool_id}/approve", response_model=McpToolInfo, tags=["mcp"], operation_id="approveMcpTool")
async def approve_tool(request: Request, tool_id: str, body: McpToolApprovalRequest, p: Admin) -> McpToolInfo:
    """Re-pin a drifted/pending tool to its current hash."""
    store = _store(request)
    row = await _row_or_404(store, tool_id)
    updated = await store.approve((row.server_id, row.name), p.username or p.subject, body.reason)
    if updated is None:
        raise HTTPException(404, detail="MCP tool not found")
    await _decision_event(request, p, "approved", updated, body.reason, Severity.medium)
    return _tool_info(request, updated)


@router.post(
    "/mcp/tools/{tool_id}/quarantine", response_model=McpToolInfo, tags=["mcp"], operation_id="quarantineMcpTool"
)
async def quarantine_tool(request: Request, tool_id: str, body: McpToolApprovalRequest, p: Analyst) -> McpToolInfo:
    store = _store(request)
    row = await _row_or_404(store, tool_id)
    updated = await store.quarantine((row.server_id, row.name), p.username or p.subject, body.reason)
    if updated is None:
        raise HTTPException(404, detail="MCP tool not found")
    await _decision_event(request, p, "quarantined", updated, body.reason, Severity.medium)
    return _tool_info(request, updated)
