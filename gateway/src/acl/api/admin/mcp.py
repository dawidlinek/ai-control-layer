"""Admin: mcp (owner: Phase 2A). Route signatures are the contract."""

from __future__ import annotations

from fastapi import APIRouter

from acl.api.deps import ERROR_RESPONSES, Admin, Analyst, Viewer, not_implemented
from acl.contracts.admin import (
    McpServerInfo,
    McpToolApprovalRequest,
    McpToolInfo,
)

router = APIRouter(responses=ERROR_RESPONSES)

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
