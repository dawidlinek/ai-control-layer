"""Installer for the MCP proxy (listed in `acl.main.INSTALLERS`).

Provides on the app:
    app.state.mcp_proxy   McpProxy   (sessions, upstream factory; tests swap `mcp_proxy.factory.client`)
    app.state.mcp_store   McpStore   (pinned tool manifests + bound servers; the admin routes use it)
Routes: `POST|DELETE|GET /mcp/{server_id}` (Streamable HTTP, hidden from the OpenAPI contract).
"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI, Request, Response

from acl.api.deps import PrincipalDep
from acl.mcp_proxy.service import McpProxy
from acl.mcp_proxy.store import McpStore
from acl.mcp_proxy.upstream import UpstreamFactory
from acl.settings import Settings

router = APIRouter(prefix="/mcp", tags=["mcp"], include_in_schema=False)


@router.post("/{server_id}")
async def mcp_post(server_id: str, request: Request, principal: PrincipalDep) -> Response:
    return await request.app.state.mcp_proxy.handle_post(request, server_id, principal)


@router.delete("/{server_id}")
async def mcp_delete(server_id: str, request: Request, principal: PrincipalDep) -> Response:
    return await request.app.state.mcp_proxy.handle_delete(request, server_id, principal)


@router.get("/{server_id}")
async def mcp_get(server_id: str, principal: PrincipalDep) -> Response:
    """No server-initiated stream: the gateway answers every request in the POST response."""
    return Response(status_code=405, headers={"Allow": "POST, DELETE"})


def install(app: FastAPI, settings: Settings) -> None:
    store = McpStore(lambda: app.state.db)
    app.state.mcp_store = store
    app.state.mcp_proxy = McpProxy(app, store, UpstreamFactory())
    app.include_router(router)

    async def stop(app: FastAPI) -> None:
        await app.state.mcp_proxy.aclose()

    app.state.on_shutdown.append(stop)
