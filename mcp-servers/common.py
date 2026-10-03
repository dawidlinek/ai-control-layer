"""Shared bootstrap of the demo MCP servers (MCP Python SDK, Streamable HTTP on :8000/mcp).

These servers are deliberately small, deterministic and offline (no real network access): they exist so the
gateway's MCP governance can be demonstrated and tested. Each runs in its own container, reachable only from
the gateway (no published ports; see deploy/compose.mcp.yml).
"""

from __future__ import annotations

import os

import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

PORT = int(os.environ.get("PORT", "8000"))


def make_app(server: MCPServer) -> Starlette:
    @server.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "server": server.name})

    # The server is only reachable from the compose network (gateway); Host-header allow-listing adds nothing here.
    security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    return server.streamable_http_app(streamable_http_path="/mcp", transport_security=security, host="0.0.0.0")  # noqa: S104


def run(server: MCPServer) -> None:
    uvicorn.run(make_app(server), host="0.0.0.0", port=PORT, log_level="info")  # noqa: S104
