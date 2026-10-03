"""In-process fake MCP servers for tests (Streamable HTTP subset), usable without sockets.

    fake = FakeMcpServer(tools=[tool("get_weather", "Get the weather.", {"city": {"type": "string"}})])
    proxy.factory.client = httpx.AsyncClient(transport=HostRouter({"mcp-weather": fake}))

The fake records every request (`fake.requests`: headers + decoded JSON body) so tests can assert what the
gateway forwarded (e.g. that no `Authorization` header ever reaches an upstream).
"""

from __future__ import annotations

import copy
import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

ToolHandler = Callable[[str, dict[str, Any]], dict[str, Any]]


def tool(name: str, description: str = "", properties: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": copy.deepcopy(properties or {})}
    if properties:
        schema["required"] = list(properties)
    return {"name": name, "description": description, "inputSchema": schema, **extra}


def text_result(text: str, *, is_error: bool = False, structured: dict[str, Any] | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": is_error}
    if structured is not None:
        res["structuredContent"] = structured
    return res


class FakeMcpServer:
    """ASGI app speaking just enough MCP 2025-11-25 Streamable HTTP for the proxy tests."""

    def __init__(
        self,
        tools: list[dict[str, Any]] | None = None,
        handler: ToolHandler | None = None,
        *,
        sse: bool = False,
        name: str = "fake",
        instructions: str | None = None,
        server_requests: list[dict[str, Any]] | None = None,
        status_override: int | None = None,
        www_authenticate: str | None = None,
        page_size: int | None = None,
        extra_handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] | None = None,
    ) -> None:
        self.tools = list(tools or [])
        self.handler = handler or (lambda n, a: text_result(f"called {n}"))
        self.sse = sse
        self.name = name
        self.instructions = instructions
        self.server_requests = server_requests or []  # sent inside the response stream before the answer (sse only)
        self.status_override = status_override
        self.www_authenticate = www_authenticate
        self.page_size = page_size
        self.extra_handlers = extra_handlers or {}
        self.requests: list[dict[str, Any]] = []
        self.replies_to_server_requests: list[dict[str, Any]] = []
        self.sessions: set[str] = set()
        self._n = 0

    # ------------------------------------------------------------------ helpers

    @property
    def calls(self) -> list[dict[str, Any]]:
        return [r["body"] for r in self.requests if r["body"].get("method") == "tools/call"]

    def methods(self) -> list[str]:
        return [r["body"].get("method", "<response>") for r in self.requests]

    # ------------------------------------------------------------------ ASGI

    async def __call__(
        self, scope: dict[str, Any], receive: Callable[..., Awaitable[Any]], send: Callable[..., Awaitable[None]]
    ) -> None:
        if scope["type"] != "http":
            return
        body = b""
        while True:
            event = await receive()
            body += event.get("body", b"")
            if not event.get("more_body"):
                break
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        if scope["method"] == "DELETE":
            self.requests.append({"headers": headers, "body": {"method": "DELETE"}})
            sid = headers.get("mcp-session-id")
            self.sessions.discard(sid or "")
            return await self._send(send, 200, b"", {})
        msg = json.loads(body or b"{}")
        self.requests.append({"headers": headers, "body": msg})
        if self.status_override:
            extra = {"www-authenticate": self.www_authenticate} if self.www_authenticate else {}
            return await self._send(send, self.status_override, b"nope", extra)
        if "method" not in msg:  # a response to a server-initiated request
            self.replies_to_server_requests.append(msg)
            return await self._send(send, 202, b"", {})
        if "id" not in msg:
            return await self._send(send, 202, b"", {})
        method, rid, params = msg["method"], msg["id"], msg.get("params") or {}
        extra_headers: dict[str, str] = {}
        if method == "initialize":
            self._n += 1
            sid = f"fake-session-{self._n}"
            self.sessions.add(sid)
            extra_headers["mcp-session-id"] = sid
            result: dict[str, Any] = {
                "protocolVersion": params.get("protocolVersion", "2025-11-25"),
                "capabilities": {"tools": {"listChanged": True}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": self.name, "version": "1.0"},
            }
            if self.instructions:
                result["instructions"] = self.instructions
        elif method == "tools/list":
            tools = self.tools
            nxt = None
            if self.page_size:
                start = int(params.get("cursor") or 0)
                tools = self.tools[start : start + self.page_size]
                nxt = str(start + self.page_size) if start + self.page_size < len(self.tools) else None
            result = {"tools": tools}
            if nxt:
                result["nextCursor"] = nxt
        elif method == "tools/call":
            result = self.handler(params.get("name", ""), params.get("arguments") or {})
        elif method == "ping":
            result = {}
        elif method in self.extra_handlers:
            result = self.extra_handlers[method](params)
        else:
            reply = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}
            return await self._send(send, 200, json.dumps(reply).encode(), {"content-type": "application/json"})
        reply: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "result": result}
        if "__error__" in result:  # a handler can make the fake answer with a JSON-RPC error
            reply = {"jsonrpc": "2.0", "id": rid, "error": result["__error__"]}
        if self.sse:
            events = [*self.server_requests, reply]
            payload = "".join(f"event: message\ndata: {json.dumps(e)}\n\n" for e in events).encode()
            return await self._send(send, 200, payload, {"content-type": "text/event-stream", **extra_headers})
        await self._send(send, 200, json.dumps(reply).encode(), {"content-type": "application/json", **extra_headers})

    @staticmethod
    async def _send(send: Callable[..., Awaitable[None]], status: int, body: bytes, headers: dict[str, str]) -> None:
        raw = [(k.encode(), v.encode()) for k, v in headers.items()]
        await send({"type": "http.response.start", "status": status, "headers": raw})
        await send({"type": "http.response.body", "body": body})


class HostRouter(httpx.AsyncBaseTransport):
    """Routes requests by hostname to in-process ASGI apps (policy URLs like http://mcp-files:8000/mcp)."""

    def __init__(self, apps: dict[str, Any]) -> None:
        self._transports = {host: httpx.ASGITransport(app=app) for host, app in apps.items()}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        transport = self._transports.get(request.url.host)
        if transport is None:
            raise httpx.ConnectError(f"no route to {request.url.host}")
        return await transport.handle_async_request(request)
