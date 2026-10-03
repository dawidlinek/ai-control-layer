"""Upstream MCP connections owned by the gateway (client side of the proxy).

Why not the `mcp` SDK client? Its `ClientSession` must be entered and exited in one task (anyio task groups),
which does not fit a long-lived, per-gateway-session upstream held across HTTP requests, and a transparent
proxy needs the raw JSON-RPC messages anyway (hashing, redaction, server-initiated requests). This module
speaks the small subset the proxy needs of MCP Streamable HTTP (2025-11-25) and stdio directly.

Security properties (tested):
  * the client's `Authorization` header is never forwarded: upstream requests are built from scratch here;
  * redirects are not followed; the upstream URL comes from policy only, never from a client;
  * the gateway declares NO client capabilities (no sampling, roots or elicitation); any server-initiated
    request seen in a response stream is answered with an error and recorded in `server_requests`;
  * response size is capped.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import os
import re
from collections.abc import Callable
from typing import Any

import httpx

from acl import __version__
from acl.mcp_proxy import jsonrpc
from acl.policy.models import McpServerConfig

MAX_RESPONSE_BYTES = 8_000_000
_RESOURCE_METADATA = re.compile(r'resource_metadata\s*=\s*"?([^",\s]+)"?', re.IGNORECASE)


class UpstreamError(Exception):
    """Transport/protocol failure.

    `kind`: unreachable | timeout | http | protocol | session_lost | auth_required | too_large.
    """

    def __init__(self, kind: str, message: str = "") -> None:
        super().__init__(f"{kind}: {message}" if message else kind)
        self.kind = kind
        self.message = message


class UpstreamRpcError(Exception):
    """The upstream answered a request with a JSON-RPC error."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.data = data


def initialize_params(protocol_version: str) -> dict[str, Any]:
    return {
        "protocolVersion": protocol_version,
        "capabilities": {},  # no sampling / roots / elicitation: the gateway never answers server requests
        "clientInfo": {"name": "acl-gateway", "version": __version__},
    }


class _Base:
    protocol_version: str | None = None

    def __init__(self) -> None:
        self.server_requests: list[str] = []  # methods of server-initiated requests we refused
        self.notifications: list[str] = []
        self.auth_metadata: str | None = None  # `resource_metadata` URL advertised on a 401 (validated by SEC-MCP-02)
        self._ids = itertools.count(1)

    async def handshake(self, protocol_version: str) -> dict[str, Any]:
        result = await self.request("initialize", initialize_params(protocol_version))
        self.protocol_version = str(result.get("protocolVersion") or protocol_version)
        await self.notify("notifications/initialized")
        return result

    async def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:  # pragma: no cover
        raise NotImplementedError

    async def aclose(self) -> None:  # pragma: no cover
        raise NotImplementedError

    @staticmethod
    def _rpc_result(resp: dict[str, Any]) -> dict[str, Any]:
        if "error" in resp:
            err = resp["error"] if isinstance(resp["error"], dict) else {}
            code = err.get("code") if isinstance(err.get("code"), int) else jsonrpc.INTERNAL_ERROR
            raise UpstreamRpcError(code, str(err.get("message") or "upstream error")[:500], err.get("data"))
        res = resp.get("result")
        if not isinstance(res, dict):
            raise UpstreamError("protocol", "result is not an object")
        return res


# ---------------------------------------------------------------------------------------------- streamable HTTP


class HttpUpstream(_Base):
    def __init__(self, url: str, client: httpx.AsyncClient, *, timeout_s: float = 60.0) -> None:
        super().__init__()
        self.url = url
        self._client = client
        self._timeout = httpx.Timeout(timeout_s, connect=5.0)
        self.session_id: str | None = None

    def _headers(self, method: str | None) -> dict[str, str]:
        # Built from scratch: nothing from the client request (Authorization, cookies, ...) is forwarded.
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        if self.protocol_version and method != "initialize":
            headers["MCP-Protocol-Version"] = self.protocol_version
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    async def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        rid = next(self._ids)
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            message["params"] = params
        resp = await self._send(message, want_id=rid)
        if resp is None:
            raise UpstreamError("protocol", "no response to request")
        return self._rpc_result(resp)

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        await self._send(message, want_id=None)

    async def _send(self, message: dict[str, Any], *, want_id: int | None) -> dict[str, Any] | None:
        method = message.get("method") if isinstance(message.get("method"), str) else None
        try:
            async with self._client.stream(
                "POST",
                self.url,
                content=json.dumps(message, ensure_ascii=False).encode("utf-8"),
                headers=self._headers(method),
                timeout=self._timeout,
            ) as resp:
                sid = resp.headers.get("mcp-session-id")
                if sid and self.session_id is None and method == "initialize":
                    self.session_id = sid
                status = resp.status_code
                if status == 202:
                    return None
                if status in (401, 403):
                    m = _RESOURCE_METADATA.search(resp.headers.get("www-authenticate", ""))
                    self.auth_metadata = m.group(1) if m else None
                    raise UpstreamError("auth_required", f"upstream answered HTTP {status}")
                if status == 404 and self.session_id and method != "initialize":
                    raise UpstreamError("session_lost", "upstream session no longer exists")
                if status >= 400:
                    raise UpstreamError("http", f"upstream answered HTTP {status}")
                ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                if ctype == "text/event-stream":
                    return await self._read_sse(resp, want_id)
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise UpstreamError("too_large", "upstream response exceeds the size cap")
                if not body:
                    return None
                try:
                    data = json.loads(body)
                except ValueError as exc:
                    raise UpstreamError("protocol", "upstream sent invalid JSON") from exc
                return await self._dispatch(data, want_id)
        except httpx.TimeoutException as exc:
            raise UpstreamError("timeout", "upstream did not answer in time") from exc
        except httpx.HTTPError as exc:
            raise UpstreamError("unreachable", type(exc).__name__) from exc

    async def _dispatch(self, data: Any, want_id: int | None) -> dict[str, Any] | None:
        messages = data if isinstance(data, list) else [data]
        found: dict[str, Any] | None = None
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            if jsonrpc.is_response(msg):
                if want_id is not None and msg.get("id") == want_id and found is None:
                    found = msg
            elif jsonrpc.is_request(msg):
                await self._refuse(msg)
            elif jsonrpc.is_notification(msg):
                self.notifications.append(str(msg.get("method")))
        return found

    async def _refuse(self, msg: dict[str, Any]) -> None:
        self.server_requests.append(str(msg.get("method")))
        reply = jsonrpc.error(msg["id"], jsonrpc.METHOD_NOT_FOUND, "the gateway client does not support this request")
        with contextlib.suppress(UpstreamError):
            await self._send(reply, want_id=None)

    async def _read_sse(self, resp: httpx.Response, want_id: int | None) -> dict[str, Any] | None:
        lines: list[str] = []
        total = 0
        async for line in resp.aiter_lines():
            total += len(line) + 1
            if total > MAX_RESPONSE_BYTES:
                raise UpstreamError("too_large", "upstream stream exceeds the size cap")
            if line == "":
                if lines:
                    found = await self._sse_event(lines, want_id)
                    lines = []
                    if found is not None:
                        return found
            elif line.startswith("data:"):
                lines.append(line[5:][1:] if line[5:6] == " " else line[5:])
        if lines:
            found = await self._sse_event(lines, want_id)
            if found is not None:
                return found
        if want_id is None:
            return None
        raise UpstreamError("protocol", "event stream ended without a response")

    async def _sse_event(self, lines: list[str], want_id: int | None) -> dict[str, Any] | None:
        try:
            data = json.loads("\n".join(lines))
        except ValueError:
            return None
        return await self._dispatch(data, want_id)

    async def aclose(self) -> None:
        if self.session_id:
            with contextlib.suppress(httpx.HTTPError):
                await self._client.delete(self.url, headers=self._headers("DELETE"), timeout=5.0)
            self.session_id = None


# ---------------------------------------------------------------------------------------------- stdio


class StdioUpstream(_Base):
    """Newline-delimited JSON-RPC over the stdin/stdout of a subprocess spawned from the policy `command`."""

    def __init__(self, command: list[str], *, timeout_s: float = 60.0) -> None:
        super().__init__()
        self.command = list(command)
        self._timeout = timeout_s
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "LANG", "HOME") if k in os.environ}
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *self.command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=env,
                limit=MAX_RESPONSE_BYTES,
            )
        except OSError as exc:
            raise UpstreamError("unreachable", f"cannot start server process ({type(exc).__name__})") from exc

    async def _write(self, message: dict[str, Any]) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.returncode is not None:
            raise UpstreamError("unreachable", "server process is not running")
        proc.stdin.write(json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n")
        await proc.stdin.drain()

    async def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        rid = next(self._ids)
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            message["params"] = params
        async with self._lock:
            try:
                await self._write(message)
                resp = await asyncio.wait_for(self._read_until(rid), self._timeout)
            except TimeoutError as exc:
                raise UpstreamError("timeout", "server did not answer in time") from exc
            except (BrokenPipeError, ConnectionResetError) as exc:
                raise UpstreamError("unreachable", "server process closed its pipe") from exc
        return self._rpc_result(resp)

    async def _read_until(self, want_id: int) -> dict[str, Any]:
        proc = self._proc
        assert proc is not None and proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                raise UpstreamError("unreachable", "server process exited")
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            if jsonrpc.is_response(msg) and msg.get("id") == want_id:
                return msg
            if jsonrpc.is_request(msg):
                self.server_requests.append(str(msg.get("method")))
                await self._write(
                    jsonrpc.error(
                        msg["id"], jsonrpc.METHOD_NOT_FOUND, "the gateway client does not support this request"
                    )
                )
            elif jsonrpc.is_notification(msg):
                self.notifications.append(str(msg.get("method")))

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        async with self._lock:
            await self._write(message)

    async def aclose(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        with contextlib.suppress(ProcessLookupError, OSError):
            if proc.stdin is not None:
                proc.stdin.close()
            try:
                await asyncio.wait_for(proc.wait(), 3.0)
            except TimeoutError:
                proc.kill()
                await proc.wait()


# ---------------------------------------------------------------------------------------------- factory

Upstream = HttpUpstream | StdioUpstream


class UpstreamFactory:
    """Opens an upstream connection for a policy server. Tests replace `client` (ASGI transports) or `connect`."""

    def __init__(self, client_factory: Callable[[], httpx.AsyncClient] | None = None, timeout_s: float = 60.0) -> None:
        self._client_factory = client_factory or self._default_client
        self._client: httpx.AsyncClient | None = None
        self.timeout_s = timeout_s

    @staticmethod
    def _default_client() -> httpx.AsyncClient:
        return httpx.AsyncClient(follow_redirects=False, trust_env=False, limits=httpx.Limits(max_connections=100))

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = self._client_factory()
        return self._client

    @client.setter
    def client(self, value: httpx.AsyncClient) -> None:
        self._client = value

    async def open(self, cfg: McpServerConfig) -> Upstream:
        if cfg.transport == "streamable_http":
            assert cfg.url is not None
            return HttpUpstream(cfg.url, self.client, timeout_s=self.timeout_s)
        assert cfg.command is not None
        up = StdioUpstream(cfg.command, timeout_s=self.timeout_s)
        await up.start()
        return up

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
