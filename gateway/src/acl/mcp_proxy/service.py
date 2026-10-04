"""The MCP proxy: Streamable HTTP in front, policy-governed upstream connections behind.

Server side of the protocol is implemented directly (JSON-RPC over HTTP POST) instead of with the SDK's server
classes: a transparent, policy-enforcing proxy must see and rewrite every message (personalised `tools/list`,
redacted results, refusals with rule ids), which the SDK server abstractions (handlers bound to local tool
functions) do not offer. The client side of each upstream connection lives in `upstream.py`.

Every MCP message goes through the same engine as chat traffic (`guard.run_point` = `evaluate_point` with proxy
overrides):

    initialize   -> pre-flight (allowlist, grant, headers) -> upstream handshake -> point `mcp_initialize`
    tools/list   -> upstream list -> pin/scan (SEC-MCP-01 at `mcp_tools_list`) -> quarantine -> personalised list
    tools/call   -> re-check pins -> point `tool_call` (+ pinned `tool_input_schema` for SEC-TOOL-01)
                 -> forward -> point `tool_result` -> redact/withhold -> client
    resources/*, prompts/*   -> allowlisted+granted servers only; results inspected like tool results
    anything else (sampling, completion, subscriptions, ...) -> refused

Clients speak 2025-11-25 sessions (`Mcp-Session-Id`, issued by the gateway and bound to the principal); requests
without a session (2026-07-28 stateless clients) get an ephemeral upstream session per request.

Information-flow session (labels, Rule of Two, loop counters): the client's `X-Session-Id` when given (the id the
OpenCode plugin also sends for chat and `/v1/decide`), else ONE principal-wide MCP session (`DEFAULT_IFC_SESSION`)
shared by every MCP server and request of that principal. It is never keyed on the per-server `Mcp-Session-Id` or a
random id: a read on one server followed by a send on another must meet in one session (CP2 finding 5).
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from acl.approvals.service import approver_scope_for
from acl.contracts.audit import EventType
from acl.contracts.common import Action, ApprovalStatus, InspectionPoint, Severity
from acl.contracts.decision import Decision
from acl.contracts.inspection import (
    InspectionContext,
    McpPayload,
    McpToolDescriptor,
    Principal,
    ToolCallPayload,
    ToolResultPayload,
)
from acl.controls.mcp import rules
from acl.controls.mcp.canon import tool_hints
from acl.controls.mcp.catalog import catalog_for
from acl.controls.mcp.pinning import McpPinningParams
from acl.controls.mcp.protocol import McpProtocolParams
from acl.engine.actions import GatewayUnavailable
from acl.engine.text import apply_replacements
from acl.engine.transforms import non_shadow_verdicts, transform_findings, unaddressable_fields
from acl.mcp_proxy import jsonrpc
from acl.mcp_proxy.db_models import McpToolRow
from acl.mcp_proxy.guard import (
    ForceBlock,
    ResultRefused,
    Segments,
    build_generic_segments,
    build_segments,
    run_point,
)
from acl.mcp_proxy.store import VISIBLE, McpStore, ToolEvent
from acl.mcp_proxy.upstream import Upstream, UpstreamError, UpstreamFactory, UpstreamRpcError

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 4_000_000
SESSION_IDLE_S = 3600.0
MAX_SESSIONS = 5000
MAX_TOOL_PAGES = 20
MAX_TOOLS = 1000
MAX_WAIT_S = 120.0
_CLIENT_SESSION_MAX = 128
DEFAULT_IFC_SESSION = "mcp-default"  # namespaced by principal in `evaluate_point`
_TOOL_INDEX = re.compile(r"^tools\[(\d+)\]")


class Withheld(Exception):
    def __init__(self, rule_ids: list[str], reason: str, decision: Decision | None = None) -> None:
        super().__init__(reason)
        self.rule_ids = rule_ids
        self.reason = reason
        self.decision = decision


@dataclass
class GatewaySession:
    id: str
    subject: str
    server_id: str
    upstream: Upstream
    protocol_version: str
    created: float = field(default_factory=time.monotonic)
    last_used: float = field(default_factory=time.monotonic)
    ephemeral: bool = False


@dataclass
class ListResult:
    visible: list[dict[str, Any]]
    rows: dict[str, McpToolRow]
    decision: Decision
    ctx: InspectionContext
    blocked_all: bool = False


class McpProxy:
    def __init__(self, app: Any, store: McpStore, factory: UpstreamFactory) -> None:
        self.app = app
        self.store = store
        self.factory = factory
        self.sessions: dict[str, GatewaySession] = {}
        self._last_refresh: dict[str, float] = {}

    # ------------------------------------------------------------------ small helpers

    @property
    def engine(self) -> Any:
        engine = self.app.state.engine
        if engine is None:
            raise GatewayUnavailable("policy not loaded")
        return engine

    def _params(self, ctype: str, model: type[Any]) -> Any:
        engine = self.app.state.engine
        if engine is not None:
            for c in engine.policy.controls:
                if c.type == ctype and c.enabled:
                    try:
                        return model.model_validate(c.params)
                    except Exception:  # invalid params are rejected at policy load; defensive
                        break
        return model()

    def pin_params(self) -> McpPinningParams:
        return self._params("mcp_pinning", McpPinningParams)

    def protocol_params(self) -> McpProtocolParams:
        return self._params("mcp_protocol", McpProtocolParams)

    @staticmethod
    def _client_session(request: Request, sess: GatewaySession | None = None) -> str:
        """IFC session of a request: `X-Session-Id`, else the principal-wide MCP session (never per server)."""
        raw = request.headers.get("x-session-id")
        if raw and raw.strip():
            return raw.strip()[:_CLIENT_SESSION_MAX]
        return DEFAULT_IFC_SESSION

    def _reply(
        self, rid: Any, value: dict[str, Any], *, session_id: str | None = None, status: int = 200
    ) -> JSONResponse:
        headers = {"Mcp-Session-Id": session_id} if session_id else None
        return JSONResponse(jsonrpc.result(rid, value), status_code=status, headers=headers)

    def _fail(
        self, rid: Any, code: int, message: str, data: dict[str, Any] | None = None, *, status: int = 200
    ) -> JSONResponse:
        return JSONResponse(jsonrpc.error(rid, code, message, data), status_code=status)

    def _blocked(
        self, rid: Any, decision: Decision, *, status: int = 200, prefix: str = "blocked by policy"
    ) -> JSONResponse:
        rules_txt = ", ".join(decision.rule_ids) or "policy"
        data = {"rule_ids": list(decision.rule_ids), "decision_id": decision.decision_id, "trace_id": decision.trace_id}
        return self._fail(rid, jsonrpc.BLOCKED, f"{prefix} ({rules_txt}): {decision.reason}"[:400], data, status=status)

    @staticmethod
    def _origin(url: str | None) -> str | None:
        if not url:
            return None
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else None

    def _mcp_headers(self, request: Request) -> dict[str, str]:
        out = {}
        for key in ("mcp-method", "mcp-name"):
            if key in request.headers:
                out[key] = request.headers[key]
        return out

    # ------------------------------------------------------------------ access

    async def _access(self, principal: Principal, server_id: str, tool_id: str | None = None) -> dict[str, Any]:
        """Grants resolved by the proxy (no I/O inside controls): {'server': {...}, 'tool': {...}|None}."""
        access = getattr(self.app.state, "access", None)
        out: dict[str, Any] = {"server": {"allowed": True}, "tool": None}
        if access is None:
            if getattr(self.app.state, "allow_anonymous_dev", False):
                return out
            out["server"] = {"allowed": False, "rule_id": "SEC-MCP-02", "reason": "access control is not configured"}
            return out
        check_server = getattr(access, "check_mcp_server", None)
        if check_server is not None:
            c = await check_server(principal, server_id)
            out["server"] = {"allowed": c.allowed, "rule_id": c.rule_id, "reason": c.reason}
        if tool_id is not None:
            t = await access.check_tool(principal, tool_id)
            out["tool"] = {"allowed": t.allowed, "rule_id": t.rule_id, "reason": t.reason}
        return out

    # ------------------------------------------------------------------ entry points

    async def handle_post(self, request: Request, server_id: str, principal: Principal) -> Response:
        try:
            return await self._handle_post(request, server_id, principal)
        except GatewayUnavailable as exc:
            log.warning("MCP request refused, gateway unavailable: %s", exc)
            return self._fail(None, jsonrpc.UNAVAILABLE, "gateway cannot decide right now (failing closed)", status=503)
        except Exception:
            log.exception("unhandled error in MCP proxy (server %s)", server_id)
            return self._fail(None, jsonrpc.INTERNAL_ERROR, "internal gateway error", status=500)

    async def _handle_post(self, request: Request, server_id: str, principal: Principal) -> Response:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            return self._fail(None, jsonrpc.INVALID_REQUEST, "request body too large", status=413)
        try:
            msg = json.loads(raw)
        except ValueError:
            return self._fail(None, jsonrpc.PARSE_ERROR, "invalid JSON", status=400)
        if not isinstance(msg, dict):
            return self._fail(None, jsonrpc.INVALID_REQUEST, "JSON-RPC batches are not supported", status=400)
        rid = msg.get("id")
        version = request.headers.get("mcp-protocol-version")
        if version and version not in jsonrpc.SUPPORTED_VERSIONS:
            return self._fail(rid, jsonrpc.INVALID_REQUEST, "unsupported MCP-Protocol-Version", status=400)
        if jsonrpc.is_response(msg):
            return Response(status_code=202)  # the gateway never sends requests to clients: nothing to answer
        method = msg.get("method")
        if msg.get("jsonrpc") != "2.0" or not isinstance(method, str) or len(method) > 128:
            return self._fail(rid, jsonrpc.INVALID_REQUEST, "invalid JSON-RPC message", status=400)
        params = msg.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return self._fail(rid, jsonrpc.INVALID_PARAMS, "params must be an object", status=400)

        # 1. pre-flight: allowlist, grant, header/body agreement (cheap, deterministic, audited when it refuses)
        refusal = await self._preflight(request, server_id, principal, method, params, rid)
        if refusal is not None:
            return refusal
        if jsonrpc.is_notification(msg):
            return Response(status_code=202)  # initialized/cancelled/...: upstream sessions are managed by the gateway

        # 2. session
        if method == "initialize":
            return await self._initialize(request, server_id, principal, rid, params)
        sess = self._session_for(request, server_id, principal)
        ephemeral = False
        if sess is None:
            if request.headers.get("mcp-session-id"):
                return self._fail(rid, jsonrpc.INVALID_REQUEST, "unknown or expired session", status=404)
            sess, error = await self._open_ephemeral(request, server_id, principal, rid)
            if sess is None:
                return error  # type: ignore[return-value]
            ephemeral = True
        try:
            sess.last_used = time.monotonic()
            try:
                response = await self._dispatch(request, sess, principal, rid, method, params)
            finally:
                await self._audit_server_requests(sess.upstream, sess.server_id, principal, request, sess)
            await self._after_upstream(request, sess, principal, method)
            return response
        finally:
            if ephemeral:
                await sess.upstream.aclose()

    async def _after_upstream(self, request: Request, sess: GatewaySession, principal: Principal, method: str) -> None:
        """`notifications/tools/list_changed` seen in a response stream: re-pin right away (quarantine early)."""
        notifications, sess.upstream.notifications = list(sess.upstream.notifications), []
        if "notifications/tools/list_changed" in notifications and method != "tools/list":
            self._last_refresh.pop(sess.server_id, None)
            try:
                await self.list_and_pin(request, sess, principal, explicit=False)
            except (UpstreamError, UpstreamRpcError):
                log.warning("re-pin after list_changed failed for server %s", sess.server_id)

    async def handle_delete(self, request: Request, server_id: str, principal: Principal) -> Response:
        sess = self._session_for(request, server_id, principal)
        if sess is None:
            return Response(status_code=404)
        self.sessions.pop(sess.id, None)
        await sess.upstream.aclose()
        return Response(status_code=204)

    async def aclose(self) -> None:
        sessions, self.sessions = list(self.sessions.values()), {}
        for s in sessions:
            try:
                await s.upstream.aclose()
            except Exception:
                log.debug("closing MCP session failed", exc_info=True)
        await self.factory.aclose()

    # ------------------------------------------------------------------ sessions

    def _session_for(self, request: Request, server_id: str, principal: Principal) -> GatewaySession | None:
        sid = request.headers.get("mcp-session-id")
        sess = self.sessions.get(sid) if sid else None
        # A session id is only valid for the principal and server it was issued to (CP1 finding 2).
        if sess is None or sess.subject != principal.subject or sess.server_id != server_id:
            return None
        return sess

    async def _register(self, sess: GatewaySession) -> None:
        now = time.monotonic()
        for old in [s for s in self.sessions.values() if now - s.last_used > SESSION_IDLE_S]:
            self.sessions.pop(old.id, None)
            await old.upstream.aclose()
        while len(self.sessions) >= MAX_SESSIONS:
            oldest = min(self.sessions.values(), key=lambda s: s.last_used)
            self.sessions.pop(oldest.id, None)
            await oldest.upstream.aclose()
        self.sessions[sess.id] = sess

    # ------------------------------------------------------------------ pre-flight

    async def _preflight(
        self, request: Request, server_id: str, principal: Principal, method: str, params: dict[str, Any], rid: Any
    ) -> Response | None:
        policy = self.engine.policy
        cfg = policy.mcp_servers.get(server_id)
        access = await self._access(principal, server_id)
        violations = rules.check_headers(method, params, self._mcp_headers(request))
        rule = "SEC-MCP-02"
        status = 400
        if method in self.protocol_params().deny_methods or method.startswith("sampling/"):
            violations.append(rules.Violation("MCP_SAMPLING_DENIED", f"'{method}' is denied by policy"))
        if cfg is None or not cfg.allowed:
            violations.append(rules.Violation("MCP_SERVER_NOT_ALLOWED", "MCP server is not on the allowlist"))
            status = 403
        elif access["server"].get("allowed") is False:
            violations.append(rules.Violation("MCP_SERVER_NOT_GRANTED", str(access["server"].get("reason"))))
            status = 403
        if not violations:
            return None
        payload = McpPayload(
            server=server_id[:128],
            method=method,
            params=self._audit_params(method, params),
            headers=self._mcp_headers(request),
            protocol_version=request.headers.get("mcp-protocol-version"),
        )
        reason = "; ".join(dict.fromkeys(v.reason for v in violations))
        ctx, decision = await run_point(
            self.app,
            principal,
            point=InspectionPoint.mcp_initialize,
            payload=payload,
            client_session=self._client_session(request, None),
            attributes={"mcp_access": access},
            force_block=ForceBlock(rule, reason, "SEC-MCP-02"),
        )
        await self._incident_for_refusal(principal, ctx, decision, server_id, violations)
        return self._blocked(rid, decision, status=status, prefix="refused")

    @staticmethod
    def _audit_params(method: str, params: dict[str, Any]) -> dict[str, Any]:
        """The few params safe and useful to put into an audit payload (never tool arguments)."""
        out: dict[str, Any] = {}
        for key in ("name", "uri"):
            v = params.get(key)
            if isinstance(v, str):
                out[key] = v[:256]
        return out

    async def _incident_for_refusal(
        self,
        principal: Principal,
        ctx: InspectionContext,
        decision: Decision,
        server_id: str,
        violations: list[rules.Violation],
    ) -> None:
        audit = getattr(self.app.state, "audit", None)
        if audit is None:
            return
        codes = sorted({v.code for v in violations})
        severe = {"MCP_HEADER_MISMATCH", "MCP_SAMPLING_DENIED", "MCP_OAUTH_URL", "MCP_ORIGIN_MISMATCH"} & set(codes)
        if not severe:
            return
        await audit.record_event(
            EventType.incident,
            severity=Severity.high,
            detail={
                "category": "mcp_protocol_violation",
                "title": f"MCP protocol violation on server '{server_id}': {', '.join(codes)}",
                "rule_ids": list(decision.rule_ids),
                "server": server_id,
                "violations": codes,
            },
            principal=principal,
            trace_id=ctx.trace_id,
            session_id=ctx.session_id,
        )

    async def _audit_server_requests(
        self, upstream: Upstream, server_id: str, principal: Principal, request: Request, sess: GatewaySession | None
    ) -> None:
        """Server-initiated requests (sampling, elicitation, ...) were refused by the upstream layer: audit them."""
        methods, upstream.server_requests = list(upstream.server_requests), []
        for m in methods:
            payload = McpPayload(
                server=server_id, method=m[:128], params={}, protocol_version=sess.protocol_version if sess else None
            )
            violation = rules.Violation("MCP_SAMPLING_DENIED", f"server-initiated '{m[:64]}' is denied by policy")
            ctx, decision = await run_point(
                self.app,
                principal,
                point=InspectionPoint.mcp_initialize,
                payload=payload,
                client_session=self._client_session(request, sess),
                force_block=ForceBlock("SEC-MCP-02", violation.reason, "SEC-MCP-02"),
            )
            await self._incident_for_refusal(principal, ctx, decision, server_id, [violation])

    # ------------------------------------------------------------------ initialize

    async def _connect(
        self, request: Request, server_id: str, principal: Principal, rid: Any, params: dict[str, Any]
    ) -> tuple[GatewaySession | None, Response | None, dict[str, Any]]:
        """Open + handshake an upstream and evaluate it at `mcp_initialize`. (session, error response, result)."""
        policy = self.engine.policy
        cfg = policy.mcp_servers[server_id]
        asked = (
            params.get("protocolVersion") if isinstance(params.get("protocolVersion"), str) else jsonrpc.LATEST_STATEFUL
        )
        wanted = min(asked, jsonrpc.LATEST_STATEFUL) if asked in jsonrpc.SUPPORTED_VERSIONS else jsonrpc.LATEST_STATEFUL
        access = await self._access(principal, server_id)
        client_session = self._client_session(request, None)
        upstream: Upstream | None = None
        try:
            upstream = await self.factory.open(cfg)
            init = await upstream.handshake(wanted)
        except (UpstreamError, UpstreamRpcError) as exc:
            kind = getattr(exc, "kind", "rpc_error")
            if upstream is not None:
                await upstream.aclose()
            await self.store.note_server(server_id, transport=cfg.transport, status="unreachable", error=kind)
            meta = getattr(upstream, "auth_metadata", None)
            if meta:  # OAuth metadata advertised by the server: validate it (CVE-2025-6514 pattern)
                payload = McpPayload(
                    server=server_id, method="initialize", params={"resource_metadata": meta}, protocol_version=wanted
                )
                await run_point(
                    self.app,
                    principal,
                    point=InspectionPoint.mcp_initialize,
                    payload=payload,
                    client_session=client_session,
                    attributes={"mcp_access": access},
                )
            return (
                None,
                self._fail(
                    rid, jsonrpc.UPSTREAM_ERROR, f"MCP server '{server_id}' is unavailable ({kind})", status=502
                ),
                {},
            )
        await self._audit_server_requests(upstream, server_id, principal, request, None)
        info = init.get("serverInfo") if isinstance(init.get("serverInfo"), dict) else {}
        caps = init.get("capabilities") if isinstance(init.get("capabilities"), dict) else {}
        instructions = init.get("instructions") if isinstance(init.get("instructions"), str) else None
        negotiated = str(init.get("protocolVersion") or wanted)
        ev_params: dict[str, Any] = {
            "upstream_url": cfg.url or "stdio",
            "observed_origin": self._origin(cfg.url),
            "capabilities": sorted(caps),
            "server_info": {k: info[k] for k in ("name", "title", "description") if isinstance(info.get(k), str)},
        }
        if instructions:
            ev_params["instructions"] = instructions
        payload = McpPayload(server=server_id, method="initialize", params=ev_params, protocol_version=negotiated)
        _, decision = await run_point(
            self.app,
            principal,
            point=InspectionPoint.mcp_initialize,
            payload=payload,
            client_session=client_session,
            attributes={"mcp_access": access},
        )
        if decision.action in (Action.block, Action.require_approval):
            await upstream.aclose()
            await self.store.note_server(
                server_id, transport=cfg.transport, status="blocked", error="blocked at initialize"
            )
            return None, self._blocked(rid, decision, status=403, prefix="refused"), {}
        await self.store.note_server(
            server_id,
            transport=cfg.transport,
            status="ok",
            url=cfg.url,
            origin=self._origin(cfg.url),
            protocol_version=negotiated,
            capabilities=caps,
            server_info={k: info[k] for k in ("name", "title", "version") if isinstance(info.get(k), str)},
        )
        sess = GatewaySession(secrets.token_urlsafe(24), principal.subject, server_id, upstream, negotiated)
        keep_instructions = instructions if instructions and not decision.applied else None
        result: dict[str, Any] = {
            "protocolVersion": negotiated,
            "capabilities": {
                name: (
                    {"listChanged": False}
                    if name in ("tools", "prompts")
                    else {"subscribe": False, "listChanged": False}
                )
                for name in ("tools", "resources", "prompts")
                if name in caps
            },
            "serverInfo": {
                "name": str(info.get("name") or server_id)[:128],
                "version": str(info.get("version") or "")[:64],
            },
        }
        if keep_instructions:
            result["instructions"] = keep_instructions
        return sess, None, result

    async def _initialize(
        self, request: Request, server_id: str, principal: Principal, rid: Any, params: dict[str, Any]
    ) -> Response:
        sess, error, result = await self._connect(request, server_id, principal, rid, params)
        if sess is None:
            return error  # type: ignore[return-value]
        await self._register(sess)
        return self._reply(rid, result, session_id=sess.id)

    async def _open_ephemeral(
        self, request: Request, server_id: str, principal: Principal, rid: Any
    ) -> tuple[GatewaySession | None, Response | None]:
        version = request.headers.get("mcp-protocol-version") or jsonrpc.LATEST_STATEFUL
        sess, error, _ = await self._connect(request, server_id, principal, rid, {"protocolVersion": version})
        if sess is None:
            return None, error
        sess.ephemeral = True
        return sess, None

    # ------------------------------------------------------------------ dispatch

    async def _dispatch(
        self,
        request: Request,
        sess: GatewaySession,
        principal: Principal,
        rid: Any,
        method: str,
        params: dict[str, Any],
    ) -> Response:
        try:
            if method == "ping":
                return self._reply(rid, {})
            if method == "logging/setLevel":
                return self._reply(rid, {})
            if method == "tools/list":
                return await self._tools_list(request, sess, principal, rid)
            if method == "tools/call":
                return await self._tools_call(request, sess, principal, rid, params)
            if method in ("resources/list", "resources/templates/list", "prompts/list"):
                return await self._passthrough(request, sess, principal, rid, method, self._cursor(params))
            if method == "resources/read" and isinstance(params.get("uri"), str):
                return await self._passthrough(request, sess, principal, rid, method, {"uri": params["uri"]})
            if method == "prompts/get" and isinstance(params.get("name"), str):
                args = params.get("arguments")
                clean = {"name": params["name"]}
                if isinstance(args, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in args.items()):
                    clean["arguments"] = args  # type: ignore[assignment]
                return await self._passthrough(request, sess, principal, rid, method, clean)
        except UpstreamRpcError as exc:
            return await self._rpc_error(request, sess, principal, rid, method, exc)
        except UpstreamError as exc:
            if exc.kind == "session_lost":
                self.sessions.pop(sess.id, None)
            return self._fail(
                rid, jsonrpc.UPSTREAM_ERROR, f"MCP server '{sess.server_id}' failed ({exc.kind})", status=502
            )
        return self._fail(rid, jsonrpc.METHOD_NOT_FOUND, f"method '{method[:64]}' is not supported by the gateway")

    @staticmethod
    def _cursor(params: dict[str, Any]) -> dict[str, Any]:
        return {"cursor": params["cursor"]} if isinstance(params.get("cursor"), str) else {}

    async def _rpc_error(
        self, request: Request, sess: GatewaySession, principal: Principal, rid: Any, method: str, exc: UpstreamRpcError
    ) -> Response:
        """Upstream errors are model-readable text too: pass them through the result inspection."""
        if method != "tools/call":
            return self._fail(rid, jsonrpc.UPSTREAM_ERROR, f"MCP server returned error {exc.code}")
        seg = build_segments({"content": [{"type": "text", "text": exc.message}], "isError": True}, max_bytes=20_000)
        try:
            out = await self._inspect_result(
                principal,
                self._client_session(request, sess),
                f"{sess.server_id}:error",
                sess.server_id,
                rid,
                seg,
                True,
            )
        except Withheld as w:
            return self._fail(rid, jsonrpc.RESULT_WITHHELD, f"error text withheld ({', '.join(w.rule_ids)})")
        text = out["content"][0].get("text", "") if out.get("content") else ""
        return self._fail(rid, jsonrpc.UPSTREAM_ERROR, text or f"MCP server returned error {exc.code}")

    # ------------------------------------------------------------------ tools/list

    async def _fetch_tools(self, sess: GatewaySession) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(MAX_TOOL_PAGES):
            res = await sess.upstream.request("tools/list", {"cursor": cursor} if cursor else None)
            page = res.get("tools")
            if not isinstance(page, list):
                raise UpstreamError("protocol", "tools/list result has no tools array")
            tools.extend(t for t in page if isinstance(t, dict))
            cursor = res.get("nextCursor") if isinstance(res.get("nextCursor"), str) else None
            if not cursor or len(tools) > MAX_TOOLS:
                break
        return tools[:MAX_TOOLS]

    @staticmethod
    def _descriptor(raw: dict[str, Any]) -> McpToolDescriptor:
        ann = raw.get("annotations")
        return McpToolDescriptor(
            name=raw["name"],
            description=raw.get("description") if isinstance(raw.get("description"), str) else None,
            input_schema=raw.get("inputSchema") if isinstance(raw.get("inputSchema"), dict) else {},
            annotations=tool_hints(ann) if isinstance(ann, dict) else None,
        )

    async def list_and_pin(
        self,
        request: Request,
        sess: GatewaySession,
        principal: Principal,
        *,
        explicit: bool,
    ) -> ListResult:
        """Fetch the upstream list, pin/scan it through the engine and return what this principal may see."""
        server = sess.server_id
        raw_all = await self._fetch_tools(sess)
        tools: list[dict[str, Any]] = []
        seen: set[str] = set()
        duplicates: list[str] = []
        for raw in raw_all:
            name = raw.get("name")
            if not isinstance(name, str) or not name or len(name) > 256:
                continue
            if name in seen:
                if name not in duplicates:
                    duplicates.append(name)
                continue
            seen.add(name)
            tools.append(raw)
        catalog = catalog_for(self.engine.policy)
        async with self.store.lock(server):
            await self.store.upgrade_legacy_pins(server, tools)  # v1 pins -> v2 (annotations) without drift
            rows = await self.store.tools_for(server)
            pins = {n: {"pinned_hash": r.pinned_hash, "status": r.status} for n, r in rows.items()}
            payload = McpPayload(
                server=server,
                method="tools/list",
                params={},
                protocol_version=sess.protocol_version,
                tools=[self._descriptor(t) for t in tools],
            )
            ctx, decision = await run_point(
                self.app,
                principal,
                point=InspectionPoint.mcp_tools_list,
                payload=payload,
                client_session=self._client_session(request, sess),
                attributes={
                    "mcp_pins": pins,
                    "mcp_other_tools": await self.store.other_tool_names(server),
                    "mcp_duplicate_names": duplicates,
                    "mcp_access": await self._access(principal, server),
                },
                record_when=(lambda d: True) if explicit else (lambda d: d.action != Action.allow),
            )
            names = [t["name"] for t in tools]
            enforce = decision.would_action is None and decision.action in (Action.block, Action.require_approval)
            flags = {n: list(f) for n, f in (ctx.attributes.get("mcp_flags") or {}).items() if n in seen}
            self._attribute_other_blocks(decision, names, flags)
            blocked_all = enforce and not flags
            if blocked_all:
                self._last_refresh[server] = time.monotonic()
                return ListResult([], rows, decision, ctx, blocked_all=True)
            outcome = await self.store.apply_listing(server, tools, flags, enforce=enforce, catalog=catalog)
        self._last_refresh[server] = time.monotonic()
        await self._audit_events(principal, ctx, outcome.events)
        visible: list[dict[str, Any]] = []
        for raw in tools:
            row = outcome.rows.get(raw["name"])
            if row is None or row.status not in VISIBLE or row.policy_tool_id is None:
                continue  # quarantined / pending approval / unknown tools are hidden by default
            access = await self._access(principal, server, row.policy_tool_id)
            if access["tool"] and access["tool"].get("allowed") is False:
                continue  # personalised list: only what this principal may call
            visible.append(self._client_tool(raw))
        return ListResult(visible, outcome.rows, decision, ctx)

    def _attribute_other_blocks(
        self, decision: Decision, names: list[str], flags: dict[str, list[dict[str, str]]]
    ) -> None:
        """Findings of other enforced blocking controls (signature feed, normaliser...) on `tools[i]` flag that tool."""
        if decision.would_action is not None:
            return
        for v in non_shadow_verdicts(self.engine, decision):
            if v.action not in (Action.block, Action.require_approval) or v.control_type == "mcp_pinning":
                continue
            for f in v.findings:
                m = _TOOL_INDEX.match(f.field or "")
                if m and int(m.group(1)) < len(names):
                    entry = {"kind": "poisoned", "detail": f"control:{v.control_id}", "rule": v.control_id}
                    bucket = flags.setdefault(names[int(m.group(1))], [])
                    if entry not in bucket:
                        bucket.append(entry)

    @staticmethod
    def _client_tool(raw: dict[str, Any]) -> dict[str, Any]:
        """Only the fields covered by the pin (name, description, inputSchema, boolean hints) leave the gateway."""
        out: dict[str, Any] = {"name": raw["name"], "inputSchema": raw.get("inputSchema") or {"type": "object"}}
        if isinstance(raw.get("description"), str):
            out["description"] = raw["description"]
        if hints := tool_hints(raw.get("annotations")):
            out["annotations"] = hints
        return out

    async def _tools_list(self, request: Request, sess: GatewaySession, principal: Principal, rid: Any) -> Response:
        result = await self.list_and_pin(request, sess, principal, explicit=True)
        return self._reply(rid, {"tools": result.visible})

    async def _audit_events(self, principal: Principal, ctx: InspectionContext, events: list[ToolEvent]) -> None:
        audit = getattr(self.app.state, "audit", None)
        if audit is None:
            return
        for ev in events:
            if ev.kind in ("pinned", "released"):
                continue
            category, title, sev = {
                "drift": ("mcp_rug_pull", f"MCP tool '{ev.tool_id}' changed after pinning (rug pull)", Severity.high),
                "quarantined": (
                    "mcp_tool_poisoning",
                    f"MCP tool '{ev.tool_id}' quarantined: suspicious definition",
                    Severity.high,
                ),
                "collision": (
                    "mcp_name_collision",
                    f"MCP tool '{ev.tool_id}' shadows an existing tool name",
                    Severity.medium,
                ),
            }[ev.kind]
            detail = {
                "server": ev.server,
                "tool": ev.name,
                "tool_id": ev.tool_id,
                "status": ev.status,
                "reasons": ev.reasons,
                "pinned_hash": ev.old_hash,
                "current_hash": ev.new_hash,
                "description_diff": ev.diff,
                "pinned_at": ev.pinned_at.isoformat() if ev.pinned_at else None,
                "changed_at": ev.changed_at.isoformat() if ev.changed_at else None,
                "rule_ids": ["SEC-MCP-01"],
            }
            drift_event = await audit.record_event(
                EventType.mcp_drift,
                severity=sev,
                detail=detail,
                principal=principal,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
            )
            await audit.record_event(
                EventType.incident,
                severity=sev,
                detail={**detail, "category": category, "title": title, "related_event_ids": [drift_event.event_id]},
                principal=principal,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
            )

    # ------------------------------------------------------------------ tools/call

    async def _tools_call(
        self, request: Request, sess: GatewaySession, principal: Principal, rid: Any, params: dict[str, Any]
    ) -> Response:
        name = params.get("name")
        args = params.get("arguments")
        if args is None:
            args = {}
        if not isinstance(name, str) or not name or not isinstance(args, dict):
            return self._fail(rid, jsonrpc.INVALID_PARAMS, "tools/call needs a tool name and object arguments")
        server = sess.server_id
        client_session = self._client_session(request, sess)

        # Re-check the pin before a call (rate-limited): a change between two tools/list calls must not slip through.
        interval = self.pin_params().recheck_interval_s
        if time.monotonic() - self._last_refresh.get(server, -1e9) >= interval:
            await self.list_and_pin(request, sess, principal, explicit=False)
        row = await self.store.get_tool(server, name)
        if row is None:  # never listed (stateless client): list + pin now
            await self.list_and_pin(request, sess, principal, explicit=False)
            row = await self.store.get_tool(server, name)

        known = row is not None and row.policy_tool_id is not None
        tool_id = row.policy_tool_id if known else f"{server}:{name}"  # type: ignore[union-attr]
        status = row.status if row is not None else "unknown"
        schema = None
        if row is not None:
            schema = row.current_schema if row.status == "drifted" else row.pinned_schema
        access = await self._access(principal, server, tool_id if known else None)
        attributes: dict[str, Any] = {
            "mcp_access": access,
            "mcp_tool_status": status,
            "mcp_upstream_tool": name,
            "mcp_server": server,
        }
        if schema is not None:
            attributes["tool_input_schema"] = schema  # pinned argument schema for SEC-TOOL-01 (unknown fields rejected)
        if q := request.query_params.get("approval_id"):
            attributes["approval_id"] = q[:128]  # a hint only; the approvals service verifies it

        force: ForceBlock | None = None
        if not known:
            force = ForceBlock("SEC-MCP-02", "tool is not declared in policy for this MCP server", "SEC-MCP-02")
        elif status in ("quarantined", "pending_approval"):
            force = ForceBlock("SEC-MCP-01", f"tool is {status} until an admin re-approves it", "SEC-MCP-01")
        elif access["tool"] and access["tool"].get("allowed") is False:
            force = ForceBlock(
                access["tool"].get("rule_id") or "SEC-TOOL-01", str(access["tool"].get("reason")), "SEC-TOOL-01"
            )
        payload = ToolCallPayload(tool=tool_id, server=server, tool_call_id=str(rid), arguments=args)  # type: ignore[arg-type]
        ctx, decision = await run_point(
            self.app,
            principal,
            point=InspectionPoint.tool_call,
            payload=payload,
            client_session=client_session,
            attributes=attributes,
            force_block=force,
        )
        if decision.action == Action.block:
            return self._blocked(rid, decision)
        if decision.action == Action.require_approval:
            waited = await self._approval(request, principal, ctx, decision, rid)
            if isinstance(waited, Response):
                return waited
            # Approved while waiting: re-evaluate the same call so the approval is redeemed through the one atomic
            # path (`ApprovalService.redeem`, consumed on first use) and the call that runs gets its own decision
            # record. If it cannot be redeemed (spent concurrently, rules changed) the call stays held (CP2 finding 7).
            ctx, decision = await run_point(
                self.app,
                principal,
                point=InspectionPoint.tool_call,
                payload=payload,
                client_session=client_session,
                attributes=attributes,
                trace_id=ctx.trace_id,
            )
            if decision.action == Action.block:
                return self._blocked(rid, decision)
            if decision.action == Action.require_approval:
                return self._fail(
                    rid,
                    jsonrpc.APPROVAL_REQUIRED,
                    "approval required (the approval was already used or no longer covers this call)",
                    {
                        "approval_id": waited,
                        "status": "consumed",
                        "rule_ids": list(decision.rule_ids),
                        "decision_id": decision.decision_id,
                    },
                )

        out_args = self._outbound_args(ctx, decision, payload)
        if out_args is None:
            return self._fail(
                rid,
                jsonrpc.BLOCKED,
                "blocked by policy (ENG-REDACT-01): a sensitive span could not be redacted safely",
                {"rule_ids": ["ENG-REDACT-01"], "decision_id": decision.decision_id, "trace_id": decision.trace_id},
            )
        try:
            result = await sess.upstream.request("tools/call", {"name": name, "arguments": out_args})
        except UpstreamRpcError as exc:
            return await self._rpc_error(request, sess, principal, rid, "tools/call", exc)
        pp = self.protocol_params()
        try:
            seg = build_segments(result, max_bytes=pp.max_result_bytes)
            cleaned = await self._inspect_result(
                principal, client_session, tool_id, server, rid, seg, bool(result.get("isError")), pp.canaries
            )
        except ResultRefused as exc:
            return self._fail(rid, jsonrpc.RESULT_WITHHELD, f"tool result withheld ({exc.code}): {exc.reason}")
        except Withheld as w:
            data = {"rule_ids": w.rule_ids, "decision_id": w.decision.decision_id if w.decision else None}
            return self._fail(
                rid, jsonrpc.RESULT_WITHHELD, f"tool result withheld by policy ({', '.join(w.rule_ids)})", data
            )
        return self._reply(rid, cleaned)

    def _outbound_args(
        self, ctx: InspectionContext, decision: Decision, payload: ToolCallPayload
    ) -> dict[str, Any] | None:
        """Arguments to forward: the normalised payload with replacements applied; None = cannot be made safe."""
        if decision.would_action is not None:
            return dict(payload.arguments)
        base = ctx.attributes.get("payload")
        base = base if isinstance(base, ToolCallPayload) else payload
        findings = transform_findings(self.engine, decision)
        if not findings:
            return dict(base.arguments)
        if (unsafe := unaddressable_fields(base)) and any(f.field in unsafe for f in findings):
            return None
        out, skipped = apply_replacements(base, findings)
        if skipped and self._uncovered(findings, skipped):
            return None
        assert isinstance(out, ToolCallPayload)
        return dict(out.arguments)

    @staticmethod
    def _uncovered(findings: list[Any], skipped: list[Any]) -> bool:
        applied = [f for f in findings if f not in skipped]
        return any(
            not any(a.field == s.field and a.start <= s.start and a.end >= s.end for a in applied) for s in skipped
        )

    async def _approval(
        self, request: Request, principal: Principal, ctx: InspectionContext, decision: Decision, rid: Any
    ) -> Response | str:
        """require_approval: create the approval, answer with its id; optionally wait (`?wait=<seconds>`).

        Returns the error response to send, or the approval id when it was approved while waiting (the caller then
        redeems it by re-evaluating the call; approval here never lets a call through by itself)."""
        approvals = getattr(self.app.state, "approvals", None)
        if approvals is None:
            return self._fail(
                rid,
                jsonrpc.APPROVAL_REQUIRED,
                "approval required but no approval service is available",
                {"rule_ids": decision.rule_ids},
            )
        from acl.audit.builder import redacted_text

        preview = redacted_text(ctx, decision.verdicts)[:2000]
        # single source of truth with /v1/decide: `user` only when every enforced hold is SEC-TOOL-01's own (a Rule of
        # Two co-hold on a confirm-tier tool is admin scope even though SEC-TOOL-01 wins `decided_by`; CP2 finding 1)
        scope = approver_scope_for(self.engine, decision)
        ref = await approvals.create(ctx, decision, approver_scope=scope, preview=preview)
        wait = 0.0
        with contextlib.suppress(ValueError):
            wait = min(MAX_WAIT_S, max(0.0, float(request.query_params.get("wait", "0"))))
        status = ref.status
        if wait > 0:
            status = await approvals.wait(ref.approval_id, wait)
        if status == ApprovalStatus.approved:
            return ref.approval_id
        data = {
            "approval_id": ref.approval_id,
            "status": str(getattr(status, "value", status)),
            "expires_at": ref.expires_at.isoformat() if ref.expires_at else None,
            "rule_ids": list(decision.rule_ids),
            "decision_id": decision.decision_id,
        }
        msg = (
            "approval required" if status == ApprovalStatus.pending else f"approval {getattr(status, 'value', status)}"
        )
        return self._fail(rid, jsonrpc.APPROVAL_REQUIRED, msg, data)

    # ------------------------------------------------------------------ results

    async def _inspect_result(
        self,
        principal: Principal,
        client_session: str,
        tool_id: str,
        server: str,
        rid: Any,
        seg: Segments,
        is_error: bool,
        canaries: list[str] | None = None,
    ) -> dict[str, Any]:
        canary_hits = seg.redact_canaries(canaries or [])
        content = seg.joined()
        payload = ToolResultPayload(
            tool=tool_id, server=server, tool_call_id=str(rid), content=content, is_error=is_error
        )
        ctx, decision = await run_point(
            self.app, principal, point=InspectionPoint.tool_result, payload=payload, client_session=client_session
        )
        if canary_hits:
            audit = getattr(self.app.state, "audit", None)
            if audit is not None:
                await audit.record_event(
                    EventType.incident,
                    severity=Severity.critical,
                    detail={
                        "category": "canary_triggered",
                        "title": f"Canary data returned by MCP tool '{tool_id}' was redacted",
                        "rule_ids": ["SEC-MCP-02"],
                        "tool": tool_id,
                        "server": server,
                        "canary_occurrences": canary_hits,
                    },
                    principal=principal,
                    trace_id=ctx.trace_id,
                    session_id=ctx.session_id,
                )
        if decision.action in (Action.block, Action.require_approval):
            raise Withheld(list(decision.rule_ids), decision.reason, decision)
        new_content = content
        if decision.would_action is None:
            base = ctx.attributes.get("payload")
            base = base if isinstance(base, ToolResultPayload) else payload
            findings = transform_findings(self.engine, decision)
            replaced, skipped = apply_replacements(base, findings)
            if skipped and self._uncovered(findings, skipped):
                raise Withheld(["ENG-REDACT-01"], "overlapping sensitive spans could not be redacted safely", decision)
            assert isinstance(replaced, ToolResultPayload)
            new_content = replaced.content
        try:
            return seg.write_back(new_content)
        except ResultRefused as exc:
            raise Withheld(["SEC-MCP-02"], exc.reason, decision) from exc

    async def _passthrough(
        self,
        request: Request,
        sess: GatewaySession,
        principal: Principal,
        rid: Any,
        method: str,
        params: dict[str, Any],
    ) -> Response:
        result = await sess.upstream.request(method, params or None)
        label = f"{sess.server_id}:{method}"
        try:
            seg = build_generic_segments(result, max_bytes=self.protocol_params().max_result_bytes)
            cleaned = await self._inspect_result(
                principal,
                self._client_session(request, sess),
                label,
                sess.server_id,
                rid,
                seg,
                False,
                self.protocol_params().canaries,
            )
        except ResultRefused as exc:
            return self._fail(rid, jsonrpc.RESULT_WITHHELD, f"result withheld ({exc.code}): {exc.reason}")
        except Withheld as w:
            data = {"rule_ids": w.rule_ids, "decision_id": w.decision.decision_id if w.decision else None}
            return self._fail(
                rid, jsonrpc.RESULT_WITHHELD, f"result withheld by policy ({', '.join(w.rule_ids)})", data
            )
        return self._reply(rid, cleaned)
