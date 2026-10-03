"""The OpenAI-compatible request path (concept §4, §6, §7).

    auth → access check → ingress inspection → transforms (redact / pseudonymise) → routing →
    audit(ingress) → connector → egress inspection → transforms → restore pseudonyms →
    hygiene (no logprobs / reasoning) → commit → audit(egress) → response

`ChatFlow` handles `/v1/chat/completions`, `EmbeddingsFlow` handles `/v1/embeddings`. Both read
`app.state.engine` once per request (a policy swap never affects a request in flight).
"""

from __future__ import annotations

import copy
import json
import logging
import re
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import anyio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import ValidationError

from acl import __version__
from acl.api.errors import GatewayError, error_body
from acl.api.request_validation import validate_chat_body, validate_embeddings_body
from acl.audit.builder import redacted_text
from acl.contracts.audit import AuditEvent, EventType, LatencyBreakdown, Usage
from acl.contracts.canonical import value_hash
from acl.contracts.common import (
    ACTION_SEVERITY,
    Action,
    CostTier,
    DataClass,
    InspectionPoint,
    Phase,
    PolicyMode,
    Preset,
    Severity,
    Versions,
)
from acl.contracts.decision import Decision, RouteInfo, Verdict
from acl.contracts.inspection import (
    ChatMessage,
    ChatPayload,
    ClientInfo,
    CompletionPayload,
    EmbeddingsPayload,
    FunctionCall,
    InspectionContext,
    Principal,
    SessionState,
    ToolCall,
)
from acl.engine.actions import commit_decision, session_key
from acl.engine.engine import Engine
from acl.engine.hooks import run_hooks
from acl.engine.replay import ReplayBuffer
from acl.engine.streaming import RepeatDetector, StreamGuard, is_blocking
from acl.engine.text import apply_replacements, iter_texts
from acl.engine.transforms import (
    message_reasoning,
    non_shadow_verdicts,
    obliges_local,
    restore_entity_types,
    restore_text,
    strip_response_hygiene,
    transform_findings,
    unaddressable_fields,
    vault_placeholders,
)
from acl.policy.models import Policy
from acl.routing.connectors.base import ConnectorError, UpstreamResponse, UpstreamUsage
from acl.routing.dev_access import PermissiveAccess
from acl.routing.metering import compute_usage, estimate_tokens
from acl.routing.registry import ConnectorRegistry, RoutingTable
from acl.routing.router import Route, RouteError, Router, RouteRequest, max_data_class

log = logging.getLogger(__name__)

_RULE_ID = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$")
_UA = re.compile(r"([A-Za-z0-9._-]+)(?:/([\w.+-]+))?")
_MAX_SESSION_ID = 128


def budget_exhausted(decision: Decision) -> str | None:
    """Reason when an enforced budget verdict asked for a local model (the response is then marked degraded)."""
    if Action.route_local not in decision.applied:
        return None
    for v in decision.verdicts:
        if v.control_type == "budget" and v.action == Action.route_local:
            return v.reason or "budget exhausted"
    return None


def _rule(candidate: str | None, fallback: str = "SEC-MODEL-01") -> str:
    return candidate if candidate and _RULE_ID.match(candidate) else fallback


def sse(obj: dict[str, Any]) -> bytes:
    return b"data: " + json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n\n"


def escalate_to_block(decision: Decision, rule_id: str, reason: str, decided_by: str) -> None:
    """Turn an engine decision into a final block (post-engine checks: routing refusal, unsafe redaction)."""
    decision.action = Action.block
    decision.final = True
    if Action.block not in decision.applied:
        decision.applied.append(Action.block)
    if rule_id not in decision.rule_ids:
        decision.rule_ids.append(rule_id)
    decision.decided_by = decided_by
    decision.decided_phase = Phase.decide
    decision.reason = reason
    decision.risk_score = max(decision.risk_score, 0.9)


def synthetic_block(
    ctx: InspectionContext, rule_id: str, reason: str, *, control_id: str, control_type: str, started: float
) -> Decision:
    verdict = Verdict(
        control_id=control_id,
        control_type=control_type,
        phase=Phase.deterministic,
        cost_tier=CostTier.deterministic,
        action=Action.block,
        final=True,
        rule_ids=[rule_id],
        reason=reason,
    )
    return Decision(
        decision_id=str(uuid.uuid4()),
        trace_id=ctx.trace_id,
        point=ctx.point,
        action=Action.block,
        applied=[Action.block],
        final=True,
        decided_by=control_id,
        decided_phase=Phase.deterministic,
        rule_ids=[rule_id],
        risk_score=1.0,
        reason=reason,
        verdicts=[verdict],
        labels_after=ctx.session.labels.model_copy(deep=True),
        versions=ctx.versions,
        latency_ms=(time.perf_counter() - started) * 1000,
    )


def message_dict(m: ChatMessage) -> dict[str, Any]:
    d = m.model_dump(exclude_none=True)
    if "content" not in d and m.role == "assistant":
        d["content"] = None
    return d


def _text_of_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


@dataclass
class Parsed:
    name: str
    payload: ChatPayload
    stream: bool
    include_usage: bool


class BaseFlow:
    """State and helpers shared by chat and embeddings."""

    point = InspectionPoint.ingress

    def __init__(self, request: Request, principal: Principal) -> None:
        self.request = request
        self.app: FastAPI = request.app
        self.principal = principal
        self.t0 = time.perf_counter()
        self.trace_id = uuid.uuid4().hex
        self.request_id = f"req-{uuid.uuid4().hex[:12]}"
        engine = self.app.state.engine
        if engine is None:
            raise GatewayError(503, "service_unavailable", "policy not loaded yet", trace_id=self.trace_id)
        self.engine: Engine = engine
        self.policy: Policy = engine.policy
        self.audit = getattr(self.app.state, "audit", None)
        if self.audit is None:
            raise GatewayError(503, "service_unavailable", "audit log unavailable", trace_id=self.trace_id)
        self.registry: ConnectorRegistry = self.app.state.connectors
        self.table: RoutingTable = self.registry.table_for(self.policy, engine.policy_version)
        self.router = Router(self.policy, self.table)
        self.access = self._access()
        self.salt = self.app.state.settings.value_hash_salt.get_secret_value()
        if getattr(self.app.state, "replay_buffer", None) is None:
            self.app.state.replay_buffer = ReplayBuffer(maxlen=2000)
        self.replay = self.app.state.replay_buffer
        self.vault = self.app.state.control_deps.get("vault")
        self.ctx: InspectionContext | None = None
        self.route: Route | None = None
        self.headers: dict[str, str] = {"x-acl-trace-id": self.trace_id}

    # ------------------------------------------------------------ plumbing

    def _access(self) -> Any:
        access = getattr(self.app.state, "access", None)
        if access is not None:
            return access
        if getattr(self.app.state, "allow_anonymous_dev", False):
            return PermissiveAccess(lambda: self.policy)
        raise GatewayError(
            403, "forbidden", "access control is not configured (failing closed)", trace_id=self.trace_id
        )

    def _client(self) -> ClientInfo:
        h = self.request.headers
        ua = _UA.match(h.get("user-agent", ""))
        app_name = h.get("x-client-app") or (ua.group(1).lower() if ua else "") or "unknown"
        return ClientInfo(
            app=app_name[:64],
            version=(h.get("x-client-version") or (ua.group(2) if ua else None) or None),
            device_id=(h.get("x-device-id") or None),
        )

    def _session_id(self, body: dict[str, Any]) -> str:
        """Session key for every session-scoped store (pseudonym vault, taint, budgets, loops).

        The client value (`X-Session-Id` / `user`) is untrusted: it is namespaced by the principal, so two
        principals that send the same value never share a session (CP1: cross-principal pseudonym restore).
        The raw client value is kept nowhere else.
        """
        raw = self.request.headers.get("x-session-id") or body.get("user")
        client = raw.strip()[:_MAX_SESSION_ID] if isinstance(raw, str) and raw.strip() else None
        return session_key(self.principal, client or f"sess-{uuid.uuid4().hex[:16]}")

    async def _context(
        self, body: dict[str, Any], name: str, payload: Any, point: InspectionPoint, user_request: str | None
    ) -> InspectionContext:
        preset: Preset = await self.access.effective_preset(self.principal)
        sid = self._session_id(body)
        sessions = getattr(self.app.state, "sessions", None)
        session = await sessions.load(sid) if sessions is not None else SessionState(session_id=sid)
        return InspectionContext(
            trace_id=self.trace_id,
            request_id=self.request_id,
            session_id=sid,
            point=point,
            principal=self.principal,
            client=self._client(),
            preset=preset,
            mode=PolicyMode.enforce,
            model_requested=name,
            payload=payload,
            session=session,
            versions=Versions(
                policy=self.engine.policy_version,
                grants=str(getattr(self.access, "grants_version", "0")),
                gateway=__version__,
            ),
            user_request=user_request,
        )

    def _decision_headers(self, decision_action: Action, route: RouteInfo | None) -> dict[str, str]:
        h = dict(self.headers)
        h["x-acl-decision"] = decision_action.value
        if route is not None:
            h["x-acl-model"] = route.model
            h["x-acl-degraded"] = "true" if route.degraded else "false"
        return h

    def _error(
        self, status: int, type_: str, message: str, code: str | None, decision: Action | None = None
    ) -> GatewayError:
        headers = dict(self.headers)
        if decision is not None:
            headers["x-acl-decision"] = decision.value
        if self.route is not None:
            headers["x-acl-model"] = self.route.info.model
            headers["x-acl-degraded"] = "true" if self.route.info.degraded else "false"
        return GatewayError(status, type_, message, code=code, trace_id=self.trace_id, headers=headers)

    def _denial(self, decision: Decision) -> GatewayError:
        code = decision.rule_ids[0] if decision.rule_ids else (decision.decided_by or "policy_violation")
        if decision.action == Action.require_approval:
            msg = decision.reason or f"Approval required by policy ({code})"
        else:
            msg = decision.reason or f"Blocked by policy ({code})"
        forbidden = "SEC-MODEL-01" in decision.rule_ids or any(
            v.control_type == "model_access" and v.action == Action.block for v in decision.verdicts
        )
        return self._error(403, "forbidden_model" if forbidden else "policy_violation", msg, code, decision.action)

    async def _record(
        self,
        ctx: InspectionContext,
        decision: Decision,
        *,
        route: RouteInfo | None = None,
        usage: Usage | None = None,
        upstream_ms: float = 0.0,
        total_since: float | None = None,
        response_hash: str | None = None,
    ) -> AuditEvent:
        redacted = self._redacted(ctx, decision.verdicts) if self.policy.global_.store_redacted_payloads else None
        total = (time.perf_counter() - (total_since if total_since is not None else self.t0)) * 1000
        if usage is not None:
            await run_hooks(self.app, "on_usage", ctx, decision, route, usage)
        return await self.audit.record_decision(
            ctx,
            decision,
            route=route,
            usage=usage,
            latency=LatencyBreakdown(total_ms=total, pipeline_ms=decision.latency_ms, upstream_ms=upstream_ms),
            redacted_payload=redacted,
            response_hash=response_hash,
        )

    async def _commit(self, ctx: InspectionContext, decision: Decision) -> None:
        """Apply an enforced decision (shared with /v1/decide and the MCP proxy)."""
        await commit_decision(self.app, ctx, decision)

    @staticmethod
    def _redacted(ctx: InspectionContext, verdicts: list[Verdict]) -> str | None:
        """Masked payload text for the audit record, or None when a detected span cannot be masked.

        A finding inside a field whose path is not addressable (free-form JSON keys such as `my-key`)
        would survive masking verbatim; the audit log must never store it (CLAUDE.md rule 2).
        """
        payload = ctx.attributes.get("payload", ctx.payload)
        if getattr(payload, "kind", None) != ctx.payload.kind:
            payload = ctx.payload
        fields = {f.field for v in verdicts for f in v.findings if f.field}
        if fields and fields & unaddressable_fields(payload):
            return None
        return redacted_text(ctx, verdicts)

    def _replay(self, ctx: InspectionContext, decision: Decision) -> None:
        if self.replay is not None:
            self.replay.add(ctx, decision)

    async def _deny_forbidden(self, ctx: InspectionContext, rule_id: str, reason: str) -> GatewayError:
        """Forbidden model: block decision + incident (concept §7.1: 403 + incident)."""
        rule = _rule(rule_id)
        decision = synthetic_block(
            ctx, rule, reason, control_id="SEC-MODEL-01", control_type="model_access", started=self.t0
        )
        event = await self._record(ctx, decision)
        await self._commit(ctx, decision)
        who = self.principal.username or self.principal.subject
        await self.audit.record_event(
            EventType.incident,
            severity=Severity.medium,
            detail={
                "category": "forbidden_model",
                "title": f"Forbidden model {ctx.model_requested!r} requested by {who}",
                "rule_ids": [rule],
                "related_event_ids": [event.event_id],
                "model": ctx.model_requested,
            },
            principal=self.principal,
            trace_id=self.trace_id,
            session_id=ctx.session_id,
        )
        return self._denial(decision)

    async def _block_after_engine(
        self, ctx: InspectionContext, decision: Decision, rule_id: str, reason: str, decided_by: str
    ) -> GatewayError:
        escalate_to_block(decision, rule_id, reason, decided_by)
        await self._record(ctx, decision)
        await self._commit(ctx, decision)
        self._replay(ctx, decision)
        return self._denial(decision)

    def _data_class(self, decision: Decision, ctx: InspectionContext) -> DataClass:
        classes = [v.data_class for v in non_shadow_verdicts(self.engine, decision)]
        classes.append(ctx.session.labels.confidentiality)
        return max_data_class(classes)

    def _check_overlaps(self, findings: list, skipped: list) -> Any:
        """A skipped (overlapping) finding that is not fully covered by an applied one → unsafe redaction."""
        applied = [f for f in findings if f not in skipped]
        for s in skipped:
            covered = any(
                a.field == s.field and a.start <= s.start and a.end >= s.end  # type: ignore[operator]
                for a in applied
            )
            if not covered:
                return s
        return None

    async def _system_alert(self, ctx: InspectionContext | None, detail: dict[str, Any]) -> None:
        try:
            await self.audit.record_event(
                EventType.system_alert,
                severity=Severity.medium,
                detail=detail,
                principal=self.principal,
                trace_id=self.trace_id,
                session_id=ctx.session_id if ctx else None,
            )
        except Exception:
            log.exception("could not record system_alert")

    def _usd_ceiling_ok(self) -> bool:  # pragma: no cover - budgets arrive in Phase 2D
        return True


# =============================================================================== chat


class ChatFlow(BaseFlow):
    def parse(self, body: dict[str, Any]) -> Parsed:
        name = body.get("model")
        if not isinstance(name, str) or not name:
            raise GatewayError(
                400, "invalid_request_error", "'model' is required", code="missing_model", trace_id=self.trace_id
            )
        raw_messages = body.get("messages")
        if not isinstance(raw_messages, list) or not raw_messages:
            raise GatewayError(
                400, "invalid_request_error", "'messages' must be a non-empty list", trace_id=self.trace_id
            )
        n = body.get("n")
        if n is not None and (isinstance(n, bool) or n != 1):
            raise GatewayError(
                400, "invalid_request_error", "n > 1 is not supported", code="n_unsupported", trace_id=self.trace_id
            )
        try:
            # Fail closed: only allowlisted, inspectable fields are accepted (and forwarded).
            clean_messages, tools, params = validate_chat_body(body)
        except GatewayError as exc:
            exc.trace_id = self.trace_id
            raise
        try:
            messages = [ChatMessage.model_validate(m) for m in clean_messages]
        except ValidationError as exc:
            raise GatewayError(
                400, "invalid_request_error", f"invalid message: {exc.errors()[0]['msg']}", trace_id=self.trace_id
            ) from exc
        stream = bool(body.get("stream"))
        so = body.get("stream_options")
        # Everything forwarded upstream lives in the payload, so the pipeline inspects (and transforms) it.
        payload = ChatPayload(messages=messages, tools=tools, params={**params, "stream": stream})
        return Parsed(name, payload, stream, bool(isinstance(so, dict) and so.get("include_usage")))

    async def run(self, body: dict[str, Any]) -> Response:
        try:
            return await self._run(body)
        except GatewayError:
            raise
        except Exception as exc:
            log.exception("unhandled error in chat flow (trace %s)", self.trace_id)
            await self._system_alert(self.ctx, {"event": "internal_error", "error": type(exc).__name__})
            raise self._error(500, "internal_error", "internal gateway error", "internal_error") from exc

    async def _run(self, body: dict[str, Any]) -> Response:
        parsed = self.parse(body)
        last_user = next(
            (_text_of_content(m.content) for m in reversed(parsed.payload.messages) if m.role == "user"), None
        )
        ctx = self.ctx = await self._context(body, parsed.name, parsed.payload, InspectionPoint.ingress, last_user)

        # -- 1. model access (authorization is deterministic and independent of detectors)
        check = await self.access.check_model(self.principal, parsed.name)
        if not check.allowed:
            raise await self._deny_forbidden(
                ctx, check.rule_id or "SEC-MODEL-01", check.reason or "model not permitted"
            )

        # -- 2. ingress inspection
        decision = await self.engine.evaluate(ctx)
        if is_blocking(decision):
            await self._record(ctx, decision)
            await self._commit(ctx, decision)
            self._replay(ctx, decision)
            raise self._denial(decision)

        # -- 3. transforms
        base = ctx.attributes.get("payload")
        base = base if isinstance(base, ChatPayload) else parsed.payload
        findings = transform_findings(self.engine, decision)
        if findings and (unsafe := unaddressable_fields(base)) and any(f.field in unsafe for f in findings):
            # a span inside a field that cannot be addressed unambiguously cannot be masked: never forward it
            raise await self._block_after_engine(
                ctx,
                decision,
                "ENG-REDACT-01",
                "a sensitive span could not be located for redaction",
                "ENG-REDACT-01",
            )
        payload_out, skipped = apply_replacements(base, findings)
        bad = self._check_overlaps(findings, skipped) if skipped else None
        if bad is not None:
            raise await self._block_after_engine(
                ctx,
                decision,
                _rule(bad.rule_id, "ENG-REDACT-01"),
                "overlapping sensitive spans could not be redacted safely",
                "ENG-REDACT-01",
            )
        assert isinstance(payload_out, ChatPayload)

        # -- 4. routing
        usable = await self.access.usable_models(self.principal)
        preset_cfg = self.policy.presets.get(ctx.preset)
        rr = RouteRequest(
            requested=parsed.name,
            data_class=self._data_class(decision, ctx),
            usable=usable,
            force_local=obliges_local(self.engine, decision),
            force_reason=("route_local" if Action.route_local in decision.applied else "downgrade"),
            budget_exhausted=budget_exhausted(decision),
            capability="chat",
            sensitive_external_action=preset_cfg.sensitive_external_action if preset_cfg else Action.route_local,
        )
        try:
            route = self.router.route(rr)
        except RouteError as exc:
            if exc.status == 403:
                raise await self._block_after_engine(ctx, decision, _rule(exc.rule_id), str(exc), "ROUTER") from exc
            self._replay(ctx, decision)
            await self._record(ctx, decision)
            await self._commit(ctx, decision)
            raise self._error(
                exc.status,
                "invalid_request_error" if exc.status < 500 else "service_unavailable",
                str(exc),
                exc.code,
                decision.action,
            ) from exc
        self.route = route
        decision.route = route.info
        self._replay(ctx, decision)

        # -- 5. audit ingress, then commit
        await self._record(ctx, decision, route=route.info)
        await self._commit(ctx, decision)

        # -- 6. upstream request
        request = self._upstream_request(payload_out, route)
        ingress_action = decision.action
        if parsed.stream:
            return await self._stream(ctx, parsed, request, rr, ingress_action)
        return await self._complete(ctx, parsed, request, rr, ingress_action, payload_out)

    # ------------------------------------------------------------ upstream

    def _upstream_request(self, payload: ChatPayload, route: Route) -> dict[str, Any]:
        """Built ONLY from the inspected (normalised + transformed) payload: nothing bypasses the pipeline."""
        messages = [message_dict(m) for m in payload.messages]
        if route.model.system_prompt:
            messages.insert(0, {"role": "system", "content": route.model.system_prompt})
        params = {k: v for k, v in payload.params.items() if k != "stream"}
        req: dict[str, Any] = {**copy.deepcopy(params), "messages": messages}
        if payload.tools:
            req["tools"] = payload.tools
        cap = self.policy.budgets.stream.max_output_tokens
        if route.model.max_output_tokens:
            cap = min(cap, route.model.max_output_tokens)
        for key in ("max_tokens", "max_completion_tokens"):
            if isinstance(req.get(key), int) and req[key] > cap:
                req[key] = cap
        return req

    async def _on_upstream_failure(
        self, route: Route, rr: RouteRequest, exc: ConnectorError, *, allow_fallback: bool
    ) -> Route:
        """Degraded fallback for a retryable upstream failure, else the client-facing error (both audited)."""
        self.registry.record_error(route.info.connector, str(exc))
        fb = self.router.degraded_route(route, rr, f"HTTP {exc.status}") if allow_fallback and exc.retryable else None
        if fb is None:
            await self._system_alert(
                self.ctx, {"event": "upstream_error", "model": route.info.model, "status": exc.status}
            )
            status = 429 if exc.status == 429 else 504 if exc.status == 504 else 502
            raise self._error(status, "upstream_error", "the upstream model call failed", f"upstream_{exc.status}")
        await self._system_alert(
            self.ctx,
            {"event": "upstream_failover", "from": route.info.model, "to": fb.info.model, "status": exc.status},
        )
        self.route = fb
        return fb

    async def _call(
        self, route: Route, request: dict[str, Any], rr: RouteRequest
    ) -> tuple[UpstreamResponse, Route, float]:
        for attempt in range(2):
            t = time.perf_counter()
            try:
                resp = await route.connector.chat(route.upstream_model, request)
            except ConnectorError as exc:
                route = await self._on_upstream_failure(route, rr, exc, allow_fallback=attempt == 0)
                continue
            ms = (time.perf_counter() - t) * 1000
            self.registry.record_success(route.info.connector, ms)
            return resp, route, ms
        raise AssertionError("unreachable")  # pragma: no cover

    # ------------------------------------------------------------ non-streaming

    def _egress_ctx(self, ctx: InspectionContext, completion: CompletionPayload, route: Route) -> InspectionContext:
        return ctx.model_copy(
            update={
                "point": InspectionPoint.egress,
                "payload": completion,
                "attributes": {"route_model": route.info.model, "route_tier": route.info.tier.value},
                "timestamp": datetime.now(UTC),
            }
        )

    @staticmethod
    def _tool_calls(raw: list[dict[str, Any]] | None) -> list[ToolCall]:
        calls = []
        for i, tc in enumerate(raw or []):
            fn = tc.get("function") or {}
            args = fn.get("arguments", "{}")
            calls.append(
                ToolCall(
                    id=str(tc.get("id") or f"call_{i}"),
                    function=FunctionCall(
                        name=str(fn.get("name", "")), arguments=args if isinstance(args, str) else json.dumps(args)
                    ),
                )
            )
        return calls

    async def _complete(
        self,
        ctx: InspectionContext,
        parsed: Parsed,
        request: dict[str, Any],
        rr: RouteRequest,
        ingress_action: Action,
        payload_out: ChatPayload,
    ) -> Response:
        assert self.route is not None
        resp, route, upstream_ms = await self._call(self.route, request, rr)
        self.route = route
        body = copy.deepcopy(resp.body)
        choice = (body.get("choices") or [{}])[0]
        message = choice.setdefault("message", {"role": "assistant", "content": None})
        content = message.get("content") if isinstance(message.get("content"), str) else None
        completion = CompletionPayload(
            content=content,
            tool_calls=self._tool_calls(message.get("tool_calls")),
            finish_reason=choice.get("finish_reason"),
            reasoning=message_reasoning(message),
            has_logprobs=bool(choice.get("logprobs")),
        )
        egress_ctx = self._egress_ctx(ctx, completion, route)
        decision = await self.engine.evaluate(egress_ctx)
        decision.route = route.info
        usage = self._usage(route, resp.usage, payload_out, completion)

        if is_blocking(decision):
            await self._record(egress_ctx, decision, route=route.info, usage=usage, upstream_ms=upstream_ms)
            await self._commit(egress_ctx, decision)
            self._replay(egress_ctx, decision)
            raise self._denial(decision)

        # -- transforms on the model output, then restore pseudonyms into assistant TEXT only
        out_payload, skipped = apply_replacements(completion, transform_findings(self.engine, decision))
        bad = self._check_overlaps(transform_findings(self.engine, decision), skipped) if skipped else None
        if bad is not None:
            escalate_to_block(
                decision,
                _rule(bad.rule_id, "ENG-REDACT-01"),
                "overlapping sensitive spans could not be redacted safely",
                "ENG-REDACT-01",
            )
            await self._record(egress_ctx, decision, route=route.info, usage=usage, upstream_ms=upstream_ms)
            await self._commit(egress_ctx, decision)
            raise self._denial(decision)
        assert isinstance(out_payload, CompletionPayload)
        text = out_payload.content
        if text and await vault_placeholders(self.vault, ctx.session_id):
            text = await restore_text(self.vault, ctx.session_id, text, restore_entity_types(self.policy))
        if content is not None or text is not None:
            message["content"] = text
        for original, replaced in zip(message.get("tool_calls") or [], out_payload.tool_calls, strict=False):
            original.setdefault("function", {})["arguments"] = replaced.function.arguments
        strip_response_hygiene(body)
        body["model"] = route.info.model
        body["usage"] = {
            "prompt_tokens": usage.input_tokens,
            "completion_tokens": usage.output_tokens,
            "total_tokens": usage.input_tokens + usage.output_tokens,
        }
        rhash = value_hash(text, self.salt, 64) if text else None
        await self._record(
            egress_ctx, decision, route=route.info, usage=usage, upstream_ms=upstream_ms, response_hash=rhash
        )
        await self._commit(egress_ctx, decision)
        self._replay(egress_ctx, decision)
        overall = max(ingress_action, decision.action, key=lambda a: ACTION_SEVERITY[a])
        return JSONResponse(body, headers=self._decision_headers(overall, route.info))

    def _usage(self, route: Route, up: UpstreamUsage, payload_in: ChatPayload, completion: CompletionPayload) -> Usage:
        if not up.input_tokens:
            up.input_tokens = estimate_tokens("\n".join(t for _, t in iter_texts(payload_in)))
        if not up.output_tokens:
            out_text = "".join(t for _, t in iter_texts(completion))
            up.output_tokens = estimate_tokens(out_text)
        return compute_usage(route.model, up)

    # ------------------------------------------------------------ streaming

    async def _open_stream(
        self, route: Route, request: dict[str, Any], rr: RouteRequest
    ) -> tuple[Route, AsyncIterator[Any], Any]:
        for attempt in range(2):
            agen = route.connector.chat_stream(route.upstream_model, request)
            try:
                first = await agen.__anext__()
                return route, agen, first
            except StopAsyncIteration:
                return route, agen, None
            except ConnectorError as exc:
                await agen.aclose()
                route = await self._on_upstream_failure(route, rr, exc, allow_fallback=attempt == 0)
        raise AssertionError("unreachable")  # pragma: no cover

    async def _stream(
        self, ctx: InspectionContext, parsed: Parsed, request: dict[str, Any], rr: RouteRequest, ingress_action: Action
    ) -> Response:
        assert self.route is not None
        t_up = time.perf_counter()
        route, agen, first = await self._open_stream(self.route, request, rr)
        self.route = route
        headers = self._decision_headers(ingress_action, route.info)
        headers.update({"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
        return StreamingResponse(
            self._stream_body(ctx, parsed, route, agen, first, t_up),
            media_type="text/event-stream",
            headers=headers,
        )

    async def _stream_body(
        self,
        ctx: InspectionContext,
        parsed: Parsed,
        route: Route,
        agen: AsyncIterator[Any],
        first: Any,
        t_up: float,
    ) -> AsyncIterator[bytes]:
        caps = self.policy.budgets.stream
        max_out = caps.max_output_tokens
        if route.model.max_output_tokens:
            max_out = min(max_out, route.model.max_output_tokens)
        placeholders = await vault_placeholders(self.vault, ctx.session_id)
        allowed_types = restore_entity_types(self.policy)

        async def restore(text: str) -> str:
            return await restore_text(self.vault, ctx.session_id, text, allowed_types)

        probe = self._egress_ctx(ctx, CompletionPayload(content="", is_partial=True), route)
        inspect = bool(self.engine.pipeline.applicable(probe))

        async def evaluate(payload: CompletionPayload) -> Decision:
            decision = await self.engine.evaluate(self._egress_ctx(ctx, payload, route))
            decision.route = route.info
            return decision

        guard = StreamGuard(
            evaluate=evaluate,
            findings_of=lambda d: transform_findings(self.engine, d),
            restore=restore if placeholders else None,
            placeholders=placeholders,
            holdback_chars=caps.holdback_chars,
            inspect=inspect,
        )
        repeat = RepeatDetector(caps.repeat_ngram.n, caps.repeat_ngram.max_repeats)
        chunk_id, created, model_id = f"chatcmpl-{uuid.uuid4().hex[:24]}", int(time.time()), route.info.model

        def chunk(delta: dict[str, Any], finish: str | None = None) -> bytes:
            return sse(
                {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model_id,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
                }
            )

        tool_acc: dict[int, dict[str, str]] = {}
        out_chars = reasoning_chars = 0
        finish_reason: str | None = None
        cut_reason: str | None = None
        upstream_usage: UpstreamUsage | None = None
        blocked: Decision | None = None
        final: Decision | None = None
        upstream_error: ConnectorError | None = None
        egress_ctx_final: InspectionContext | None = None
        out_calls: list[ToolCall] = []
        emitted_text: list[str] = []
        completed = False

        try:
            yield chunk({"role": "assistant", "content": ""})

            async def chunks() -> AsyncIterator[Any]:
                if first is not None:
                    yield first
                try:
                    async for ch in agen:
                        yield ch
                except ConnectorError as exc:
                    nonlocal upstream_error
                    upstream_error = exc
                    self.registry.record_error(route.info.connector, str(exc))

            upstream_iter = chunks()
            async for ch in upstream_iter:
                if ch.usage is not None:
                    upstream_usage = ch.usage
                for choice in ch.body.get("choices") or []:
                    delta = choice.get("delta") or {}
                    if choice.get("finish_reason"):
                        finish_reason = choice["finish_reason"]
                    for key in ("reasoning_content", "reasoning"):
                        if isinstance(delta.get(key), str):
                            reasoning_chars += len(delta[key])  # counted for the cap, never forwarded
                    for tc in delta.get("tool_calls") or []:
                        idx = tc.get("index")
                        if idx is None:
                            idx = len(tool_acc) - 1 if (not tc.get("id") and tool_acc) else len(tool_acc)
                        slot = tool_acc.setdefault(idx, {"id": "", "name": "", "arguments": ""})
                        slot["id"] = tc.get("id") or slot["id"]
                        fn = tc.get("function") or {}
                        slot["name"] += fn.get("name") or ""
                        slot["arguments"] += fn.get("arguments") or ""
                        out_chars += len(fn.get("arguments") or "")
                    text = delta.get("content")
                    if isinstance(text, str) and text:
                        out_chars += len(text)
                        step = await guard.feed(text)
                        if step.blocked is not None:
                            blocked = step.blocked
                            break
                        if step.text:
                            emitted_text.append(step.text)
                            yield chunk({"content": step.text})
                        if repeat.feed(text):
                            cut_reason = "repeated n-gram"
                if blocked is not None:
                    break
                if cut_reason is None:
                    if out_chars / 4 > max_out:
                        cut_reason = "max_output_tokens"
                    elif reasoning_chars / 4 > caps.max_reasoning_tokens:
                        cut_reason = "max_reasoning_tokens"
                if cut_reason is not None:
                    break
            await upstream_iter.aclose()
            await agen.aclose()

            if blocked is None:
                # A tool call cut off by a stream cap is incomplete: never forward it.
                calls = (
                    []
                    if cut_reason
                    else [
                        ToolCall(
                            id=s["id"] or f"call_{i}",
                            function=FunctionCall(name=s["name"], arguments=s["arguments"] or "{}"),
                        )
                        for i, s in sorted(tool_acc.items())
                    ]
                )
                end = await guard.finish(calls, finish_reason)
                final = end.decision
                egress_ctx_final = self._egress_ctx(
                    ctx,
                    CompletionPayload(content=guard.buf or None, tool_calls=calls, finish_reason=finish_reason),
                    route,
                )
                if end.blocked:
                    blocked = end.decision
                else:
                    if end.text:
                        emitted_text.append(end.text)
                        yield chunk({"content": end.text})
                    out_calls = end.tool_calls
                    if out_calls:
                        yield chunk(
                            {
                                "tool_calls": [
                                    {
                                        "index": i,
                                        "id": tc.id,
                                        "type": "function",
                                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                                    }
                                    for i, tc in enumerate(out_calls)
                                ]
                            }
                        )
            if blocked is not None:
                final = blocked
                yield sse(
                    error_body(
                        blocked.reason or "response blocked by policy",
                        "policy_violation",
                        blocked.rule_ids[0] if blocked.rule_ids else (blocked.decided_by or "policy_violation"),
                        self.trace_id,
                    )
                )
            else:
                if cut_reason is not None:
                    reason_out = "length"
                elif out_calls:
                    reason_out = "tool_calls"
                else:
                    reason_out = finish_reason or "stop"
                yield chunk({}, reason_out)
                if upstream_error is not None:
                    yield sse(
                        error_body(
                            "the upstream model call failed mid-stream",
                            "upstream_error",
                            f"upstream_{upstream_error.status}",
                            self.trace_id,
                        )
                    )
                completed = True
                if parsed.include_usage:
                    usage = self._stream_usage(route, upstream_usage, ctx, guard, tool_acc)
                    yield sse(
                        {
                            "id": chunk_id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model_id,
                            "choices": [],
                            "usage": {
                                "prompt_tokens": usage.input_tokens,
                                "completion_tokens": usage.output_tokens,
                                "total_tokens": usage.input_tokens + usage.output_tokens,
                            },
                        }
                    )
            yield b"data: [DONE]\n\n"
        finally:
            # Runs on normal end, block, error and client disconnect; shielded so the audit write survives cancel.
            with anyio.CancelScope(shield=True):
                await self._finish_stream_audit(
                    ctx,
                    route,
                    final,
                    egress_ctx_final,
                    guard,
                    tool_acc,
                    upstream_usage,
                    upstream_ms=(time.perf_counter() - t_up) * 1000,
                    cut_reason=cut_reason,
                    completed=completed,
                    emitted="".join(emitted_text),
                )

    def _stream_usage(
        self,
        route: Route,
        up: UpstreamUsage | None,
        ctx: InspectionContext,
        guard: StreamGuard,
        tool_acc: dict[int, dict[str, str]],
    ) -> Usage:
        up = up or UpstreamUsage()
        if not up.input_tokens:
            assert isinstance(ctx.payload, ChatPayload)
            up.input_tokens = estimate_tokens("\n".join(t for _, t in iter_texts(ctx.payload)))
        if not up.output_tokens:
            up.output_tokens = estimate_tokens(guard.buf + "".join(s["arguments"] for s in tool_acc.values()))
        return compute_usage(route.model, up)

    async def _finish_stream_audit(
        self,
        ctx: InspectionContext,
        route: Route,
        final: Decision | None,
        egress_ctx: InspectionContext | None,
        guard: StreamGuard,
        tool_acc: dict[int, dict[str, str]],
        upstream_usage: UpstreamUsage | None,
        *,
        upstream_ms: float,
        cut_reason: str | None,
        completed: bool,
        emitted: str,
    ) -> None:
        try:
            if final is None:
                await self._system_alert(
                    ctx, {"event": "stream_aborted", "model": route.info.model, "connector": route.info.connector}
                )
                return
            if egress_ctx is None:
                egress_ctx = self._egress_ctx(ctx, CompletionPayload(content=guard.buf or None, is_partial=True), route)
            usage = self._stream_usage(route, upstream_usage, ctx, guard, tool_acc)
            await self._record(
                egress_ctx,
                final,
                route=route.info,
                usage=usage,
                upstream_ms=upstream_ms,
                response_hash=value_hash(emitted, self.salt, 64) if emitted else None,
            )
            await self._commit(egress_ctx, final)
            self._replay(egress_ctx, final)
            if cut_reason is not None:
                await self._system_alert(ctx, {"event": "stream_cut", "reason": cut_reason, "model": route.info.model})
        except Exception:
            log.exception("stream audit failed (trace %s)", self.trace_id)


# =============================================================================== embeddings


class EmbeddingsFlow(BaseFlow):
    point = InspectionPoint.embeddings

    async def run(self, body: dict[str, Any]) -> Response:
        try:
            return await self._run(body)
        except GatewayError:
            raise
        except Exception as exc:
            log.exception("unhandled error in embeddings flow (trace %s)", self.trace_id)
            await self._system_alert(self.ctx, {"event": "internal_error", "error": type(exc).__name__})
            raise self._error(500, "internal_error", "internal gateway error", "internal_error") from exc

    async def _run(self, body: dict[str, Any]) -> Response:
        try:
            forwarded = validate_embeddings_body(body)  # fail closed: allowlisted keys only
        except GatewayError as exc:
            exc.trace_id = self.trace_id
            raise
        raw = body.get("input")
        inputs = [raw] if isinstance(raw, str) else raw
        if not isinstance(inputs, list) or not inputs or not all(isinstance(i, str) for i in inputs):
            raise GatewayError(
                400,
                "invalid_request_error",
                "'input' must be a string or a non-empty list of strings",
                trace_id=self.trace_id,
            )
        default = self.policy.routing.targets.embeddings
        name = body.get("model") or default
        if not isinstance(name, str) or not name:
            raise GatewayError(400, "invalid_request_error", "'model' is required", trace_id=self.trace_id)
        payload = EmbeddingsPayload(inputs=list(inputs))
        ctx = self.ctx = await self._context(body, name, payload, InspectionPoint.embeddings, None)

        check = await self.access.check_model(self.principal, name)
        if not check.allowed:
            raise await self._deny_forbidden(
                ctx, check.rule_id or "SEC-MODEL-01", check.reason or "model not permitted"
            )

        decision = await self.engine.evaluate(ctx)
        if is_blocking(decision):
            await self._record(ctx, decision)
            await self._commit(ctx, decision)
            self._replay(ctx, decision)
            raise self._denial(decision)

        base = ctx.attributes.get("payload")
        base = base if isinstance(base, EmbeddingsPayload) else payload
        findings = transform_findings(self.engine, decision)
        out, skipped = apply_replacements(base, findings)
        bad = self._check_overlaps(findings, skipped) if skipped else None
        if bad is not None:
            raise await self._block_after_engine(
                ctx,
                decision,
                _rule(bad.rule_id, "ENG-REDACT-01"),
                "overlapping sensitive spans could not be redacted safely",
                "ENG-REDACT-01",
            )
        assert isinstance(out, EmbeddingsPayload)

        usable = await self.access.usable_models(self.principal)
        preset_cfg = self.policy.presets.get(ctx.preset)
        rr = RouteRequest(
            requested=name,
            data_class=self._data_class(decision, ctx),
            usable=usable,
            force_local=obliges_local(self.engine, decision),
            budget_exhausted=budget_exhausted(decision),
            capability="embeddings",
            sensitive_external_action=preset_cfg.sensitive_external_action if preset_cfg else Action.route_local,
        )
        try:
            route = self.router.route(rr)
        except RouteError as exc:
            if exc.status == 403:
                raise await self._block_after_engine(ctx, decision, _rule(exc.rule_id), str(exc), "ROUTER") from exc
            await self._record(ctx, decision)
            await self._commit(ctx, decision)
            raise self._error(
                exc.status,
                "invalid_request_error" if exc.status < 500 else "service_unavailable",
                str(exc),
                exc.code,
                decision.action,
            ) from exc
        self.route = route
        decision.route = route.info
        self._replay(ctx, decision)

        t = time.perf_counter()
        try:
            resp = await route.connector.embeddings(route.upstream_model, {**forwarded, "input": out.inputs})
        except ConnectorError as exc:
            self.registry.record_error(route.info.connector, str(exc))
            await self._record(ctx, decision, route=route.info)
            await self._commit(ctx, decision)
            await self._system_alert(ctx, {"event": "upstream_error", "status": exc.status, "model": route.info.model})
            raise self._error(
                502, "upstream_error", "the upstream model call failed", f"upstream_{exc.status}"
            ) from exc
        upstream_ms = (time.perf_counter() - t) * 1000
        self.registry.record_success(route.info.connector, upstream_ms)
        up = resp.usage
        if not up.input_tokens:
            up.input_tokens = estimate_tokens("\n".join(out.inputs))
        usage = compute_usage(route.model, up)
        await self._record(ctx, decision, route=route.info, usage=usage, upstream_ms=upstream_ms)
        await self._commit(ctx, decision)
        result = copy.deepcopy(resp.body)
        result["model"] = route.info.model
        result["usage"] = {"prompt_tokens": usage.input_tokens, "total_tokens": usage.input_tokens}
        return JSONResponse(result, headers=self._decision_headers(decision.action, route.info))


async def models_listing(request: Request, principal: Principal) -> dict[str, Any]:
    app = request.app
    engine = app.state.engine
    access = getattr(app.state, "access", None)
    if access is None:
        if not getattr(app.state, "allow_anonymous_dev", False):
            raise GatewayError(403, "forbidden", "access control is not configured (failing closed)")
        access = PermissiveAccess(lambda: engine.policy if engine else None)
    if engine is None:
        raise GatewayError(503, "service_unavailable", "policy not loaded yet")
    names = await access.visible_names(principal)
    policy = engine.policy
    owners = {m.id: policy.connectors[m.connector].tier.value for m in policy.models}
    now = int(time.time())
    return {
        "object": "list",
        "data": [
            {"id": n, "object": "model", "created": now, "owned_by": owners.get(n, "acl")} for n in sorted(set(names))
        ],
    }


__all__ = ["BaseFlow", "ChatFlow", "EmbeddingsFlow", "models_listing"]
