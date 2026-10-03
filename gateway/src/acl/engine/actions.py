"""Evaluate one inspection point outside the chat flow (orchestrator-owned seam).

Used by `/v1/decide` (client-local tool calls), the MCP proxy (tools/call, tool results, tools/list,
initialize) and anything else that must be governed exactly like chat traffic:

    ctx, decision = await evaluate_point(
        app, principal, point=InspectionPoint.tool_call,
        payload=ToolCallPayload(tool="mail.send", server="mail", arguments={...}),
        client_session="oc-anna-7",            # untrusted client value; namespaced by principal here
        attributes={"tool_input_schema": {...}},  # optional pre-populated context attributes
    )

It loads session state, evaluates (side-effect free), writes the audit record, and — unless
`commit=False` (dry evaluation) — applies the decision: control `commit()`s, monotonic session
labels/steps and flow hooks. Callers enforce `decision.action` themselves.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from acl import __version__
from acl.contracts.common import Action, InspectionPoint, PolicyMode, Preset, Versions
from acl.contracts.decision import Decision
from acl.contracts.inspection import ClientInfo, InspectionContext, Payload, Principal, SessionState
from acl.engine.hooks import run_hooks
from acl.sessions.store import merge_labels


class GatewayUnavailable(RuntimeError):
    """No engine/audit/access wired: callers must fail closed (HTTP 503 / JSON-RPC error)."""


def principal_namespace(principal: Principal) -> str:
    """First 16 hex chars of sha256(principal.subject): the per-principal session namespace."""
    return hashlib.sha256(principal.subject.encode("utf-8")).hexdigest()[:16]


def session_key(principal: Principal, client_value: str) -> str:
    """Session ids are untrusted client values namespaced by principal (CP1 finding 2)."""
    return f"{principal_namespace(principal)}:{client_value}"


async def commit_decision(app: Any, ctx: InspectionContext, decision: Decision) -> None:
    """Apply an enforced decision: control state, session labels (monotonic) + step counter, flow hooks."""
    engine = app.state.engine
    if engine is not None:
        await engine.commit(ctx, decision)
    sessions = getattr(app.state, "sessions", None)
    if sessions is not None:
        ingress = ctx.point == InspectionPoint.ingress
        tool = ctx.point == InspectionPoint.tool_call and decision.action not in (Action.block, Action.require_approval)

        def apply(state: SessionState) -> SessionState:
            return state.model_copy(
                update={
                    "labels": merge_labels(state.labels, decision.labels_after),
                    "step": state.step + (1 if ingress else 0),
                    "tool_depth": state.tool_depth + (1 if tool else 0),
                }
            )

        await sessions.update(ctx.session_id, apply)
    await run_hooks(app, "on_commit", ctx, decision)


async def evaluate_point(
    app: Any,
    principal: Principal,
    *,
    point: InspectionPoint,
    payload: Payload,
    client_session: str | None,
    client: ClientInfo | None = None,
    model_requested: str | None = None,
    user_request: str | None = None,
    attributes: dict[str, Any] | None = None,
    trace_id: str | None = None,
    commit: bool = True,
    record: bool = True,
) -> tuple[InspectionContext, Decision]:
    engine = getattr(app.state, "engine", None)
    if engine is None:
        raise GatewayUnavailable("policy not loaded")
    audit = getattr(app.state, "audit", None)
    if record and audit is None:
        raise GatewayUnavailable("audit log unavailable")
    access = getattr(app.state, "access", None)
    if access is not None:
        preset: Preset = await access.effective_preset(principal)
        grants_version = str(getattr(access, "grants_version", "0"))
    elif getattr(app.state, "allow_anonymous_dev", False):
        preset, grants_version = engine.policy.global_.default_preset, "0"
    else:
        raise GatewayUnavailable("access control is not configured (failing closed)")

    sid = session_key(principal, client_session or f"sess-{uuid.uuid4().hex[:16]}")
    sessions = getattr(app.state, "sessions", None)
    session = await sessions.load(sid) if sessions is not None else SessionState(session_id=sid)
    ctx = InspectionContext(
        trace_id=trace_id or uuid.uuid4().hex,
        request_id=f"req-{uuid.uuid4().hex[:12]}",
        session_id=sid,
        point=point,
        principal=principal,
        client=client or ClientInfo(),
        preset=preset,
        mode=PolicyMode.enforce,
        model_requested=model_requested,
        payload=payload,
        session=session,
        versions=Versions(policy=engine.policy_version, grants=grants_version, gateway=__version__),
        user_request=user_request,
        attributes=dict(attributes or {}),
    )
    decision = await engine.evaluate(ctx)
    if record:
        from acl.audit.builder import redacted_text
        from acl.engine.transforms import unaddressable_fields

        redacted = None
        if engine.policy.global_.store_redacted_payloads:
            fields = {f.field for v in decision.verdicts for f in v.findings if f.field}
            if not (fields and fields & unaddressable_fields(ctx.payload)):
                redacted = redacted_text(ctx, decision.verdicts)
        await audit.record_decision(ctx, decision, redacted_payload=redacted)
    replay = getattr(app.state, "replay_buffer", None)
    if replay is not None:
        replay.add(ctx, decision)
    if commit:
        await commit_decision(app, ctx, decision)
    return ctx, decision
