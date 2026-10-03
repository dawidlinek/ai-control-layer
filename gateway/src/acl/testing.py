"""Test helpers shipped with the package (used by gateway unit tests and the system test harness)."""

from __future__ import annotations

import uuid
from typing import Any

from acl.contracts.common import AuthMethod, InspectionPoint, PolicyMode, Preset, PrincipalKind, Versions
from acl.contracts.inspection import (
    ChatMessage,
    ChatPayload,
    CompletionPayload,
    InspectionContext,
    Payload,
    Principal,
    SessionState,
    ToolCallPayload,
    ToolResultPayload,
)


def make_principal(username: str = "anna", groups: list[str] | None = None, **kw: Any) -> Principal:
    return Principal(
        subject=kw.pop("subject", f"sub-{username}"),
        kind=kw.pop("kind", PrincipalKind.user),
        username=username,
        groups=groups if groups is not None else ["developers"],
        auth_method=kw.pop("auth_method", AuthMethod.jwt),
        **kw,
    )


def make_payload(point: InspectionPoint, data: Any) -> Payload:
    """Build a payload from a short-hand: str → text for the point; dict → payload fields."""
    if point in (InspectionPoint.ingress, InspectionPoint.embeddings, InspectionPoint.agent_message):
        if isinstance(data, str):
            return ChatPayload(messages=[ChatMessage(role="user", content=data)])
        return ChatPayload.model_validate(data)
    if point == InspectionPoint.egress:
        return CompletionPayload(content=data) if isinstance(data, str) else CompletionPayload.model_validate(data)
    if point == InspectionPoint.tool_call:
        return ToolCallPayload.model_validate(data)
    if point == InspectionPoint.tool_result:
        return ToolResultPayload.model_validate(data)
    raise ValueError(f"no shorthand payload for {point}")


def make_context(
    data: Any = "hello",
    *,
    point: InspectionPoint = InspectionPoint.ingress,
    principal: Principal | None = None,
    preset: Preset = Preset.balanced,
    mode: PolicyMode = PolicyMode.enforce,
    session_id: str | None = None,
    policy_version: str = "test",
    model_requested: str | None = "auto",
    **kw: Any,
) -> InspectionContext:
    sid = session_id or f"sess-{uuid.uuid4().hex[:8]}"
    return InspectionContext(
        trace_id=f"tr-{uuid.uuid4().hex[:12]}",
        request_id=f"req-{uuid.uuid4().hex[:12]}",
        session_id=sid,
        point=point,
        principal=principal or make_principal(),
        preset=preset,
        mode=mode,
        model_requested=model_requested,
        payload=make_payload(point, data),
        session=kw.pop("session", None) or SessionState(session_id=sid),
        versions=Versions(policy=policy_version),
        **kw,
    )
