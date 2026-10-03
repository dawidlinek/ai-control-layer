"""Shared helpers for the Phase 2B tests (tool policy, taint / Rule of Two, approvals, /v1/decide)."""

from __future__ import annotations

from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

from acl.contracts.common import InspectionPoint, Preset
from acl.contracts.decision import Decision
from acl.contracts.inspection import SessionState
from acl.controls.base import ControlDeps
from acl.engine.engine import Engine
from acl.identity.access import DefaultAccessResolver
from acl.policy.loader import LoadedPolicy, load_policy_dir
from acl.policy.models import Policy
from acl.sessions.store import InMemorySessionStore
from acl.testing import make_context, make_principal

POLICY_DIR = Path(__file__).resolve().parents[4] / "policy"
WORKSPACE = "/work/proj"
CORE = ("SEC-TOOL-01", "SEC-FLOW-01", "SEC-TAINT-01")


@lru_cache(maxsize=1)
def loaded() -> LoadedPolicy:
    return load_policy_dir(POLICY_DIR)


def policy_with(only: Iterable[str] | None = CORE, *, patch_tools: dict[str, dict[str, Any]] | None = None) -> Policy:
    """The seed policy with only the given controls enabled (None = leave as is) and optional tool overrides."""
    pol = loaded().policy
    if only is not None:
        keep = set(only)
        pol = pol.model_copy(
            update={"controls": [c.model_copy(update={"enabled": c.id in keep}) for c in pol.controls]}
        )
    if patch_tools:
        tools = dict(pol.tools)
        for tid, patch in patch_tools.items():
            tools[tid] = tools[tid].model_copy(update=patch)
        pol = pol.model_copy(update={"tools": tools})
    return pol


def build_engine(
    only: Iterable[str] | None = CORE,
    *,
    policy: Policy | None = None,
    extra_deps: dict[str, Any] | None = None,
    sessions: InMemorySessionStore | None = None,
) -> Engine:
    pol = policy or policy_with(only)
    version = loaded().version
    deps = ControlDeps(
        access=DefaultAccessResolver(lambda: (pol, version)),
        sessions=sessions or InMemorySessionStore(),
        **(extra_deps or {}),
    )
    return Engine.build(pol, version, deps=deps)


def tool_ctx(
    tool: str,
    arguments: dict[str, Any] | None = None,
    *,
    groups: list[str] | None = None,
    preset: Preset = Preset.balanced,
    session: SessionState | dict[str, Any] | None = None,
    username: str = "anna",
    session_id: str = "sess-1",
    root: str | None = WORKSPACE,
    attributes: dict[str, Any] | None = None,
    point: InspectionPoint = InspectionPoint.tool_call,
    data: Any = None,
):
    if isinstance(session, dict):
        session = SessionState(session_id=session_id, **session)
    payload = (
        data if data is not None else {"tool": tool, "arguments": arguments or {}, "workspace_root": root, "cwd": root}
    )
    return make_context(
        payload,
        point=point,
        preset=preset,
        principal=make_principal(username, groups if groups is not None else ["developers"]),
        session=session or SessionState(session_id=session_id),
        session_id=session_id,
        attributes=attributes or {},
    )


async def decide(engine: Engine, tool: str, arguments: dict[str, Any] | None = None, **kw: Any) -> Decision:
    return await engine.evaluate(tool_ctx(tool, arguments, **kw))


TOXIC = {
    "labels": {
        "integrity": "untrusted",
        "confidentiality": "confidential",
        "taint": ["untrusted", "sensitive"],
    }
}
UNTRUSTED = {"labels": {"integrity": "untrusted", "taint": ["untrusted"]}}
SENSITIVE = {"labels": {"confidentiality": "confidential", "taint": ["sensitive"]}}
