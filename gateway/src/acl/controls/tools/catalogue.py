"""Tool catalogue helpers shared by SEC-TOOL-01, SEC-FLOW-01 and SEC-TAINT-01.

* `effective_grant`: which tier / constraints apply to this principal for a tool, merged over every group the
  principal inherits from (`a/b/c` → `a/b/c`, `a/b`, `a`). Merge rules (always the safe direction):
    - tier: strictest across the granting groups (deny > confirm > must > allow); a group that sets
      `tier: deny` simply does not grant the tool (see `acl.identity.access`);
    - `path_deny`: union; `path_allow` / `recipients_allow` / `domains_allow`: union, but only when EVERY granting
      group restricts (one unrestricted grant makes the tool unrestricted in that dimension, grants are additive);
* `resolve_tool_id`: map the function name a client uses for a tool (`bash`, `files_read_file`, `files.read_file`)
  to a catalogue id; ambiguous or unknown names resolve to None.
* `tool_labels` / `is_sink`: IFC labels of a catalogue tool.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from acl.contracts.common import Action, Capability, ToolLabel, ToolTier
from acl.contracts.decision import Decision
from acl.contracts.inspection import InspectionContext, SessionState
from acl.identity.access import expand_groups
from acl.policy.models import Policy, ToolDef, ToolGrant

TIER_RANK = {ToolTier.allow: 0, ToolTier.must: 1, ToolTier.confirm: 2, ToolTier.deny: 3}


@dataclass(frozen=True)
class EffectiveGrant:
    tier: ToolTier
    tier_source: str  # "default" | "group:<name>"
    groups: tuple[str, ...]  # groups that list the tool (and do not deny it)
    explicit: bool  # the tool is listed in at least one of the principal's groups
    path_allow: tuple[str, ...] = ()
    path_deny: tuple[str, ...] = ()
    recipients_allow: tuple[str, ...] = ()
    domains_allow: tuple[str, ...] = ()


def _union_if_all(grants: list[ToolGrant], attr: str) -> tuple[str, ...]:
    lists = [getattr(g, attr) for g in grants]
    if not lists or any(not lst for lst in lists):
        return ()
    return tuple(dict.fromkeys(x for lst in lists for x in lst))


def effective_grant(policy: Policy, groups: Iterable[str], tool_id: str, tool: ToolDef) -> EffectiveGrant:
    granting: list[tuple[str, ToolGrant]] = []
    for g in expand_groups(groups):
        gp = policy.groups.get(g)  # type: ignore[call-overload]
        tg = gp.tools.get(tool_id) if gp is not None else None
        if tg is None or tg.tier == ToolTier.deny:
            continue
        granting.append((g, tg))
    if granting:
        tiers = [(tg.tier or tool.default_tier, g) for g, tg in granting]
        tier, src = max(tiers, key=lambda t: TIER_RANK[t[0]])
        source = f"group:{src}" if any(tg.tier is not None for _, tg in granting) else "default"
    else:
        tier, source = tool.default_tier, "default"
    grants = [tg for _, tg in granting]
    return EffectiveGrant(
        tier=tier,
        tier_source=source,
        groups=tuple(g for g, _ in granting),
        explicit=bool(granting),
        path_allow=_union_if_all(grants, "path_allow"),
        path_deny=tuple(dict.fromkeys(x for tg in grants for x in tg.path_deny)),
        recipients_allow=_union_if_all(grants, "recipients_allow"),
        domains_allow=_union_if_all(grants, "domains_allow"),
    )


def tool_labels(tool: ToolDef | None) -> frozenset[ToolLabel]:
    return frozenset(tool.labels) if tool is not None else frozenset()


def is_write_tool(tool: ToolDef) -> bool:
    """`approval_on_writes` set: irreversible tools and tools whose path checker declares `access: write`."""
    if ToolLabel.irreversible in tool.labels:
        return True
    return any(c.type == "path" and str(c.params.get("access", "")).lower() == "write" for c in tool.checkers)


def is_sink_tool(tool: ToolDef | None) -> bool:
    """Unknown tools count as sinks (fail safe); known tools by their `external_egress` label."""
    return tool is None or ToolLabel.external_egress in tool.labels


def downgrade_safe(tool: ToolDef) -> bool:
    """May stay in `allowed_tools` after a `downgrade`: no irreversible/external-egress label and no exec/network."""
    if ToolLabel.irreversible in tool.labels or ToolLabel.external_egress in tool.labels:
        return False
    return not ({Capability.exec, Capability.network} & set(tool.capabilities))


def narrowed_tools(policy: Policy, current: list[str] | None) -> list[str]:
    """Tool set after a `downgrade`: intersection with what is already allowed (never widens)."""
    safe = sorted(tid for tid, t in policy.tools.items() if downgrade_safe(t))
    if current is None:
        return safe
    return [t for t in safe if t in set(current)]


async def apply_downgrade(deps: Any, ctx: InspectionContext, decision: Decision) -> None:
    """`downgrade` was enforced: narrow `allowed_tools` to downgrade-safe tools for the rest of the session.

    Idempotent and monotonic (intersection with whatever is already allowed), so SEC-TOOL-01 and SEC-TAINT-01 can both
    call it from `commit()`; never widens.
    """
    if Action.downgrade not in decision.applied and decision.action != Action.downgrade:
        return
    sessions, policy = deps.get("sessions"), deps.get("policy")
    if sessions is None or policy is None:
        return

    def narrow(state: SessionState) -> SessionState:
        return state.model_copy(
            update={"allowed_tools": narrowed_tools(policy, state.allowed_tools), "downgraded": True}
        )

    await sessions.update(ctx.session_id, narrow)


class ToolNames:
    """Client function name → catalogue tool id (built once per policy)."""

    def __init__(self, policy: Policy) -> None:
        owners: dict[str, set[str]] = {}

        def add(alias: str | None, tid: str) -> None:
            if alias:
                owners.setdefault(alias.lower(), set()).add(tid)

        for tid, t in policy.tools.items():
            add(tid, tid)
            add(tid.replace(".", "_"), tid)
            add(tid.replace(".", "__"), tid)
            add(tid.replace(".", "-"), tid)
            if tid.startswith("opencode."):
                add(tid.removeprefix("opencode."), tid)
            if t.server and t.name:
                for sep in (".", "_", "__", "-"):
                    add(f"{t.server}{sep}{t.name}", tid)
        self._map = {a: next(iter(ids)) for a, ids in owners.items() if len(ids) == 1}

    def resolve(self, name: str | None) -> str | None:
        return self._map.get(name.strip().lower()) if name else None
