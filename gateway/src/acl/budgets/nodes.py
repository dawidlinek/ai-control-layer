"""Budget hierarchy: which nodes a principal's request touches and which limits each node carries.

    org → group(s) → user → agent → session

`*_session` limits are defined on org/group/user/agent nodes but apply to every session below them: the
counters live on the session node (a breaker for such a limit trips the session, not the whole group).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from acl.contracts.inspection import Principal
from acl.policy.models import BudgetLimits, Policy

LEVELS = ("org", "group", "user", "agent", "session")
RPM = "requests_per_minute"


@dataclass(frozen=True)
class NodeSpec:
    id: str
    level: str
    parent: str | None
    limits: Mapping[str, float] = field(default_factory=dict)


def split_meter(meter: str) -> tuple[str, str]:
    """`gpu_seconds_day` → (`gpu_seconds`, `day`)."""
    base, _, window = meter.rpartition("_")
    return base, window


def limits_dict(limits: BudgetLimits | None) -> dict[str, float]:
    if limits is None:
        return {}
    return {k: float(v) for k, v in limits.model_dump(exclude_none=True).items()}


def user_name(principal: Principal) -> str:
    return principal.username or principal.subject


def node_specs(policy: Policy, principal: Principal, session_id: str) -> list[NodeSpec]:
    """Every node a request of `principal` in `session_id` is accounted against (org first, session last)."""
    budgets = policy.budgets
    specs = [NodeSpec("org", "org", None, limits_dict(budgets.org))]
    parent = "org"
    seen: set[str] = set()
    for group in principal.groups:
        if group in seen:
            continue
        seen.add(group)
        limits = limits_dict(budgets.groups.get(group))
        gp = policy.groups.get(group)
        if RPM not in limits and gp is not None and gp.limits is not None and gp.limits.requests_per_minute:
            limits[RPM] = float(gp.limits.requests_per_minute)
        specs.append(NodeSpec(f"group:{group}", "group", "org", limits))
        parent = f"group:{group}"
    name = user_name(principal)
    user_limits = limits_dict(budgets.default_user)
    user_limits.update(limits_dict(budgets.users.get(name)))
    specs.append(NodeSpec(f"user:{name}", "user", parent, user_limits))
    parent = f"user:{name}"
    if principal.agent_id:
        specs.append(
            NodeSpec(
                f"agent:{principal.agent_id}", "agent", parent, limits_dict(budgets.agents.get(principal.agent_id))
            )
        )
        parent = f"agent:{principal.agent_id}"
    specs.append(NodeSpec(f"session:{session_id}", "session", parent, {}))
    return specs
