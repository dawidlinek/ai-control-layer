"""Permissive access resolver, used ONLY when the app runs with `allow_anonymous_dev=True` (tests)
and no real `app.state.access` was installed by the identity package.

Everything in the policy is allowed; every model accepts the data classes it declares, minus the
org locks (so routing behaves like production for data-class ceilings).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from acl.contracts.common import ConnectorTier, DataClass, Preset
from acl.contracts.inspection import Principal
from acl.policy.models import DataClassTierLock, Policy


@dataclass(frozen=True)
class DevAccessCheck:
    allowed: bool
    rule_id: str | None = None
    reason: str = "dev: allowed"
    source: str = "dev"


class PermissiveAccess:
    def __init__(self, policy_getter: Callable[[], Policy | None]) -> None:
        self._policy = policy_getter

    def _p(self) -> Policy:
        policy = self._policy()
        if policy is None:  # pragma: no cover - engine missing is handled earlier
            raise RuntimeError("no policy loaded")
        return policy

    async def check_model(self, principal: Principal, name: str) -> DevAccessCheck:
        return DevAccessCheck(True)

    async def usable_models(self, principal: Principal) -> dict[str, list[DataClass]]:
        policy = self._p()
        out: dict[str, list[DataClass]] = {}
        for m in policy.models:
            tier: ConnectorTier = policy.connectors[m.connector].tier
            allowed = []
            for dc in m.data_classes:
                locked = any(
                    isinstance(lock, DataClassTierLock) and dc in lock.data_classes and tier not in lock.allowed_tiers
                    for lock in policy.org_locks
                )
                if not locked:
                    allowed.append(dc)
            out[m.id] = allowed
        return out

    async def visible_names(self, principal: Principal) -> list[str]:
        policy = self._p()
        return sorted({m.id for m in policy.models} | policy.alias_names() | set(policy.skills))

    async def effective_preset(self, principal: Principal) -> Preset:
        return self._p().global_.default_preset

    async def effective_access(self, principal: Principal):  # type: ignore[no-untyped-def]
        raise NotImplementedError("dev access resolver has no effective-access view")

    async def check_tool(self, principal: Principal, tool_id: str) -> DevAccessCheck:
        return DevAccessCheck(True)
