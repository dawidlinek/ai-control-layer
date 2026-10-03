"""Minimal router (Phase 3B extends it with specialists, complexity bands and budgets).

Resolution of the requested name:
    model id                         → that model
    alias declared on a model        → that model
    `aliases[x]` strategy `fixed`    → its target
    `aliases[x]` auto/rules          → data class → routing.data_class_sensitivity → routing.sensitivity:
                                       local_only → targets.local; otherwise targets.ext_small if the
                                       principal may use it for this data class, else targets.local
    `skill/<x>`                      → the skill's model (template handling is Phase 3B)

Then, in order:
    1. `route_local` / `downgrade` obligations force the local target;
    2. a choice whose allowed data classes for this principal (`access.usable_models`, i.e.
       model ∩ grants ∩ org locks) lack the request's data class falls back to `targets.local`, and the
       reason cites the org lock (e.g. LOCK-01). Presets whose `sensitive_external_action` is `block`
       refuse instead;
    3. a disabled / killed / unavailable connector or model falls back to `targets.degraded`
       (`degraded=True`), but only if the fallback honours the same obligations: data class usable,
       no org lock, and a LOCAL model whenever the request must stay local (route_local/downgrade,
       confidential/restricted data, `local_only` sensitivity) or was routed to a local model. Otherwise
       503 (`route`) / no failover (`degraded_route`); data is never sent to a cloud model instead.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from acl.budgets.signal import budget_exhausted_reason
from acl.contracts.common import DATA_CLASS_ORDER, Action, ConnectorTier, DataClass
from acl.contracts.decision import RouteInfo
from acl.policy.models import DataClassTierLock, ModelEntry, Policy
from acl.routing.connectors.base import Connector
from acl.routing.registry import RoutingTable


class RouteError(Exception):
    """Routing cannot proceed. `status` 403 → policy denial (audited as a block); 404/400/503 otherwise."""

    def __init__(self, message: str, *, status: int, code: str, rule_id: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.rule_id = rule_id


@dataclass
class RouteRequest:
    requested: str
    data_class: DataClass = DataClass.public
    usable: Mapping[str, Sequence[DataClass]] = field(default_factory=dict)
    force_local: bool = False
    force_reason: str = ""
    capability: str = "chat"
    sensitive_external_action: Action = Action.route_local
    budget_exhausted: str | None = None
    """Why the cloud budget is spent (SEC-BUDGET-01 `route_local`). When unset the router falls back to the
    request-scoped signal of `acl.budgets.signal`; the chat flow may fill this field directly."""


@dataclass
class Route:
    info: RouteInfo
    model: ModelEntry
    connector: Connector
    upstream_model: str


def max_data_class(classes: Sequence[DataClass | None]) -> DataClass:
    best = DataClass.public
    for c in classes:
        if c is not None and DATA_CLASS_ORDER[c] > DATA_CLASS_ORDER[best]:
            best = c
    return best


class Router:
    def __init__(self, policy: Policy, table: RoutingTable) -> None:
        self.policy = policy
        self.table = table
        self._models = policy.model_by_id()
        self._alias_owner = {a: m.id for m in policy.models for a in m.aliases}

    # ------------------------------------------------------------ name resolution

    def _ref(self, ref: str) -> str | None:
        """A model id, a model alias, or a `fixed` alias → concrete model id."""
        if ref in self._models:
            return ref
        if ref in self._alias_owner:
            return self._alias_owner[ref]
        alias = self.policy.aliases.get(ref)
        if alias is not None and alias.strategy == "fixed":
            return alias.target
        return None

    def _tier(self, model_id: str) -> ConnectorTier:
        return self.policy.connectors[self._models[model_id].connector].tier

    def _lock_for(self, model_id: str, data_class: DataClass) -> str | None:
        """Id of the org lock that forbids this data class on the model's connector tier."""
        tier = self._tier(model_id)
        for lock in self.policy.org_locks:
            if (
                isinstance(lock, DataClassTierLock)
                and data_class in lock.data_classes
                and tier not in lock.allowed_tiers
            ):
                return lock.id
        return None

    def _requires_local(self, req: RouteRequest) -> bool:
        """The request may only be served by a local model (route_local/downgrade, sensitivity, data class)."""
        if req.force_local or req.data_class in (DataClass.confidential, DataClass.restricted):
            return True
        sens = self.policy.routing.data_class_sensitivity.get(req.data_class, "low")
        return self.policy.routing.sensitivity.get(sens) == "local_only"

    def _fallback_refusal(self, fallback: str, primary: str, req: RouteRequest) -> str | None:
        """Why the degraded target may NOT serve this request (None = permitted).

        The failover path honours exactly the obligations of the primary path: a misconfigured
        `routing.targets.degraded` pointing at a cloud model must never receive local-only data.
        """
        if req.data_class not in req.usable.get(fallback, ()):
            return "the degraded target is not permitted for this principal/data class"
        if self._lock_for(fallback, req.data_class) is not None:
            return "the degraded target is forbidden for this data class by an org lock"
        if self._tier(fallback) != ConnectorTier.local:
            if self._requires_local(req):
                return "the degraded target is not local and this request must stay local"
            if self._tier(primary) == ConnectorTier.local:
                return "the request was routed to a local model and may not fail over to the cloud"
        return None

    def route(self, req: RouteRequest) -> Route:
        policy = self.policy
        targets = policy.routing.targets
        factors: dict[str, Any] = {"data_class": req.data_class.value}
        steps: list[str] = []
        requested = req.requested

        # -- 1. resolve the requested name
        name = requested
        skill = policy.skills.get(requested)
        if skill is not None:
            name = skill.model
            steps.append(f"skill {requested}")
            factors["skill"] = requested
        auto = False
        model_id = self._ref(name)
        if model_id is None:
            alias = policy.aliases.get(name)
            if alias is None:
                raise RouteError(f"model {requested!r} not found", status=404, code="model_not_found")
            auto = True
        if auto:
            local = self._ref(targets.local)
            sens = policy.routing.data_class_sensitivity.get(req.data_class, "low")
            rule = policy.routing.sensitivity.get(sens, "by_complexity")
            factors.update(sensitivity=sens, sensitivity_rule=rule)
            if rule == "local_only":
                model_id = local
                steps.append(f"{name} → {model_id}: data={req.data_class.value} → sensitivity {sens} → local_only")
            else:
                ext = self._ref(targets.ext_small)
                if ext is not None and req.data_class in req.usable.get(ext, ()):
                    model_id = ext
                    steps.append(f"{name} → {model_id}: data={req.data_class.value} → sensitivity {sens} → {rule}")
                else:
                    model_id = local
                    steps.append(
                        f"{name} → {model_id}: data={req.data_class.value}, "
                        f"{targets.ext_small} not usable for this principal/data class → local"
                    )
        elif name != requested or (name in self._alias_owner):
            steps.append(f"{requested} → {model_id}")
        assert model_id is not None
        factors["via"] = "auto" if auto else "direct"

        # -- 2a. budget exhausted (SEC-BUDGET-01 route_local): a degraded local route, never silent
        degraded = False
        exhausted = req.budget_exhausted or budget_exhausted_reason()
        if exhausted and self._tier(model_id) != ConnectorTier.local:
            local = self._ref(targets.local)
            if local is not None:
                steps.append(f"budget exhausted ({exhausted}) → degraded {local}")
                factors["budget_exhausted"] = exhausted
                degraded = True
                model_id = local

        # -- 2b. route_local / downgrade obligations
        if req.force_local and self._tier(model_id) != ConnectorTier.local:
            local = self._ref(targets.local)
            steps.append(f"{req.force_reason or 'route_local'} → {local}")
            factors["forced_local"] = True
            model_id = local or model_id

        # -- 3. data-class ceiling (model ∩ grants ∩ org locks)
        if req.data_class not in req.usable.get(model_id, ()):
            lock = self._lock_for(model_id, req.data_class)
            why = (
                f"org lock {lock} forbids {req.data_class.value} on {self._tier(model_id).value} connectors"
                if lock
                else f"{req.data_class.value} data is not allowed on {model_id} for this principal"
            )
            if req.sensitive_external_action == Action.block:
                raise RouteError(
                    f"{why}; sensitive data may not be sent to {model_id}",
                    status=403,
                    code="data_class_violation",
                    rule_id=lock or "SEC-MODEL-01",
                )
            local = self._ref(targets.local)
            if local is None or req.data_class not in req.usable.get(local, ()):
                raise RouteError(
                    f"{why}; no permitted local model for {req.data_class.value} data",
                    status=403,
                    code="no_permitted_model",
                    rule_id=lock or "SEC-MODEL-01",
                )
            steps.append(f"{why} → {local}")
            factors["lock"] = lock
            model_id = local

        # -- 4. availability → degraded fallback
        problem = self.table.model_problem(model_id)
        if problem is not None:
            fallback = self._ref(targets.degraded)
            if fallback is None or fallback == model_id or self.table.model_problem(fallback) is not None:
                raise RouteError(
                    f"{model_id} unavailable ({problem}) and no degraded fallback is available",
                    status=503,
                    code="service_unavailable",
                )
            refusal = self._fallback_refusal(fallback, model_id, req)
            if refusal is not None:
                raise RouteError(
                    f"{model_id} unavailable ({problem}) and {refusal}",
                    status=503,
                    code="service_unavailable",
                )
            steps.append(f"{model_id} unavailable ({problem}) → degraded {fallback}")
            factors["degraded_from"] = model_id
            degraded = True
            model_id = fallback

        entry = self._models[model_id]
        connector = self.table.connector_for(model_id)
        handle = self.table.models[model_id]
        if connector is None or handle.upstream_model is None:  # pragma: no cover - guarded by model_problem
            raise RouteError(f"{model_id} unavailable", status=503, code="service_unavailable")
        if req.capability not in entry.capabilities:
            raise RouteError(
                f"model {model_id} does not support {req.capability}", status=400, code="invalid_request_error"
            )
        reason = "; ".join(steps) if steps else f"{requested} (explicit)"
        return Route(
            info=RouteInfo(
                model_requested=requested,
                model=model_id,
                connector=entry.connector,
                tier=self._tier(model_id),
                reason=reason,
                degraded=degraded,
                factors=factors,
            ),
            model=entry,
            connector=connector,
            upstream_model=handle.upstream_model,
        )

    def degraded_route(self, current: Route, req: RouteRequest, why: str) -> Route | None:
        """Runtime fallback after an upstream failure (retryable errors only). None if not possible.

        Same obligations as `route()`: a request that must stay local never fails over to a cloud model.
        """
        targets = self.policy.routing.targets
        fallback = self._ref(targets.degraded)
        if (
            fallback is None
            or fallback == current.info.model
            or self.table.model_problem(fallback) is not None
            or self._fallback_refusal(fallback, current.info.model, req) is not None
        ):
            return None
        entry = self._models[fallback]
        connector = self.table.connector_for(fallback)
        handle = self.table.models[fallback]
        if connector is None or handle.upstream_model is None:
            return None
        info = current.info.model_copy(
            update={
                "model": fallback,
                "connector": entry.connector,
                "tier": self._tier(fallback),
                "degraded": True,
                "reason": f"{current.info.reason}; {current.info.model} failed ({why}) → degraded {fallback}",
            }
        )
        return Route(info=info, model=entry, connector=connector, upstream_model=handle.upstream_model)
