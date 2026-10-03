"""Control plugin interface and registry.

A control family lives in `acl/controls/<family>/` and registers one or more classes:

    from acl.controls.base import Control, register_control

    class PiiParams(BaseModel):
        entities: list[str] = []

    @register_control
    class PiiControl(Control):
        type = "pii"
        phase = Phase.deterministic
        Params = PiiParams

        async def inspect(self, ctx: InspectionContext) -> Verdict:
            ...
            return self.verdict(action=Action.pseudonymise, rule_ids=[self.id], findings=[...])

Controls read the policy they were built with via `self.deps.get("policy")` (a per-engine child of the
app-wide ControlDeps) and preset settings via `self.preset_settings(ctx)`.

Each configured instance comes from a `ControlConfig` in policy (id, stages, cost_tier,
fail_mode, timeout_ms, params). Controls MUST:
  * be side-effect free on the context (return data in the Verdict; use `outputs` for
    in-process data later phases need, e.g. normalised text);
  * never put raw sensitive values into `reason`, `findings` or logs;
  * be safe to run concurrently with other controls of the same phase.
"""

from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from acl.contracts.common import Action, FailMode, Phase, PolicyMode
from acl.contracts.decision import Decision, Verdict
from acl.contracts.inspection import InspectionContext
from acl.policy.models import ControlConfig


class EmptyParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ControlDeps:
    """Service locator handed to controls at build time (vault, session store, feed, clock, ...).

    Phase 0 keeps this deliberately loose; services are attached by the app at startup:
    `deps.register("vault", vault)` / `deps.get("vault")`.
    """

    def __init__(self, **services: Any) -> None:
        self._services: dict[str, Any] = dict(services)

    def register(self, name: str, service: Any) -> None:
        self._services[name] = service

    def get(self, name: str, default: Any = None) -> Any:
        return self._services.get(name, default)

    def child(self, **extra: Any) -> ControlDeps:
        """Per-engine view: same services plus build-specific ones (e.g. `policy`)."""
        return ControlDeps(**{**self._services, **extra})

    def require(self, name: str) -> Any:
        try:
            return self._services[name]
        except KeyError as exc:  # pragma: no cover - wiring error
            raise RuntimeError(f"control dependency {name!r} is not registered") from exc


class Control(ABC):
    type: ClassVar[str]
    phase: ClassVar[Phase] = Phase.deterministic
    Params: ClassVar[type[BaseModel]] = EmptyParams

    def __init__(self, config: ControlConfig, params: BaseModel, deps: ControlDeps) -> None:
        self.config = config
        self.params = params
        self.deps = deps

    # ------------------------------------------------------------ identity

    @property
    def id(self) -> str:
        return self.config.id

    @property
    def timeout_s(self) -> float:
        return self.config.timeout_ms / 1000.0

    def effective_fail_mode(self, default: FailMode) -> FailMode:
        return self.config.fail_mode or default

    def applies(self, ctx: InspectionContext) -> bool:
        if not self.config.enabled or ctx.point not in self.config.stages:
            return False
        return self.config.presets is None or ctx.preset in self.config.presets

    def preset_settings(self, ctx: InspectionContext) -> Any:
        """`PresetSettings` for the context's preset from the engine's policy (None if unavailable)."""
        policy = self.deps.get("policy")
        return policy.presets.get(ctx.preset) if policy is not None else None

    @property
    def shadow(self) -> bool:
        return self.config.mode == PolicyMode.monitor

    # ------------------------------------------------------------ behaviour

    @abstractmethod
    async def inspect(self, ctx: InspectionContext) -> Verdict:
        """Inspect the context and return a verdict. Must not mutate `ctx`."""

    async def commit(self, ctx: InspectionContext, decision: Decision) -> None:  # noqa: B027 - optional hook
        """Apply state changes (budgets, taint, counters) AFTER the decision is enforced.

        Called by the request flow only for real traffic, never for dry-run/replay. `inspect()`
        must stay side-effect free so that dry-run can re-evaluate stored traffic safely.
        """

    async def aclose(self) -> None:  # noqa: B027 - optional hook
        """Release resources (models, connections) on policy swap / shutdown."""

    def verdict(self, **kwargs: Any) -> Verdict:
        """Verdict pre-filled with this control's identity; applies the configured action override."""
        kwargs.setdefault("control_id", self.id)
        kwargs.setdefault("control_type", self.type)
        kwargs.setdefault("phase", self.phase)
        kwargs.setdefault("cost_tier", self.config.cost_tier)
        kwargs.setdefault("taxonomy", self.config.taxonomy)
        action = kwargs.get("action", Action.allow)
        if self.config.action is not None and action not in (Action.allow, Action.monitor):
            kwargs["action"] = self.config.action
        return Verdict(**kwargs)


class UnknownControlType(KeyError):
    pass


class ControlRegistry:
    def __init__(self) -> None:
        self._types: dict[str, type[Control]] = {}

    def register(self, cls: type[Control]) -> type[Control]:
        name = getattr(cls, "type", None)
        if not name:
            raise ValueError(f"{cls.__name__} must define a non-empty `type`")
        existing = self._types.get(name)
        if existing is not None and existing is not cls:
            raise ValueError(f"control type {name!r} already registered by {existing.__name__}")
        self._types[name] = cls
        return cls

    def get(self, type_name: str) -> type[Control]:
        try:
            return self._types[type_name]
        except KeyError as exc:
            raise UnknownControlType(type_name) from exc

    def types(self) -> list[str]:
        return sorted(self._types)

    def build(self, config: ControlConfig, deps: ControlDeps) -> Control:
        cls = self.get(config.type)
        params = cls.Params.model_validate(config.params)
        return cls(config, params, deps)


registry = ControlRegistry()


def register_control(cls: type[Control]) -> type[Control]:
    return registry.register(cls)


def load_builtin_controls() -> list[str]:
    """Import every `acl.controls.<family>` package so its controls self-register."""
    import acl.controls as pkg

    for mod in pkgutil.iter_modules(pkg.__path__):
        if mod.name != "base":
            importlib.import_module(f"{pkg.__name__}.{mod.name}")
    return registry.types()
