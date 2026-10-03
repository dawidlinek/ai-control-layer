"""Compile step: texts -> validated `Policy` -> built `Engine` (never partially applied).

validate (YAML syntax, `PolicyDocument`, merge, `Policy` cross-references)
  -> every *enabled* control's `type` is registered and its `params` validate against its `Params` model
  -> `build_engine(policy, version)` succeeds.
Any failure raises `PolicyLoadError` with located `PolicyError`s; the caller keeps the last good engine.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import ValidationError

from acl.contracts.admin import PolicyError
from acl.controls.base import ControlRegistry, UnknownControlType, load_builtin_controls, registry
from acl.engine.engine import Engine
from acl.policy.loader import LoadedPolicy, PolicyLoadError, parse_documents
from acl.policy.models import Policy
from acl.policy.yamledit import Locator

log = logging.getLogger(__name__)

BuildEngine = Callable[[Policy, str], Engine]


@dataclass
class Compiled:
    loaded: LoadedPolicy
    engine: Engine

    @property
    def policy(self) -> Policy:
        return self.loaded.policy

    @property
    def version(self) -> str:
        return self.loaded.version

    async def discard(self) -> None:
        """Release a compiled engine that was never swapped in (validate / dry-run / rejected writes)."""
        try:
            await self.engine.aclose()
        except Exception:  # pragma: no cover - defensive
            log.exception("closing discarded engine failed")


def check_controls(
    loaded: LoadedPolicy, texts: dict[str, str], control_registry: ControlRegistry = registry
) -> list[PolicyError]:
    """Registered type + valid params for every enabled control, located in the defining file."""
    file = loaded.sections.get("controls")
    locator = Locator(texts[file]) if file in texts else None
    errors: list[PolicyError] = []

    def add(idx: int, tail: tuple[str, ...], message: str) -> None:
        loc: tuple[str | int, ...] = ("controls", idx, *tail)
        pos = locator.locate(loc) if locator else None
        errors.append(
            PolicyError(
                file=file,
                path=".".join(str(p) for p in loc),
                line=pos[0] if pos else None,
                column=pos[1] if pos else None,
                message=message,
            )
        )

    for idx, control in enumerate(loaded.policy.controls):
        if not control.enabled:
            continue
        try:
            cls = control_registry.get(control.type)
        except UnknownControlType:
            known = ", ".join(control_registry.types()) or "none"
            add(idx, ("type",), f"control {control.id}: unknown type {control.type!r} (registered: {known})")
            continue
        try:
            cls.Params.model_validate(control.params)
        except ValidationError as exc:
            for e in exc.errors():
                where = ".".join(str(p) for p in e["loc"])
                add(idx, ("params", *map(str, e["loc"])), f"control {control.id}: params.{where}: {e['msg']}")
    return errors


def compile_texts(
    texts: dict[str, str],
    build_engine: BuildEngine,
    control_registry: ControlRegistry = registry,
    *,
    load_builtins: bool = True,
) -> Compiled:
    if load_builtins:
        load_builtin_controls()
    loaded = parse_documents(texts)
    errors = check_controls(loaded, texts, control_registry)
    if errors:
        raise PolicyLoadError(errors)
    try:
        engine = build_engine(loaded.policy, loaded.version)
    except Exception as exc:
        # Control constructors must not put raw values in exceptions (CLAUDE.md rule 2); keep it short anyway.
        log.exception("engine build failed for policy %s", loaded.version)
        raise PolicyLoadError(
            [
                PolicyError(
                    file=loaded.sections.get("controls"),
                    message=f"engine build failed: {type(exc).__name__}: {str(exc)[:200]}",
                )
            ]
        ) from exc
    return Compiled(loaded=loaded, engine=engine)
