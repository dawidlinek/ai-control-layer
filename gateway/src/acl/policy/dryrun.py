"""Dry-run replay (concept §11.1): re-evaluate the last N stored requests against a candidate policy.

The candidate is the current files overlaid with the request's files, compiled into a throw-away Engine
(`app.state.build_engine`). Only `Engine.evaluate` is called (side-effect free); `commit` never is.
Contexts come from `app.state.replay_buffer.recent(n, point)` and are deep-copied before evaluation.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections import Counter
from typing import TYPE_CHECKING, Any

from acl.contracts.admin import DryRunChange, DryRunRequest, DryRunResponse, PolicyError
from acl.contracts.common import Preset
from acl.contracts.decision import Decision
from acl.contracts.inspection import InspectionContext
from acl.policy.errors import InvalidFileName, LockedControl, ValidationFailed
from acl.policy.loader import compute_version
from acl.policy.models import Policy

if TYPE_CHECKING:
    from acl.policy.service import PolicyService

log = logging.getLogger(__name__)

_PRESET_RANK = {p: i for i, p in enumerate((Preset.monitor, Preset.balanced, Preset.strict, Preset.paranoid))}


def resolve_preset(policy: Policy, groups: list[str]) -> Preset:
    """Strictest group preset, else the global default (mirrors how a request's preset is derived)."""
    found = [gp.preset for g in groups if (gp := policy.groups.get(g)) is not None and gp.preset is not None]
    return max(found, key=_PRESET_RANK.__getitem__) if found else policy.global_.default_preset


def rebase_context(ctx: InspectionContext, current: Policy | None, candidate: Policy) -> InspectionContext:
    """Copy of `ctx` whose policy-derived fields (preset, mode) follow the candidate policy.

    A field is only re-derived if it equals what the *current* policy would have derived for this principal;
    values set another way (explicit per-request overrides) are left alone."""
    copy = ctx.model_copy(deep=True)
    if current is None:
        return copy
    if copy.preset == resolve_preset(current, copy.principal.groups):
        copy.preset = resolve_preset(candidate, copy.principal.groups)
    if copy.mode == current.global_.mode:
        copy.mode = candidate.global_.mode
    return copy


async def _recent(buffer: Any, n: int, point: Any) -> list[tuple[InspectionContext, Decision]]:
    got = buffer.recent(n, point=point)
    if inspect.isawaitable(got):
        got = await got
    return list(got)


async def run_dry_run(service: PolicyService, req: DryRunRequest) -> DryRunResponse:
    try:
        texts = service.candidate_texts(req.files)
    except InvalidFileName as exc:
        return DryRunResponse(
            candidate_version="", evaluated=0, changed=0, errors=[PolicyError(file=exc.name, message=exc.message)]
        )
    version = compute_version(texts)
    try:
        compiled = await service.compile_candidate(texts)
    except ValidationFailed as exc:
        return DryRunResponse(candidate_version=version, evaluated=0, changed=0, errors=exc.errors)
    except LockedControl as exc:
        errors = [PolicyError(path=f"controls.{v.control_id}", message=str(exc.message)) for v in exc.violations]
        return DryRunResponse(candidate_version=version, evaluated=0, changed=0, errors=errors)

    try:
        buffer = getattr(service.app.state, "replay_buffer", None)
        if buffer is None:
            return DryRunResponse(
                candidate_version=version,
                evaluated=0,
                changed=0,
                errors=[PolicyError(message="no stored requests are available to replay (replay buffer missing)")],
            )
        stored = await _recent(buffer, req.last_n, req.point)
        current = service.loaded.policy if service.loaded else None
        sem = asyncio.Semaphore(max(1, service.options.dry_run_concurrency))

        async def one(ctx: InspectionContext, before: Decision) -> tuple[InspectionContext, Decision, Decision] | None:
            async with sem:
                try:
                    after = await compiled.engine.evaluate(rebase_context(ctx, current, compiled.policy))
                except Exception:
                    log.exception("dry-run evaluation failed for one stored request")
                    return None
                return ctx, before, after

        results = [r for r in await asyncio.gather(*(one(c, d) for c, d in stored)) if r is not None]
    finally:
        await compiled.discard()

    transitions: Counter[str] = Counter()
    samples: list[DryRunChange] = []
    changed = 0
    for ctx, before, after in results:
        if before.action == after.action and sorted(before.rule_ids) == sorted(after.rule_ids):
            continue
        changed += 1
        transitions[f"{before.action.value}->{after.action.value}"] += 1
        if len(samples) < service.options.dry_run_samples:
            samples.append(
                DryRunChange(
                    event_id=before.decision_id,
                    timestamp=ctx.timestamp,
                    subject=ctx.principal.username or ctx.principal.subject,
                    before_action=before.action,
                    after_action=after.action,
                    before_rule_ids=list(before.rule_ids),
                    after_rule_ids=list(after.rule_ids),
                )
            )
    return DryRunResponse(
        candidate_version=version,
        evaluated=len(results),
        changed=changed,
        transitions=dict(sorted(transitions.items(), key=lambda kv: -kv[1])),
        samples=samples,
    )
