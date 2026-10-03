"""Decision pipeline: run applicable controls phase by phase, then compose a Decision.

Mechanics (concept §6.2):
  * phases run in PHASE_ORDER; controls within a phase run concurrently (asyncio.gather);
  * each control has its own timeout; errors/timeouts follow the control's fail mode;
  * a final (deterministic) block exits early;
  * `Verdict.outputs` of a phase are merged into `ctx.attributes` before the next phase.

Verdicts of controls with `cacheable = True` are cached by content hash (`acl.engine.cache`).
No L2 escalation band and no risk scoring yet (Phase 2B / 3A extend this module and `acl.engine.decide`).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Iterable, Mapping

from acl.contracts.common import PHASE_ORDER, Action, CostTier, FailMode, Preset, VerdictStatus
from acl.contracts.decision import Decision, Verdict
from acl.contracts.inspection import InspectionContext
from acl.controls.base import Control
from acl.engine.cache import VerdictCache, payload_digest
from acl.engine.decide import compose_decision
from acl.policy.models import GlobalSettings, PresetSettings

log = logging.getLogger(__name__)


def _default_fail_mode(settings: GlobalSettings, tier: CostTier) -> FailMode:
    if tier == CostTier.deterministic:
        return settings.fail_mode.deterministic
    return settings.fail_mode.semantic


class Pipeline:
    def __init__(
        self,
        controls: Iterable[Control],
        settings: GlobalSettings,
        presets: Mapping[Preset, PresetSettings] | None = None,
        *,
        policy_version: str = "",
        cache: VerdictCache | None = None,
    ) -> None:
        self.controls = list(controls)
        self.settings = settings
        self.presets = dict(presets or {})
        self.policy_version = policy_version
        self.cache = cache

    def applicable(self, ctx: InspectionContext) -> list[Control]:
        return [c for c in self.controls if c.applies(ctx)]

    async def run(self, ctx: InspectionContext) -> Decision:
        started = time.perf_counter()
        verdicts: list[Verdict] = []
        applicable = self.applicable(ctx)
        digest: list[str] = []  # computed lazily per phase (a normaliser may rewrite the payload)
        for phase in PHASE_ORDER:
            group = [c for c in applicable if c.phase == phase]
            if not group:
                continue
            digest.clear()
            results = await asyncio.gather(*(self._run_cached(c, ctx, digest) for c in group))
            verdicts.extend(results)
            for v in results:
                if v.outputs:
                    ctx.attributes.update(v.outputs)
            if any(v.final and v.action == Action.block for v in results):
                break
        return compose_decision(
            ctx,
            verdicts,
            self.settings,
            latency_ms=(time.perf_counter() - started) * 1000,
            shadow_controls=frozenset(c.id for c in applicable if c.shadow),
            never_block=bool((ps := self.presets.get(ctx.preset)) and ps.never_block),
        )

    async def _run_cached(self, control: Control, ctx: InspectionContext, digest: list[str]) -> Verdict:
        if self.cache is None or not control.cacheable:
            return await self._run_one(control, ctx)
        if not digest:
            digest.append(payload_digest(ctx))
        key = VerdictCache.key(control.id, self.policy_version, ctx, digest[0])
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        verdict = await self._run_one(control, ctx)
        self.cache.put(key, verdict)
        return verdict

    async def _run_one(self, control: Control, ctx: InspectionContext) -> Verdict:
        t0 = time.perf_counter()
        status: VerdictStatus
        try:
            verdict = await asyncio.wait_for(control.inspect(ctx), timeout=control.timeout_s)
            verdict.latency_ms = (time.perf_counter() - t0) * 1000
            return verdict
        except TimeoutError:
            status = VerdictStatus.timeout
        except Exception:  # a broken control must never crash the request
            log.exception("control %s failed", control.id)
            status = VerdictStatus.error
        return self._failed(control, status, (time.perf_counter() - t0) * 1000)

    def _failed(self, control: Control, status: VerdictStatus, latency_ms: float) -> Verdict:
        mode = control.effective_fail_mode(_default_fail_mode(self.settings, control.config.cost_tier))
        closed = mode == FailMode.closed
        return Verdict(
            control_id=control.id,
            control_type=control.type,
            phase=control.phase,
            cost_tier=control.config.cost_tier,
            action=Action.block if closed else Action.allow,
            final=closed,
            rule_ids=[control.id] if closed else [],
            reason=f"control {status.value}; fail mode {mode.value}",
            status=status,
            fail_mode_applied=mode,
            latency_ms=latency_ms,
        )
