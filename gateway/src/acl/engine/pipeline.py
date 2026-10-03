"""Decision pipeline: run applicable controls phase by phase, then compose a Decision.

Mechanics (concept §6.2):
  * phases run in PHASE_ORDER; controls within a phase run concurrently (asyncio.gather);
  * each control has its own timeout; errors/timeouts follow the control's fail mode;
  * a final (deterministic) block exits early;
  * `Verdict.outputs` of a phase are merged into `ctx.attributes` before the next phase.

Phase 0 skeleton: no content-hash cache, no L2 escalation band, no risk scoring
(Phase 1A / 2B / 3A extend this module and `acl.engine.decide`).
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
    ) -> None:
        self.controls = list(controls)
        self.settings = settings
        self.presets = dict(presets or {})

    def applicable(self, ctx: InspectionContext) -> list[Control]:
        return [c for c in self.controls if c.applies(ctx)]

    async def run(self, ctx: InspectionContext) -> Decision:
        started = time.perf_counter()
        verdicts: list[Verdict] = []
        applicable = self.applicable(ctx)
        for phase in PHASE_ORDER:
            group = [c for c in applicable if c.phase == phase]
            if not group:
                continue
            results = await asyncio.gather(*(self._run_one(c, ctx) for c in group))
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
