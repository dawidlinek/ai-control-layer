"""`loop_detector` control (SEC-LOOP-01): runaway agents (concept §8, "Loops and runaways").

Points: ingress, tool_call. Deterministic, NOT cacheable (reads per-session history).

    SEC-LOOP-01.REPEAT        the same (tool, args-hash) for the Nth time within `repeat_call.window_s` → block
    SEC-LOOP-01.NO_PROGRESS   the same call keeps returning the identical result (the coding-agent "same failing
                              test, same fix" pattern, approximated as repeated (tool, args-hash) + identical
                              result hash) over a longer window → block
    SEC-LOOP-01.STEPS         session steps > max_steps → block
    SEC-LOOP-01.DEPTH         tool depth > max_tool_depth → block
    SEC-LOOP-01.SPIKE         tokens/min of this session > `spend_spike_factor` × its trailing average →
                              require_approval (+ a `budget_breach` "spend spike" event)
    context growth           input tokens per step growing steeply → flagged in the verdict reason (action monitor)

Limits: `budgets.loops`, overridden per group by `groups.<g>.limits` (the tightest override of the principal's
groups wins). History is read here and written only by the flow hooks (`acl.budgets.service`), so `inspect()`
is dry-run safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from acl.budgets.estimate import input_tokens_of
from acl.budgets.loops import args_key
from acl.budgets.service import BudgetService
from acl.contracts.common import Action, InspectionPoint, Phase
from acl.contracts.decision import Verdict
from acl.contracts.inspection import ChatPayload, InspectionContext, Principal, ToolCallPayload
from acl.controls.base import Control, register_control
from acl.policy.models import Policy


class LoopParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    no_progress_calls: int = Field(default=2, ge=2, description="Earlier identical calls with identical results.")
    no_progress_window_s: int = Field(default=600, ge=1)
    spike_min_tokens: int = Field(default=2000, ge=0, description="Ignore spikes below this many tokens in the minute.")
    spike_min_history_minutes: int = Field(default=3, ge=1, description="Minutes of history before a spike can fire.")
    growth_min_steps: int = Field(default=4, ge=2)
    growth_factor: float = Field(default=2.0, gt=1)
    growth_min_tokens: int = Field(default=4000, ge=0)


@dataclass(frozen=True)
class EffectiveLoopLimits:
    repeat_count: int
    repeat_window_s: int
    max_steps: int
    max_tool_depth: int
    spike_factor: float


def effective_limits(policy: Policy, principal: Principal) -> EffectiveLoopLimits:
    loops = policy.budgets.loops
    count, window = loops.repeat_call.count, loops.repeat_call.window_s
    steps, depth = loops.max_steps, loops.max_tool_depth
    overridden = False
    for g in dict.fromkeys(principal.groups):
        gp = policy.groups.get(g)
        lim = gp.limits if gp else None
        if lim is None:
            continue
        if lim.repeat_call is not None:
            if not overridden or lim.repeat_call.count < count:
                count, window = lim.repeat_call.count, lim.repeat_call.window_s
            overridden = True
    group_steps = [
        x.limits.max_steps
        for g in dict.fromkeys(principal.groups)
        if (x := policy.groups.get(g)) and x.limits and x.limits.max_steps
    ]
    group_depth = [
        x.limits.max_tool_depth
        for g in dict.fromkeys(principal.groups)
        if (x := policy.groups.get(g)) and x.limits and x.limits.max_tool_depth
    ]
    if group_steps:
        steps = min(group_steps)
    if group_depth:
        depth = min(group_depth)
    return EffectiveLoopLimits(count, window, steps, depth, loops.spend_spike_factor)


@register_control
class LoopDetectorControl(Control):
    type = "loop_detector"
    phase = Phase.deterministic
    Params = LoopParams
    cacheable = False  # per-session history

    _standalone: BudgetService | None = None

    def _service(self) -> BudgetService:
        svc = self.deps.get("budgets")
        if svc is not None:
            return svc
        if self._standalone is None:
            self._standalone = BudgetService.standalone(self.deps.get("policy"))
        return self._standalone

    def _block(self, suffix: str, reason: str, title: str, **detail: Any) -> Verdict:
        rule = f"{self.id}.{suffix}"
        return self.verdict(
            action=Action.block,
            final=True,
            rule_ids=[self.id, rule],
            reason=reason,
            outputs={"loop_report": {"rule": rule, "title": title, "action": "block", **detail}},
        )

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        svc = self._service()
        policy = self.deps.get("policy") or svc.policy
        lim = effective_limits(policy, ctx.principal)
        if ctx.point == InspectionPoint.tool_call:
            return self._tool_call(svc, ctx, lim)
        return self._ingress(svc, ctx, lim)

    # ------------------------------------------------------------ tool_call

    def _tool_call(self, svc: BudgetService, ctx: InspectionContext, lim: EffectiveLoopLimits) -> Verdict:
        payload = ctx.payload
        if not isinstance(payload, ToolCallPayload):
            return self.verdict(action=Action.allow)
        key = args_key(payload.tool, payload.arguments)
        nth = svc.loops.repeats(ctx.session_id, key, lim.repeat_window_s).count + 1
        if nth >= lim.repeat_count:
            return self._block(
                "REPEAT",
                f"repeated tool call: {payload.tool} with identical arguments for the {nth}th time within "
                f"{lim.repeat_window_s}s (limit {lim.repeat_count})",
                f"Runaway loop: {payload.tool} repeated {nth}x",
                tool=payload.tool,
                repeats=nth,
                window_s=lim.repeat_window_s,
            )
        longer = svc.loops.repeats(ctx.session_id, key, self.params.no_progress_window_s)
        n = self.params.no_progress_calls
        recent = longer.results[-n:]
        if longer.count >= n and len(recent) == n and recent[0] is not None and len(set(recent)) == 1:
            return self._block(
                "NO_PROGRESS",
                f"no progress: {payload.tool} was called {longer.count} times with identical arguments and "
                f"identical results (same failing step, same fix)",
                f"Runaway loop: {payload.tool} makes no progress",
                tool=payload.tool,
                repeats=longer.count + 1,
            )
        if ctx.session.tool_depth + 1 > lim.max_tool_depth:
            return self._block(
                "DEPTH",
                f"tool depth {ctx.session.tool_depth + 1} exceeds the limit {lim.max_tool_depth}",
                "Runaway agent: tool depth limit",
                depth=ctx.session.tool_depth + 1,
                limit=lim.max_tool_depth,
            )
        if ctx.session.step > lim.max_steps:
            return self._block(
                "STEPS",
                f"session step {ctx.session.step} exceeds the limit {lim.max_steps}",
                "Runaway agent: step limit",
                steps=ctx.session.step,
                limit=lim.max_steps,
            )
        return self.verdict(action=Action.allow)

    # ------------------------------------------------------------ ingress

    def _ingress(self, svc: BudgetService, ctx: InspectionContext, lim: EffectiveLoopLimits) -> Verdict:
        if ctx.session.step + 1 > lim.max_steps:
            return self._block(
                "STEPS",
                f"session step {ctx.session.step + 1} exceeds the limit {lim.max_steps}",
                "Runaway agent: step limit",
                steps=ctx.session.step + 1,
                limit=lim.max_steps,
            )
        payload = ctx.payload
        tokens = input_tokens_of(payload) if isinstance(payload, ChatPayload) else 0

        # -- spend derivative: this session's tokens/min vs its own trailing average
        rate = svc.ledger.session_rate(ctx.session_id, extra_tokens=tokens)
        if (
            rate.span_minutes >= self.params.spike_min_history_minutes
            and rate.trailing_avg > 0
            and rate.current >= self.params.spike_min_tokens
            and rate.current >= lim.spike_factor * rate.trailing_avg
        ):
            rule = f"{self.id}.SPIKE"
            return self.verdict(
                action=Action.require_approval,
                rule_ids=[self.id, rule],
                reason=(
                    f"spend spike: {rate.current:.0f} tokens this minute vs {rate.trailing_avg:.0f}/min average "
                    f"(factor {rate.current / rate.trailing_avg:.1f} > {lim.spike_factor:g})"
                ),
                outputs={
                    "loop_report": {
                        "rule": rule,
                        "title": "Spend spike",
                        "action": "require_approval",
                        "tokens_this_minute": round(rate.current),
                        "trailing_avg_per_minute": round(rate.trailing_avg),
                        "factor": round(rate.current / rate.trailing_avg, 2),
                    }
                },
            )

        # -- context growth: input tokens per step rising steeply (quadratic growth of agent loops)
        k = self.params.growth_min_steps
        history = svc.loops.inputs(ctx.session_id)
        if tokens and len(history) >= k - 1:
            series = [*history[-(k - 1) :], tokens]
            first = series[0]
            monotone = all(b >= a * 0.9 for a, b in pairwise(series))
            if (
                monotone
                and tokens >= self.params.growth_factor * max(first, 1)
                and tokens - first >= self.params.growth_min_tokens
            ):
                return self.verdict(
                    action=Action.monitor,
                    reason=f"context growth: input tokens {first} → {tokens} over {k} steps (compact the context?)",
                )
        return self.verdict(action=Action.allow)
