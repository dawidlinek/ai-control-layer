"""`budget` control (SEC-BUDGET-01): pre-dispatch budget check, soft / hard limits, circuit breaker.

Points: ingress, embeddings, tool_call. Deterministic, NOT cacheable (depends on live counters).

    breaker open (any node of the request)       → block, rule SEC-BUDGET-01.BREAKER
    hard limit (estimate would exceed it)        → `on_exceed.hard_action`:
                                                     block            → block (final)
                                                     degrade_to_local → route_local, reason "budget exhausted",
                                                                        for cloud-spend meters (tokens, USD) at
                                                                        ingress when routing.on_budget_exhausted
                                                                        is degrade_to_local; everything else blocks
    soft limit (`on_exceed.soft_pct`)            → allow; a `budget_breach` event once per window (commit hook)

`inspect()` only reads the ledger. The hooks in `acl.budgets.service` count, trip breakers and write events from
the report this control leaves in `Verdict.outputs["budget_report"]`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from acl.budgets.estimate import Estimate, estimate_request
from acl.budgets.ledger import Breach
from acl.budgets.retry import breaker_retry_after_s, retry_after_s
from acl.budgets.service import BudgetService
from acl.contracts.common import Action, InspectionPoint, Phase
from acl.contracts.decision import Verdict
from acl.contracts.inspection import InspectionContext
from acl.controls.base import Control, register_control


class BudgetParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_output_tokens: int | None = Field(
        default=None,
        ge=0,
        description="Output tokens assumed when the client sets no max_tokens; null = the stream output cap.",
    )


@register_control
class BudgetControl(Control):
    type = "budget"
    phase = Phase.deterministic
    Params = BudgetParams
    cacheable = False  # live counters

    _standalone: BudgetService | None = None

    def _service(self) -> BudgetService:
        svc = self.deps.get("budgets")
        if svc is not None:
            return svc
        if self._standalone is None:  # engine built without the app wiring: private, empty, in-memory ledger
            self._standalone = BudgetService.standalone(self.deps.get("policy"))
        return self._standalone

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        svc = self._service()
        policy = self.deps.get("policy") or svc.policy
        budgets = policy.budgets
        specs = svc.specs(ctx.principal, ctx.session_id, policy)
        tool = ctx.point == InspectionPoint.tool_call
        est = Estimate(tool_calls=1) if tool else estimate_request(ctx, policy, self.params.default_output_tokens)

        # -- circuit breakers (every node this request is accounted against)
        views = svc.breakers.views(s.id for s in specs)
        blocking = [v for v in views if v.state == "open" or (v.state == "half_open" and not v.probe_available)]
        if blocking:
            v = blocking[0]
            wait = f", retry after {v.cooldown_until:.0f}" if v.cooldown_until else ""
            return self.verdict(
                action=Action.block,
                final=True,
                rule_ids=[self.id, f"{self.id}.BREAKER"],
                reason=f"circuit breaker {v.state.replace('_', '-')} on {v.node_id}: "
                f"{v.reason or 'budget exhausted'}{wait}",
                outputs={
                    "budget_report": {"hard": [], "soft": [], "probe_nodes": [], "action": "block"},
                    "retry_after_s": breaker_retry_after_s(v.cooldown_until, svc.clock()),  # HTTP 429 Retry-After
                },
            )
        probe_nodes = [v.node_id for v in views if v.state == "half_open" and v.probe_available]

        # -- limits
        breaches = svc.ledger.check(
            specs,
            est,
            soft_pct=budgets.on_exceed.soft_pct,
            tools_only=tool,
            floors={"tool_calls": float(ctx.session.tool_depth)},
        )
        hard = [b for b in breaches if b.hard]
        soft = [b for b in breaches if not b.hard]
        report: dict[str, Any] = {"hard": hard, "soft": soft, "probe_nodes": probe_nodes, "action": "alert"}

        if hard:
            detail = "; ".join(_describe(b) for b in hard)
            degrade = ctx.point == InspectionPoint.ingress and all(svc.degradable(b, policy) for b in hard)
            if degrade:
                report["action"] = "route_local"
                reason = f"budget exhausted: {detail}; serving a local model"
                return self.verdict(
                    action=Action.route_local, rule_ids=[self.id], reason=reason, outputs={"budget_report": report}
                )
            report["action"] = "block"
            return self.verdict(
                action=Action.block,
                final=True,
                rule_ids=[self.id],
                reason=f"budget exceeded: {detail}",
                outputs={"budget_report": report, "retry_after_s": retry_after_s(hard, svc.clock())},
            )
        if soft:
            detail = "; ".join(b.describe() for b in soft)
            return self.verdict(
                action=Action.allow,
                reason=f"soft budget limit reached ({budgets.on_exceed.soft_pct}%): {detail}",
                outputs={"budget_report": report},
            )
        return self.verdict(action=Action.allow, outputs={"budget_report": report} if probe_nodes else {})


def _describe(b: Breach) -> str:
    return b.describe() + (" (already spent)" if b.exhausted else " (pre-dispatch estimate)")
