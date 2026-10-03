"""Budget service: ledger + breakers + loop tracker, and the flow hooks that drive them (concept §8).

Registered as control service `"budgets"` (SEC-BUDGET-01 / SEC-LOOP-01 read from it) and in
`app.state.flow_hooks`. Everything that mutates state lives in the two hooks:

    on_commit(ctx, decision)            requests/minute bucket, tool-call count, loop bookkeeping, breaker
                                        trips and probes, `budget_breach` events requested by the controls
    on_usage(ctx, decision, route, u)   reconcile actual tokens / USD / GPU-seconds, trip breakers on overrun,
                                        close a half-open breaker whose probe finished within budget

The controls only *read* (`inspect()` stays side-effect free); they hand what the hooks must do to
`decision.verdicts[*].outputs["budget_report"]` / `["loop_report"]`.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from acl.budgets.breaker import BreakerBook, BreakerView
from acl.budgets.estimate import ZERO, input_tokens_of
from acl.budgets.ledger import Breach, Ledger
from acl.budgets.loops import LoopTracker, args_key
from acl.budgets.nodes import RPM, NodeSpec, limits_dict, node_specs
from acl.contracts.admin import BreakerState, BudgetNode, BudgetTree
from acl.contracts.audit import EventType, Usage
from acl.contracts.common import Action, InspectionPoint, Severity
from acl.contracts.decision import Decision, RouteInfo
from acl.contracts.inspection import ChatPayload, InspectionContext, Principal, ToolCallPayload, ToolResultPayload
from acl.policy.models import Policy

log = logging.getLogger(__name__)

PolicyProvider = Callable[[], Policy | None]
AuditProvider = Callable[[], Any]
DEGRADABLE_BASES = frozenset({"tokens", "usd"})  # cloud-spend meters: a local model relieves them


@dataclass(frozen=True)
class GuardCharge:
    tokens: int
    gpu_seconds: float
    over_cap: bool
    reason: str | None = None


class BudgetService:
    def __init__(
        self,
        policy_provider: PolicyProvider,
        *,
        audit_provider: AuditProvider = lambda: None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.clock = clock
        self.ledger = Ledger(clock)
        self.breakers = BreakerBook(clock)
        self.loops = LoopTracker(clock)
        self._policy = policy_provider
        self._audit = audit_provider
        self.store: Any = None  # BudgetStore, attached by the wiring

    @classmethod
    def standalone(cls, policy: Policy, *, audit: Any = None, clock: Callable[[], float] = time.time) -> BudgetService:
        """A service bound to one policy (unit tests, engines built without the app wiring)."""
        return cls(lambda: policy, audit_provider=lambda: audit, clock=clock)

    @property
    def policy(self) -> Policy | None:
        return self._policy()

    def specs(self, principal: Principal, session_id: str, policy: Policy | None = None) -> list[NodeSpec]:
        policy = policy or self.policy
        assert policy is not None
        return node_specs(policy, principal, session_id)

    # ------------------------------------------------------------ breakers

    def degradable(self, breach: Breach, policy: Policy) -> bool:
        """A hard breach a local model relieves (cloud spend), under a degrade-to-local policy."""
        return (
            breach.base in DEGRADABLE_BASES
            and policy.budgets.on_exceed.hard_action == "degrade_to_local"
            and policy.routing.on_budget_exhausted == "degrade_to_local"
        )

    def trip_nodes(self, breaches: list[Breach], policy: Policy) -> list[tuple[str, Breach]]:
        """Nodes whose breaker a set of hard breaches opens: cumulative spend that is spent (not rate limits,
        not a request that is merely too large, not cloud spend that is being degraded to local)."""
        cfg = policy.budgets.on_exceed.circuit_breaker
        opened: list[tuple[str, Breach]] = []
        for b in breaches:
            if not b.hard or not b.exhausted or b.meter == RPM or self.degradable(b, policy):
                continue
            reason = f"hard limit reached: {b.describe()}"
            if self.breakers.trip(b.scope, reason, cooldown_s=cfg.cooldown_s, half_open_probes=cfg.half_open_probes):
                opened.append((b.scope, b))
        return opened

    # ------------------------------------------------------------ events

    async def emit(
        self,
        ctx: InspectionContext,
        severity: Severity,
        title: str,
        detail: dict[str, Any],
    ) -> None:
        audit = self._audit()
        if audit is None:
            return
        try:
            await audit.record_event(
                EventType.budget_breach,
                severity=severity,
                detail={"category": "budget_breach", "title": title, **detail},
                principal=ctx.principal,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
            )
        except Exception:
            log.exception("could not record budget_breach event")

    async def _notify(
        self, ctx: InspectionContext, b: Breach, *, action: str, extra: dict[str, Any] | None = None
    ) -> None:
        if not self.ledger.mark_notified(b.scope, b.counter, b.level):
            return
        who = ctx.principal.username or ctx.principal.subject
        title = f"{'Hard' if b.hard else 'Soft'} budget limit: {b.describe()} ({who})"
        await self.emit(
            ctx,
            Severity.high if b.hard else Severity.medium,
            title,
            {
                "level": b.level,
                "node": b.owner,
                "scope": b.scope,
                "meter": b.meter,
                "limit": b.limit,
                "used": round(b.used, 6),
                "projected": round(b.projected, 6),
                "action": action,
                "rule_ids": ["SEC-BUDGET-01"],
                **(extra or {}),
            },
        )

    async def _announce_trip(self, ctx: InspectionContext, node: str, b: Breach) -> None:
        cfg = (self.policy.budgets.on_exceed.circuit_breaker) if self.policy else None
        await self.emit(
            ctx,
            Severity.high,
            f"Circuit breaker opened on {node}: {b.describe()}",
            {
                "level": "hard",
                "breaker": "open",
                "node": node,
                "meter": b.meter,
                "limit": b.limit,
                "used": round(b.used, 6),
                "cooldown_s": cfg.cooldown_s if cfg else None,
                "rule_ids": ["SEC-BUDGET-01.BREAKER"],
            },
        )

    # ------------------------------------------------------------ flow hooks

    async def on_commit(self, ctx: InspectionContext, decision: Decision) -> None:
        policy = self.policy
        if policy is None:
            return
        specs = self.specs(ctx.principal, ctx.session_id, policy)
        point = ctx.point
        blocked = decision.action == Action.block
        allowed = decision.action not in (Action.block, Action.require_approval)
        payload = ctx.payload

        if point in (InspectionPoint.ingress, InspectionPoint.embeddings) and not blocked:
            self.ledger.count_request(specs)
            if point == InspectionPoint.ingress and isinstance(payload, ChatPayload):
                self.loops.record_input(ctx.session_id, input_tokens_of(payload))
        elif point == InspectionPoint.tool_call and isinstance(payload, ToolCallPayload):
            self.loops.record_call(
                ctx.session_id, args_key(payload.tool, payload.arguments), payload.tool, payload.tool_call_id
            )
            if allowed:
                self.ledger.count_tool_call(specs)
        elif point == InspectionPoint.tool_result and isinstance(payload, ToolResultPayload):
            self.loops.record_result(ctx.session_id, payload.tool, payload.tool_call_id, payload.content)

        for v in decision.verdicts:
            report = v.outputs.get("budget_report") if v.control_type == "budget" else None
            if report:
                await self._apply_budget_report(ctx, decision, report, policy, allowed)
            loop_report = v.outputs.get("loop_report") if v.control_type == "loop_detector" else None
            if loop_report:
                await self._apply_loop_report(ctx, loop_report)

    async def _apply_budget_report(
        self, ctx: InspectionContext, decision: Decision, report: dict[str, Any], policy: Policy, allowed: bool
    ) -> None:
        hard: list[Breach] = report.get("hard", [])
        soft: list[Breach] = report.get("soft", [])
        action = report.get("action", "alert")
        for b in hard:
            await self._notify(ctx, b, action=action)
        for b in soft:
            await self._notify(ctx, b, action="alert")
        for node, b in self.trip_nodes(hard, policy):
            await self._announce_trip(ctx, node, b)
        if allowed and not hard:
            for node in report.get("probe_nodes", []):
                if self.breakers.begin_probe(node) and ctx.point == InspectionPoint.tool_call:
                    # no upstream usage follows a tool call: the call itself is the probe
                    self.breakers.probe_succeeded(node)

    async def _apply_loop_report(self, ctx: InspectionContext, report: dict[str, Any]) -> None:
        rule = report.get("rule")
        if not rule:
            return
        session_node = f"session:{ctx.session_id}"
        counter = f"loop_{str(rule).lower().replace('.', '_').replace('-', '_')}_minute"
        if not self.ledger.mark_notified(session_node, counter, "soft"):
            return
        await self.emit(
            ctx,
            Severity.medium,
            str(report.get("title") or f"Runaway signal {rule}"),
            {
                "level": "loop",
                "rule_ids": [rule],
                "action": report.get("action"),
                "detail": {k: v for k, v in report.items() if k not in ("title", "rule", "action")},
            },
        )

    async def on_usage(self, ctx: InspectionContext, decision: Decision, route: RouteInfo | None, usage: Usage) -> None:
        policy = self.policy
        if policy is None:
            return
        specs = self.specs(ctx.principal, ctx.session_id, policy)
        self.ledger.charge(
            specs,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            usd=usage.usd,
            gpu_seconds=usage.gpu_seconds,
        )
        floors = {"tool_calls": float(ctx.session.tool_depth)}
        breaches = self.ledger.check(specs, ZERO, soft_pct=policy.budgets.on_exceed.soft_pct, floors=floors)
        for b in breaches:
            await self._notify(ctx, b, action="reconciled")
        tripped = self.trip_nodes(breaches, policy)
        for node, b in tripped:
            await self._announce_trip(ctx, node, b)
        tripped_ids = {n for n, _ in tripped}
        for view in self.breakers.views(s.id for s in specs):
            if (
                view.state == "half_open"
                and view.node_id not in tripped_ids
                and self.breakers.probe_succeeded(view.node_id)
            ):
                log.info("budget breaker %s closed after a successful probe", view.node_id)

    # ------------------------------------------------------------ guard spend (Phase 3 judges)

    def guard_caps(self) -> tuple[int, float]:
        policy = self.policy
        g = policy.budgets.guard if policy else None
        return (g.tokens_per_request, g.gpu_seconds_per_request) if g else (4000, 5.0)

    def charge_guard(self, principal: Principal, session_id: str, tokens: int, gpu_seconds: float) -> GuardCharge:
        """Record judge / guard spend as its own line. `over_cap` flags a call above `budgets.guard` caps; the
        spend is recorded either way (it happened) and never counted against the user's token/GPU budgets."""
        policy = self.policy
        specs = self.specs(principal, session_id, policy)
        self.ledger.charge_guard(specs, tokens=tokens, gpu_seconds=gpu_seconds)
        max_tokens, max_gpu = self.guard_caps()
        reason = None
        if tokens > max_tokens:
            reason = f"guard tokens {tokens} exceed the per-request cap {max_tokens}"
        elif gpu_seconds > max_gpu:
            reason = f"guard GPU-seconds {gpu_seconds:g} exceed the per-request cap {max_gpu:g}"
        return GuardCharge(tokens, gpu_seconds, reason is not None, reason)

    # ------------------------------------------------------------ admin views

    @staticmethod
    def _dt(ts: float | None) -> datetime | None:
        return datetime.fromtimestamp(ts, UTC) if ts is not None else None

    def breaker_state(self, view: BreakerView) -> BreakerState:
        return BreakerState(
            id=view.node_id,
            state=view.state,  # type: ignore[arg-type]
            opened_at=self._dt(view.opened_at),
            cooldown_until=self._dt(view.cooldown_until),
            reason=view.reason,
        )

    def tree(self, max_sessions: int = 100) -> BudgetTree:
        policy = self.policy
        limits: dict[str, dict[str, float]] = {"org": limits_dict(policy.budgets.org) if policy else {}}
        parents: dict[str, str | None] = {"org": None}
        levels: dict[str, str] = {"org": "org"}
        if policy:
            for g, lim in policy.budgets.groups.items():
                limits[f"group:{g}"], parents[f"group:{g}"], levels[f"group:{g}"] = limits_dict(lim), "org", "group"
            for u, lim in policy.budgets.users.items():
                merged = {**limits_dict(policy.budgets.default_user), **limits_dict(lim)}
                limits[f"user:{u}"], parents[f"user:{u}"], levels[f"user:{u}"] = merged, "org", "user"
            for a, lim in policy.budgets.agents.items():
                limits[f"agent:{a}"], parents[f"agent:{a}"], levels[f"agent:{a}"] = limits_dict(lim), "org", "agent"
        observed = self.ledger.nodes()
        sessions = sorted((n for n in observed if n["level"] == "session"), key=lambda n: -n["last_seen"])[
            :max_sessions
        ]
        for n in [*(n for n in observed if n["level"] != "session"), *sessions]:
            levels[n["id"]] = n["level"]
            parents[n["id"]] = n["parent"] or parents.get(n["id"])
            if n["id"] not in limits:
                base = limits_dict(policy.budgets.default_user) if (policy and n["level"] == "user") else {}
                limits[n["id"]] = base
        for n in sessions:  # a session inherits the tightest `*_session` limit of its ancestors
            merged: dict[str, float] = {}
            cur = n["parent"]
            hops = 0
            while cur is not None and hops < 8:
                for k, v in limits.get(cur, {}).items():
                    if k.endswith("_session"):
                        merged[k] = min(v, merged.get(k, v))
                cur = parents.get(cur)
                hops += 1
            limits[n["id"]] = merged
        views = {v.node_id: v for v in self.breakers.all()}
        usage = {n["id"]: n["usage"] for n in observed}
        nodes = []
        for nid in levels:
            if levels[nid] == "session" and nid not in {s["id"] for s in sessions}:
                continue
            view = views.get(nid)
            nodes.append(
                BudgetNode(
                    id=nid,
                    level=levels[nid],  # type: ignore[arg-type]
                    parent=parents.get(nid),
                    limits=limits.get(nid, {}),
                    usage=usage.get(nid, {}),
                    breaker=self.breaker_state(view) if view else None,
                )
            )
        order = {lvl: i for i, lvl in enumerate(("org", "group", "user", "agent", "session"))}
        nodes.sort(key=lambda n: (order[n.level], n.id))
        return BudgetTree(generated_at=datetime.now(UTC), nodes=nodes)

    def list_breakers(self) -> list[BreakerState]:
        return [self.breaker_state(v) for v in sorted(self.breakers.all(), key=lambda v: v.node_id)]

    def reset_breaker(self, breaker_id: str) -> BreakerState | None:
        view = self.breakers.reset(breaker_id)
        return self.breaker_state(view) if view else None
