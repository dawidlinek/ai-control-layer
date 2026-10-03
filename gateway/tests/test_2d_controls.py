"""2D: SEC-BUDGET-01 and SEC-LOOP-01 driven through the engine and the flow hooks, with an injected clock."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from acl.budgets.service import BudgetService
from acl.contracts.audit import EventType, Usage
from acl.contracts.common import Action, InspectionPoint
from acl.contracts.decision import Decision
from acl.contracts.inspection import InspectionContext, SessionState
from acl.controls.base import ControlDeps
from acl.engine.engine import Engine
from acl.policy.loader import load_policy_dir
from acl.policy.models import Budgets, Policy
from acl.testing import make_context, make_principal

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"
MY_CONTROLS = {"SEC-BUDGET-01", "SEC-LOOP-01"}


class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class Sink:
    """Records `budget_breach` events like the audit service would."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def record_event(self, event_type: EventType, **kw: Any) -> None:
        self.events.append({"type": event_type, **kw})

    def of(self, **match: Any) -> list[dict[str, Any]]:
        return [e for e in self.events if all(e["detail"].get(k) == v for k, v in match.items())]


@lru_cache(maxsize=1)
def _seed() -> Policy:
    return load_policy_dir(POLICY_DIR).policy


def make_policy(budgets: dict[str, Any] | None = None, routing: dict[str, Any] | None = None) -> Policy:
    """The seed policy with only the two 2D controls, and `budgets` / `routing` patched (deep-merged one level)."""
    base = _seed()
    merged = base.budgets.model_dump()
    for k, v in (budgets or {}).items():
        merged[k] = {**merged.get(k, {}), **v} if isinstance(v, dict) and isinstance(merged.get(k), dict) else v
    updates: dict[str, Any] = {
        "controls": [c for c in base.controls if c.id in MY_CONTROLS],
        "budgets": Budgets.model_validate(merged),
    }
    if routing:
        updates["routing"] = base.routing.model_copy(update=routing)
    return base.model_copy(update=updates)


class Rig:
    """Engine + budget service + fake clock + audit sink."""

    def __init__(self, budgets: dict[str, Any] | None = None, routing: dict[str, Any] | None = None) -> None:
        self.clock = Clock()
        self.sink = Sink()
        self.policy = make_policy(budgets, routing)
        self.svc = BudgetService.standalone(self.policy, audit=self.sink, clock=self.clock)
        self.engine = Engine.build(self.policy, "t", deps=ControlDeps(budgets=self.svc))
        self.sessions: dict[str, SessionState] = {}

    def ctx(
        self,
        data: Any = "hello",
        *,
        point: InspectionPoint = InspectionPoint.ingress,
        user: str = "anna",
        groups: list[str] | None = None,
        agent: str | None = None,
        sid: str = "s1",
        model: str = "local/general",
        max_tokens: int | None = 5,
        **session: Any,
    ) -> InspectionContext:
        if isinstance(data, str) and point == InspectionPoint.ingress:
            # a small explicit output cap keeps the worst-case output estimate out of the way of tiny test limits
            params = {"max_tokens": max_tokens} if max_tokens is not None else {}
            data = {"messages": [{"role": "user", "content": data}], "params": params}
        state = self.sessions.setdefault(sid, SessionState(session_id=sid))
        if session:
            state = state.model_copy(update=session)
            self.sessions[sid] = state
        return make_context(
            data,
            point=point,
            principal=make_principal(user, groups if groups is not None else ["developers"], agent_id=agent),
            session_id=sid,
            session=state.model_copy(deep=True),
            model_requested=model,
        )

    async def step(self, ctx: InspectionContext, usage: Usage | None = None) -> Decision:
        """Evaluate, enforce (commit hook + session counters like `commit_decision`), reconcile usage."""
        decision = await self.engine.evaluate(ctx)
        st = self.sessions.setdefault(ctx.session_id, SessionState(session_id=ctx.session_id))
        tool_ok = ctx.point == InspectionPoint.tool_call and decision.action not in (
            Action.block,
            Action.require_approval,
        )
        self.sessions[ctx.session_id] = st.model_copy(
            update={
                "step": st.step + (1 if ctx.point == InspectionPoint.ingress else 0),
                "tool_depth": st.tool_depth + (1 if tool_ok else 0),
            }
        )
        await self.svc.on_commit(ctx, decision)
        if usage is not None:
            await self.svc.on_usage(ctx, decision, None, usage)
        return decision

    def tool(self, tool: str = "opencode.bash", args: dict[str, Any] | None = None, **kw: Any) -> InspectionContext:
        return self.ctx(
            {"tool": tool, "arguments": args or {"command": "pytest -x"}}, point=InspectionPoint.tool_call, **kw
        )


def usage(inp: int = 10, out: int = 10, usd: float = 0.0, gpu: float = 0.0) -> Usage:
    return Usage(input_tokens=inp, output_tokens=out, usd=usd, gpu_seconds=gpu)


# =============================================================================== SEC-BUDGET-01


async def test_under_the_cap_is_allowed() -> None:
    rig = Rig({"default_user": {"tokens_day": 100_000}})
    d = await rig.step(rig.ctx("hello"), usage(20, 30))
    assert d.action == Action.allow and not d.rule_ids
    assert rig.svc.ledger.value("user:anna", "tokens_day") == 50
    assert rig.svc.ledger.value("org", "tokens_day") == 50  # every level of the hierarchy is charged
    assert rig.svc.ledger.value("group:developers", "tokens_day") == 50


async def test_token_overrun_is_blocked_with_the_rule_and_without_a_breaker() -> None:
    rig = Rig({"default_user": {"tokens_day": 1000}})
    await rig.step(rig.ctx("hi"), usage(400, 500))
    d = await rig.step(rig.ctx("x" * 800, max_tokens=50))
    assert d.action == Action.block and d.final and "SEC-BUDGET-01" in d.rule_ids
    assert "tokens_day" in d.reason and "estimate" in d.reason
    # a request that is merely too large must not lock the user out: no breaker, a small request still passes
    assert rig.svc.breakers.all() == []
    d2 = await rig.step(rig.ctx("hi"))
    assert d2.action == Action.allow


async def test_output_estimate_is_the_requested_max_capped_by_the_stream_cap() -> None:
    rig = Rig({"default_user": {"tokens_session": 6000}, "stream": {"max_output_tokens": 5000}})
    big = {"messages": [{"role": "user", "content": "hi"}], "params": {"max_tokens": 100_000}}
    d = await rig.step(rig.ctx(big))  # 1 + min(100000, 5000) = 5001 < 6000 → ok
    assert d.action == Action.allow
    rig2 = Rig({"default_user": {"tokens_session": 4000}, "stream": {"max_output_tokens": 5000}})
    d = await rig2.step(rig2.ctx(big))  # the client's 100000 is capped to 5000, which exceeds 4000
    assert d.action == Action.block


async def test_gpu_second_overrun_is_blocked() -> None:
    rig = Rig({"default_user": {"gpu_seconds_session": 10}})
    await rig.step(rig.ctx("hi"), usage(100, 100, gpu=9.0))
    d = await rig.step(rig.ctx({"messages": [{"role": "user", "content": "hi"}], "params": {"max_tokens": 4000}}))
    assert d.action == Action.block and "gpu_seconds_session" in d.reason  # 9 + ~2 s estimate (0.5 s / 1k tokens)


async def test_soft_limit_allows_and_emits_one_event_per_window() -> None:
    rig = Rig({"default_user": {"tokens_day": 1000}})
    await rig.step(rig.ctx("hi"), usage(400, 450))  # 850 >= 80 %
    d = await rig.step(rig.ctx("hi"))
    assert d.action == Action.allow
    assert any("soft budget limit" in (v.reason or "") for v in d.verdicts)
    soft = rig.sink.of(level="soft", meter="tokens_day")
    assert len(soft) == 1 and soft[0]["type"] == EventType.budget_breach and soft[0]["severity"].value == "medium"
    await rig.step(rig.ctx("hi again"))
    assert len(rig.sink.of(level="soft", meter="tokens_day")) == 1  # once per window
    rig.clock.t += 86_400  # next day: the counter restarts, a new crossing notifies again
    await rig.step(rig.ctx("hi"), usage(450, 450))
    await rig.step(rig.ctx("hi"))
    assert len(rig.sink.of(level="soft", meter="tokens_day")) == 2


async def test_group_node_is_checked_for_every_group_of_the_principal() -> None:
    rig = Rig({"groups": {"developers": {"tokens_day": 100}}})
    d = await rig.step(rig.ctx("x" * 800, max_tokens=10))
    assert d.action == Action.block and "group:developers" in d.reason
    other = await rig.step(rig.ctx("x" * 800, max_tokens=10, groups=["credit-analysts"], sid="s2"))
    assert other.action == Action.allow


async def test_agent_limits_use_the_principals_agent_id() -> None:
    rig = Rig({"agents": {"bot": {"tokens_session": 100}}})
    big = {"messages": [{"role": "user", "content": "x" * 800}], "params": {"max_tokens": 10}}
    assert (await rig.step(rig.ctx(big, agent="bot"))).action == Action.block
    assert (await rig.step(rig.ctx(big, agent=None, sid="s2"))).action == Action.allow


async def test_requests_per_minute_blocks_the_burst_and_recovers() -> None:
    rig = Rig({"default_user": {"requests_per_minute": 3}})
    actions = [(await rig.step(rig.ctx("hi", sid=f"s{i}"))).action for i in range(5)]
    assert actions == [Action.allow] * 3 + [Action.block] * 2
    rig.clock.t += 60
    assert (await rig.step(rig.ctx("hi", sid="s9"))).action == Action.allow


async def test_tool_calls_per_session_are_counted_on_commit() -> None:
    rig = Rig({"agents": {"bot": {"tool_calls_session": 3}}})
    outcomes = []
    for i in range(5):
        d = await rig.step(rig.tool(args={"command": f"ls {i}"}, agent="bot"))
        outcomes.append(d.action)
    assert outcomes == [Action.allow] * 3 + [Action.block] * 2
    assert rig.svc.ledger.value("session:s1", "tool_calls_session") == 3  # blocked calls are not counted


async def test_inspect_never_mutates_state() -> None:
    rig = Rig({"default_user": {"tokens_day": 1000, "requests_per_minute": 2}})
    for _ in range(10):
        await rig.engine.evaluate(rig.ctx("hi"))  # dry-run / replay style: no commit
        await rig.engine.evaluate(rig.tool())
    assert rig.svc.ledger.usage_of("user:anna") == {} and rig.svc.loops.inputs("s1") == []
    assert rig.svc.breakers.all() == [] and rig.sink.events == []


# ---- hard_action: degrade_to_local


async def test_exhausted_cloud_budget_degrades_to_local_instead_of_blocking() -> None:
    rig = Rig({"default_user": {"tokens_day": 100}, "on_exceed": {"hard_action": "degrade_to_local"}})
    big = {"messages": [{"role": "user", "content": "x" * 800}], "params": {"max_tokens": 10}}
    d = await rig.step(rig.ctx(big, model="smart"))
    assert d.action == Action.route_local and "SEC-BUDGET-01" in d.rule_ids
    assert "budget exhausted" in d.reason
    # not a breaker case: the degraded traffic keeps flowing
    assert rig.svc.breakers.all() == []


async def test_degrade_only_applies_to_cloud_spend_and_routing_can_force_block() -> None:
    rig = Rig({"default_user": {"gpu_seconds_session": 1}, "on_exceed": {"hard_action": "degrade_to_local"}})
    await rig.step(rig.ctx("hi"), usage(10, 10, gpu=2.0))
    d = await rig.step(rig.ctx("hi"))
    assert d.action == Action.block  # a local model does not relieve GPU-seconds
    rig2 = Rig(
        {"default_user": {"tokens_day": 100}, "on_exceed": {"hard_action": "degrade_to_local"}},
        routing={"on_budget_exhausted": "block"},
    )
    big = {"messages": [{"role": "user", "content": "x" * 800}], "params": {"max_tokens": 10}}
    assert (await rig2.step(rig2.ctx(big))).action == Action.block


# ---- circuit breaker end to end (hooks + clock)


async def test_breaker_opens_on_overrun_half_opens_after_cooldown_and_closes_after_a_good_probe() -> None:
    rig = Rig(
        {
            "default_user": {"tokens_minute": 1000},
            "on_exceed": {"circuit_breaker": {"cooldown_s": 300, "half_open_probes": 1}},
        }
    )
    d = await rig.step(rig.ctx("hi"), usage(900, 300))  # actual spend 1200 > 1000: hard breach on reconcile
    assert d.action == Action.allow
    [view] = rig.svc.breakers.all()
    assert view.node_id == "user:anna" and view.state == "open"
    hard = rig.sink.of(level="hard", breaker="open")
    assert len(hard) == 1 and hard[0]["severity"].value == "high" and hard[0]["detail"]["node"] == "user:anna"

    blocked = await rig.step(rig.ctx("again"))
    assert blocked.action == Action.block and "SEC-BUDGET-01.BREAKER" in blocked.rule_ids
    assert "circuit breaker open" in blocked.reason

    rig.clock.t += 301  # cooldown over, and the minute window has rolled: the probe fits the budget
    assert rig.svc.breakers.view("user:anna").state == "half_open"  # type: ignore[union-attr]
    probe = await rig.step(rig.ctx("probe"), usage(10, 10))
    assert probe.action == Action.allow
    assert rig.svc.breakers.view("user:anna").state == "closed"  # type: ignore[union-attr]
    assert (await rig.step(rig.ctx("normal"), usage(10, 10))).action == Action.allow


async def test_half_open_breaker_admits_a_single_probe_and_a_failing_probe_reopens() -> None:
    rig = Rig({"default_user": {"tokens_day": 1000}, "on_exceed": {"circuit_breaker": {"cooldown_s": 60}}})
    await rig.step(rig.ctx("hi"), usage(600, 600))  # day budget overrun: breaker opens
    assert rig.svc.breakers.view("user:anna").state == "open"  # type: ignore[union-attr]
    rig.clock.t += 61
    # the probe is evaluated, but the day budget is still spent → it fails and the breaker re-opens
    probe = await rig.step(rig.ctx("probe"))
    assert probe.action == Action.block and "SEC-BUDGET-01" in probe.rule_ids
    assert rig.svc.breakers.view("user:anna").state == "open"  # type: ignore[union-attr]
    again = await rig.step(rig.ctx("again"))
    assert "SEC-BUDGET-01.BREAKER" in again.rule_ids


async def test_half_open_allows_only_the_configured_number_of_probes() -> None:
    rig = Rig({"default_user": {"tokens_minute": 100}, "on_exceed": {"circuit_breaker": {"cooldown_s": 60}}})
    await rig.step(rig.ctx("hi"), usage(100, 100))
    rig.clock.t += 61
    first = rig.ctx("p1")
    second = rig.ctx("p2", sid="s2")
    d1 = await rig.engine.evaluate(first)
    assert d1.action == Action.allow
    await rig.svc.on_commit(first, d1)  # the probe slot is taken at commit, not at inspect
    d2 = await rig.engine.evaluate(second)  # a concurrent second request while the probe is in flight
    assert d2.action == Action.block and "SEC-BUDGET-01.BREAKER" in d2.rule_ids


async def test_session_breach_trips_only_the_session() -> None:
    rig = Rig({"default_user": {"tokens_session": 100}})
    await rig.step(rig.ctx("hi", sid="a"), usage(80, 40))
    assert [v.node_id for v in rig.svc.breakers.all()] == ["session:a"]
    assert (await rig.step(rig.ctx("hi", sid="a"))).action == Action.block
    assert (await rig.step(rig.ctx("hi", sid="b"))).action == Action.allow  # other sessions of the user are fine


async def test_admin_reset_clears_a_breaker() -> None:
    rig = Rig({"default_user": {"tokens_minute": 10}})
    await rig.step(rig.ctx("hi"), usage(10, 10))
    assert (await rig.step(rig.ctx("again"))).action == Action.block
    state = rig.svc.reset_breaker("user:anna")
    assert state is not None and state.state == "closed"
    rig.clock.t += 61  # the minute window rolled; the breaker was already reset
    assert (await rig.step(rig.ctx("again"))).action == Action.allow


# ---- guard spend


async def test_guard_spend_is_a_separate_line_with_per_request_caps() -> None:
    rig = Rig({"guard": {"tokens_per_request": 1000, "gpu_seconds_per_request": 2.0}})
    p = make_principal("anna")
    ok = rig.svc.charge_guard(p, "s1", 800, 1.0)
    assert not ok.over_cap
    big = rig.svc.charge_guard(p, "s1", 1500, 0.5)
    assert big.over_cap and "per-request cap" in (big.reason or "")
    slow = rig.svc.charge_guard(p, "s1", 10, 3.0)
    assert slow.over_cap
    usage_ = rig.svc.ledger.usage_of("user:anna")
    assert usage_["guard_tokens_day"] == 2310 and "tokens_day" not in usage_


# =============================================================================== SEC-LOOP-01


async def test_repeated_tool_call_is_blocked_at_the_configured_count() -> None:
    rig = Rig({"loops": {"repeat_call": {"count": 3, "window_s": 60}}})
    a = [(await rig.step(rig.tool(args={"command": "pytest -x"}))).action for _ in range(4)]
    assert a == [Action.allow, Action.allow, Action.block, Action.block]
    d = await rig.step(rig.tool(args={"command": "pytest -x"}))
    assert any(r == "SEC-LOOP-01.REPEAT" for r in d.rule_ids) and "SEC-LOOP-01" in d.rule_ids
    other = await rig.step(rig.tool(args={"command": "ls"}))  # different args: not a repeat
    assert other.action == Action.allow


async def test_repeat_window_slides() -> None:
    rig = Rig({"loops": {"repeat_call": {"count": 3, "window_s": 60}}})
    for _ in range(2):
        await rig.step(rig.tool())
    rig.clock.t += 61
    assert (await rig.step(rig.tool())).action == Action.allow


async def test_group_repeat_override_wins_over_the_global_setting() -> None:
    rig = Rig({"loops": {"repeat_call": {"count": 10, "window_s": 60}}})
    # agents/research-bot sets repeat_call.count = 3 in groups.yaml
    acts = [
        (await rig.step(rig.tool("files.read_file", {"path": "/data/a"}, groups=["agents/research-bot"]))).action
        for _ in range(3)
    ]
    assert acts == [Action.allow, Action.allow, Action.block]
    dev = [(await rig.step(rig.tool("files.read_file", {"path": "/data/a"}, sid="s2"))).action for _ in range(3)]
    assert dev == [Action.allow] * 3


async def test_identical_calls_with_identical_results_are_a_no_progress_loop() -> None:
    rig = Rig({"loops": {"repeat_call": {"count": 5, "window_s": 30}}})
    for _ in range(2):  # a slow test run: calls are minutes apart, outside the repeat window
        await rig.step(rig.tool(args={"command": "pytest tests/test_x.py"}))
        result = rig.ctx(
            {"tool": "opencode.bash", "content": "FAILED tests/test_x.py::test_a - AssertionError", "is_error": True},
            point=InspectionPoint.tool_result,
        )
        await rig.step(result)
        rig.clock.t += 120
    d = await rig.step(rig.tool(args={"command": "pytest tests/test_x.py"}))
    assert d.action == Action.block and "SEC-LOOP-01.NO_PROGRESS" in d.rule_ids


async def test_changed_results_are_not_a_no_progress_loop() -> None:
    rig = Rig({"loops": {"repeat_call": {"count": 5, "window_s": 30}}})
    for i in range(2):
        await rig.step(rig.tool(args={"command": "pytest"}))
        await rig.step(
            rig.ctx({"tool": "opencode.bash", "content": f"{3 - i} failed"}, point=InspectionPoint.tool_result)
        )
        rig.clock.t += 120
    assert (await rig.step(rig.tool(args={"command": "pytest"}))).action == Action.allow


async def test_step_and_depth_limits() -> None:
    rig = Rig({"loops": {"max_steps": 3, "max_tool_depth": 2}})
    steps = [(await rig.step(rig.ctx("hi"))).action for _ in range(5)]
    assert steps == [Action.allow] * 3 + [Action.block] * 2
    d = await rig.step(rig.ctx("hi"))
    assert "SEC-LOOP-01.STEPS" in d.rule_ids
    depth = [(await rig.step(rig.tool(args={"command": f"c{i}"}, sid="d"))).action for i in range(4)]
    assert depth == [Action.allow] * 2 + [Action.block] * 2


async def test_spend_spike_requires_approval_and_raises_an_event() -> None:
    rig = Rig({"loops": {"spend_spike_factor": 5.0}})
    for _ in range(5):  # five quiet minutes at ~200 tokens/min
        await rig.step(rig.ctx("hi"), usage(100, 100))
        rig.clock.t += 60
    d = await rig.step(rig.ctx("x" * 12_000))  # ~3000 input tokens in the current minute vs ~200/min
    assert d.action == Action.require_approval and "SEC-LOOP-01.SPIKE" in d.rule_ids
    assert "spend spike" in d.reason
    spike = rig.sink.of(rule_ids=["SEC-LOOP-01.SPIKE"])
    assert len(spike) == 1 and spike[0]["detail"]["title"] == "Spend spike"
    assert spike[0]["type"] == EventType.budget_breach
    # a gentle increase does not fire
    quiet = Rig({"loops": {"spend_spike_factor": 5.0}})
    for _ in range(5):
        await quiet.step(quiet.ctx("hi"), usage(100, 100))
        quiet.clock.t += 60
    assert (await quiet.step(quiet.ctx("x" * 400))).action == Action.allow


async def test_context_growth_is_flagged_in_the_reason_without_blocking() -> None:
    rig = Rig()
    for n in (1000, 2000, 4000):
        await rig.step(rig.ctx("a" * (n * 4)), usage(n, 10))
        rig.clock.t += 1
    d = await rig.step(rig.ctx("a" * 32_000))  # 8000 tokens: 8x the first of the last four steps
    assert d.action in (Action.allow, Action.monitor)
    assert any("context growth" in (v.reason or "") for v in d.verdicts)


async def test_loop_blocks_raise_one_event_per_minute() -> None:
    rig = Rig({"loops": {"repeat_call": {"count": 2, "window_s": 60}}})
    for _ in range(5):
        await rig.step(rig.tool())
    assert len(rig.sink.of(rule_ids=["SEC-LOOP-01.REPEAT"])) == 1
    assert rig.sink.events[0]["severity"].value == "medium"


def test_controls_are_not_cacheable() -> None:
    controls = Rig().engine.pipeline.controls
    assert {c.id for c in controls} == MY_CONTROLS
    assert all(c.cacheable is False for c in controls)
