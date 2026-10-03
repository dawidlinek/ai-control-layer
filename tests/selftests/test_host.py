"""The session host runs the real app lifespan once and falls back loudly when the app cannot start."""

from __future__ import annotations

import pytest
from harness.cases import build_context
from harness.host import EngineHost
from harness.runner import CaseRunner


def test_session_host_runs_the_real_app(host) -> None:
    assert host.mode == "app", host.fallback_reason
    assert host.app is not None and host.app.state.db_engine is not None
    assert host.engine is host.app.state.engine
    info = host.info()
    assert info["deterministic"] is True and info["policy_version"]


def test_host_evaluates_through_the_app_engine(host) -> None:
    case = {"id": "host-1", "control": "none", "kind": "positive", "input": "hello", "expect": {"action": "allow"}}
    res = CaseRunner(host.evaluate, record=False).run(case, "balanced")
    assert res.passed
    ctx = build_context(case, "strict")
    assert host.evaluate(ctx).action.value == "allow"


def test_engine_is_re_read_so_hot_reload_swaps_are_seen(host) -> None:
    before = host.engine
    other = host.app.state.build_engine(before.policy, "swapped")
    host.app.state.engine = other
    try:
        assert host.engine is other
    finally:
        host.app.state.engine = before


def test_in_process_client_reaches_the_app(host) -> None:
    async def go() -> int:
        async with host.async_client() as c:
            return (await c.get("/healthz")).status_code

    assert host.run(go()) == 200


def test_fallback_is_loud_when_the_app_cannot_start() -> None:
    h = EngineHost(installers=["acl.does_not_exist.wiring:install"])
    with pytest.warns(RuntimeWarning, match="FALLING BACK"):
        h.start()
    try:
        assert h.mode == "fallback" and h.fallback_reason and "does_not_exist" in h.fallback_reason
        case = {"id": "fb", "control": "none", "kind": "positive", "input": "hi", "expect": {"action": "allow"}}
        assert CaseRunner(h.evaluate, record=False).run(case, "balanced").passed
        assert h.info()["mode"] == "fallback"
    finally:
        h.stop()
    assert h.mode == "stopped"
