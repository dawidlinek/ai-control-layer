"""CP2 scenario 7 "runaway agent" against the running stack (`make up`, then `make e2e`).

A scripted loop trips the repeat-call detector (SEC-LOOP-01) and a GPU-second budget (SEC-BUDGET-01), the circuit
breaker opens, and the `budget_breach` events show up on `/admin/v1/events` (and the live SSE stream).

Needs the deterministic mock upstream (`ACL_DETERMINISTIC=1`, the compose default without a model server): the
GPU overrun is produced with `[[mock:tokens N]]`. It uses user `jan` (developers) and one fresh session per run;
the run charges ~125k tokens to jan's daily budget (500k), so it can be repeated a few times per day. The session
breaker it opens is reset again at the end. Demo users come from deploy/keycloak/realm-export.json.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import pytest

pytestmark = pytest.mark.e2e

GPU_OVERRUN_TOKENS = 125_000  # mock: 1 ms of GPU per output token → 125 s > default_user.gpu_seconds_session (120)


def _is_breach(since: float):  # type: ignore[no-untyped-def]
    return lambda e: e.data.get("event_type") == "budget_breach" and e.t >= since - 0.5


def _decide(stack, session: str, command: str) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    r = stack.http.post(
        f"{stack.cfg.gateway}/v1/decide",
        json={
            "session_id": session,
            "action": {"kind": "tool_call", "tool": "opencode.bash", "arguments": {"command": command}},
            "client": {"app": "opencode"},
        },
        headers=stack.auth("jan"),
    )
    assert r.status_code == 200, f"/v1/decide: HTTP {r.status_code} {r.text[:300]}"
    return r.json()


def _chat(stack, session: str, content: str):  # type: ignore[no-untyped-def]
    return stack.http.post(
        f"{stack.cfg.gateway}/v1/chat/completions",
        json={"model": "local", "messages": [{"role": "user", "content": content}]},
        headers={**stack.auth("jan"), "X-Session-Id": session},
        timeout=60,
    )


def _breach_details(stack, user: str = "jan") -> list[dict[str, Any]]:  # type: ignore[no-untyped-def]
    listed = stack.admin("GET", "/events", params={"event_type": "budget_breach", "limit": 200})
    assert listed.status_code == 200, f"GET /events: HTTP {listed.status_code}"
    body = listed.json()
    items = body if isinstance(body, list) else body.get("items", [])
    out = []
    for ev in items:
        if ev.get("username") != user:
            continue
        full = stack.admin("GET", f"/events/{ev['event_id']}")
        assert full.status_code == 200
        out.append({**full.json().get("detail", {}), "_severity": ev["severity"], "_session": ev.get("session_id")})
    return out


def test_cp2_runaway_agent_trips_loop_detector_gpu_budget_and_breaker(stack, sse) -> None:
    run = uuid.uuid4().hex[:10]
    session = f"e2e-runaway-{run}"
    started = time.monotonic()

    # -- 0. the scripted upstream is available and the session starts clean
    probe = _chat(stack, session, "hello")
    assert probe.status_code == 200, f"baseline chat failed: HTTP {probe.status_code} {probe.text[:200]}"
    if not (probe.json()["choices"][0]["message"].get("content") or "").startswith("MOCK["):
        pytest.skip("needs the deterministic mock upstream to script usage ([[mock:tokens N]])")

    # -- 1. the loop: the agent repeats the same failing command; the 3rd identical call is blocked
    command = f"pytest -x tests/test_{run}.py"
    first = [_decide(stack, session, command)["action"] for _ in range(2)]
    assert first == ["allow", "allow"], f"the first two identical calls should pass, got {first}"
    third = _decide(stack, session, command)
    assert third["action"] == "block", f"the 3rd identical call must be blocked, got {third['action']}"
    assert "SEC-LOOP-01.REPEAT" in third["rule_ids"], f"rule ids: {third['rule_ids']}"
    assert _decide(stack, session, "ls")["action"] == "allow", "a different call is not a repeat"

    # -- 2. the same run burns GPU-seconds: one huge generation overruns the per-session budget
    burn = _chat(stack, session, f"[[mock:tokens {GPU_OVERRUN_TOKENS}]] keep going")
    assert burn.status_code == 200, "the call itself is within its estimate; the overrun shows up on reconciliation"

    # -- 3. the circuit breaker is open: the next call of this session is refused with the breaker rule
    refused = _chat(stack, session, "and again")
    assert refused.status_code == 403, f"expected the breaker to block, got HTTP {refused.status_code}"
    assert "SEC-BUDGET-01" in refused.text and "circuit breaker" in refused.text
    other = _chat(stack, f"e2e-other-{run}", "a different session is unaffected")
    assert other.status_code == 200, f"another session of the same user must still work: HTTP {other.status_code}"

    # -- 4. the breaker is visible (and resettable) in the panel API
    breakers = stack.admin("GET", "/budgets/breakers")
    assert breakers.status_code == 200, f"GET /budgets/breakers: HTTP {breakers.status_code}"
    opened = [b for b in breakers.json() if b["state"] == "open" and b["id"].startswith("session:")]
    assert opened, f"no open session breaker in {breakers.json()}"
    tree = stack.admin("GET", "/budgets")
    assert tree.status_code == 200
    assert any(
        n["level"] == "session" and n["breaker"] and n["breaker"]["state"] == "open" for n in tree.json()["nodes"]
    )

    # -- 5. budget_breach events: on the live stream and in the event list
    live = sse.wait_for(_is_breach(started), timeout=2.0)
    assert live is not None, "no budget_breach event on the SSE stream"
    details = _breach_details(stack)
    assert any(d.get("breaker") == "open" and d.get("level") == "hard" for d in details), "no breaker-open event"
    assert any(d.get("meter") == "gpu_seconds_session" for d in details), "the GPU-second overrun was not reported"
    assert any(d.get("rule_ids") == ["SEC-LOOP-01.REPEAT"] for d in details), "the runaway loop was not reported"

    # -- cleanup: reset the breakers this run opened
    for b in opened:
        reset = stack.admin("POST", f"/budgets/breakers/{b['id']}/reset")
        assert reset.status_code == 200 and reset.json()["state"] == "closed"
