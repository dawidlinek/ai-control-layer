"""2D: budgets and loops through the real app (seed policy, mock connectors, hooks, router, admin API, DB)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from ruamel.yaml import YAML

from acl.contracts.common import InspectionPoint
from acl.contracts.inspection import ToolCallPayload
from acl.engine.actions import evaluate_point
from acl.main import create_app
from acl.settings import Settings
from acl.testing import make_principal

REPO = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO / "policy"
ADMIN = {"X-ACL-Dev-Roles": "acl-admin"}


def _headers(user: str = "anna", **extra: str) -> dict[str, str]:
    return {"X-ACL-Dev-User": user, "X-ACL-Dev-Groups": "developers", **extra}


def policy_copy(tmp: Path, patch: Callable[[dict[str, Any]], None]) -> Path:
    """A private copy of the seed policy with `budgets` patched by `patch`."""
    dst = tmp / "policy"
    shutil.copytree(POLICY_DIR, dst)
    yaml = YAML(typ="safe")
    path = dst / "budgets.yaml"
    doc = yaml.load(path.read_text(encoding="utf-8"))
    patch(doc["budgets"])
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        yaml.dump(doc, fh)
    return dst


def build(tmp: Path, patch: Callable[[dict[str, Any]], None] = lambda b: None, name: str = "acl.db") -> Any:
    settings = Settings(
        policy_dir=policy_copy(tmp, patch) if not (tmp / "policy").exists() else tmp / "policy",
        database_url=f"sqlite+aiosqlite:///{tmp / name}",
        audit_path=tmp / "audit.jsonl",
        deterministic=True,
        value_hash_salt="test-salt",  # type: ignore[arg-type]
    )
    return create_app(settings, allow_anonymous_dev=True)


@pytest.fixture
def make_client(tmp_path: Path) -> Iterator[Callable[..., TestClient]]:
    clients: list[TestClient] = []

    def _make(patch: Callable[[dict[str, Any]], None] = lambda b: None) -> TestClient:
        c = TestClient(build(tmp_path, patch))
        c.__enter__()
        clients.append(c)
        return c

    yield _make
    for c in reversed(clients):
        c.__exit__(None, None, None)


def chat(client: TestClient, content: str, model: str = "smart", user: str = "anna", **extra: Any) -> httpx.Response:
    headers = extra.pop("headers", {})
    body = {"model": model, "messages": [{"role": "user", "content": content}], **extra}
    return client.post("/v1/chat/completions", json=body, headers=_headers(user, **headers))


def sse_events(text: str) -> list[Any]:
    out: list[Any] = []
    for block in text.split("\n\n"):
        block = block.strip()
        if block.startswith("data:"):
            data = block[5:].strip()
            out.append("[DONE]" if data == "[DONE]" else json.loads(data))
    return out


def stream_text(events: list[Any]) -> str:
    return "".join(c["choices"][0]["delta"].get("content") or "" for c in events if c != "[DONE]" and c.get("choices"))


def events_of(client: TestClient, kind: str) -> list[dict[str, Any]]:
    r = client.get("/admin/v1/events", params={"event_type": kind, "limit": 200}, headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    return body if isinstance(body, list) else body["items"]


def breach_details(client: TestClient) -> list[dict[str, Any]]:
    """Full `detail` of every budget_breach event (the list endpoint only carries summaries)."""
    out = []
    for ev in events_of(client, "budget_breach"):
        full = client.get(f"/admin/v1/events/{ev['event_id']}", headers=ADMIN).json()
        out.append({**full["detail"], "severity": ev["severity"]})
    return out


def small_day_budget(b: dict[str, Any]) -> None:
    b["default_user"] = {**b["default_user"], "tokens_day": 100}
    b["stream"] = {**b["stream"], "max_output_tokens": 16}


# =============================================================================== degrade / block


def test_exhausted_budget_degrades_to_a_local_model_and_says_so(make_client) -> None:  # type: ignore[no-untyped-def]
    def patch(b: dict[str, Any]) -> None:
        small_day_budget(b)
        b["on_exceed"] = {**b["on_exceed"], "hard_action": "degrade_to_local"}

    client = make_client(patch)
    first = chat(client, "[[mock:tokens 200]] hello")
    assert first.status_code == 200 and first.headers["x-acl-model"] == "gemini/flash"
    assert first.headers["x-acl-degraded"] == "false"

    second = chat(client, "hello again")  # same user, same cloud model, budget now spent
    assert second.status_code == 200
    assert second.headers["x-acl-degraded"] == "true"  # never silent
    assert second.headers["x-acl-model"] == "local/general"
    assert second.headers["x-acl-decision"] == "route_local"
    assert second.json()["model"] == "local/general"

    # another user is unaffected
    other = chat(client, "hello", user="bob")
    assert other.headers["x-acl-model"] == "gemini/flash" and other.headers["x-acl-degraded"] == "false"

    # the routed decision names the reason, and a budget_breach event exists
    audit = [json.loads(line) for line in client.app.state.settings.audit_path.read_text("utf-8").splitlines()]  # type: ignore[attr-defined]
    ingress = [r for r in audit if r["event_type"] == "decision" and r.get("route", {}).get("degraded")]
    assert ingress and "budget exhausted" in ingress[0]["route"]["reason"]
    assert any(e["event_type"] == "budget_breach" for e in audit)
    # degraded traffic keeps flowing: no circuit breaker for degradable cloud spend
    assert client.get("/admin/v1/budgets/breakers", headers=_headers(**ADMIN)).json() == []


def test_exhausted_budget_blocks_by_default_and_the_breaker_is_visible_and_resettable(make_client) -> None:  # type: ignore[no-untyped-def]
    client = make_client(small_day_budget)
    assert chat(client, "[[mock:tokens 200]] hi").status_code == 200  # reconciled usage overruns the day budget
    blocked = chat(client, "hi again")
    assert blocked.status_code == 403
    assert "SEC-BUDGET-01" in blocked.text and "circuit breaker" in blocked.text

    admin = _headers("adam", **ADMIN)
    [breaker] = client.get("/admin/v1/budgets/breakers", headers=admin).json()
    assert breaker["id"] == "user:anna" and breaker["state"] == "open" and breaker["cooldown_until"]

    tree = client.get("/admin/v1/budgets", headers=admin).json()["nodes"]
    by_id = {n["id"]: n for n in tree}
    assert by_id["org"]["level"] == "org" and by_id["org"]["limits"]["usd_month"] == 100
    user = by_id["user:anna"]
    assert user["level"] == "user" and user["limits"]["tokens_day"] == 100 and user["usage"]["tokens_day"] >= 200
    assert user["breaker"]["state"] == "open" and user["parent"] == "group:developers"
    assert by_id["group:developers"]["parent"] == "org" and by_id["group:developers"]["usage"]["tokens_day"] >= 200
    session = next(n for n in tree if n["level"] == "session")
    assert session["parent"] == "user:anna" and session["limits"]["gpu_seconds_session"] == 120

    assert client.post("/admin/v1/budgets/breakers/user:anna/reset", headers=_headers("anna")).status_code == 403
    reset = client.post("/admin/v1/budgets/breakers/user:anna/reset", headers=admin)
    assert reset.status_code == 200 and reset.json()["state"] == "closed"
    assert client.post("/admin/v1/budgets/breakers/nope/reset", headers=admin).status_code == 404

    breaches = breach_details(client)
    assert any(e["severity"] == "high" and e["level"] == "hard" for e in breaches)
    assert any(e.get("breaker") == "open" and e["node"] == "user:anna" for e in breaches)


def test_viewer_cannot_reset_but_can_read(make_client) -> None:  # type: ignore[no-untyped-def]
    client = make_client()
    viewer = _headers("vic", **{"X-ACL-Dev-Roles": "acl-viewer"})
    assert client.get("/admin/v1/budgets", headers=viewer).status_code == 200
    assert client.post("/admin/v1/budgets/breakers/x/reset", headers=viewer).status_code == 403


# =============================================================================== streaming caps


def test_endless_output_is_cut_at_the_policy_cap_and_metered(make_client) -> None:  # type: ignore[no-untyped-def]
    def patch(b: dict[str, Any]) -> None:
        b["stream"] = {**b["stream"], "max_output_tokens": 8, "holdback_chars": 16}

    client = make_client(patch)
    r = chat(client, "[[mock:repeat 200 abcd]]", model="local", stream=True)
    events = sse_events(r.text)
    content = stream_text(events)
    assert 0 < len(content) <= 80 < 200 * 4  # 8 tokens ≈ 32 chars (+ the hold-back window), never the 800 asked for
    finish = [e for e in events[:-1] if e["choices"] and e["choices"][0]["finish_reason"]]
    assert finish[-1]["choices"][0]["finish_reason"] == "length"
    ledger = client.app.state.budgets.ledger  # type: ignore[attr-defined]
    assert 0 < ledger.value("user:anna", "output_tokens_day") <= 40  # the cut stream is what got billed


def test_repeated_ngrams_cut_the_stream(make_client) -> None:  # type: ignore[no-untyped-def]
    def patch(b: dict[str, Any]) -> None:
        b["stream"] = {**b["stream"], "repeat_ngram": {"n": 3, "max_repeats": 3}}

    client = make_client(patch)
    r = chat(client, "[[mock:repeat 100 foo bar baz ]]", model="local", stream=True)
    events = sse_events(r.text)
    assert len(stream_text(events)) < 100 * 11 // 2
    finish = [e for e in events[:-1] if e["choices"] and e["choices"][0]["finish_reason"]]
    assert finish[-1]["choices"][0]["finish_reason"] == "length"


def test_non_streaming_request_max_tokens_is_clamped_to_the_cap(make_client) -> None:  # type: ignore[no-untyped-def]
    def patch(b: dict[str, Any]) -> None:
        b["stream"] = {**b["stream"], "max_output_tokens": 64}

    client = make_client(patch)
    r = chat(client, "hi", model="local", max_tokens=100_000)
    assert r.status_code == 200
    sent = client.app.state.connectors.get("local").calls[-1]["request"]  # type: ignore[attr-defined]
    assert sent["max_tokens"] == 64


# =============================================================================== hooks and loops through HTTP


def test_usage_is_reconciled_once_per_call_and_requests_are_counted(make_client) -> None:  # type: ignore[no-untyped-def]
    client = make_client()
    for _ in range(3):
        assert chat(client, "[[mock:tokens 30]] hi", model="local").status_code == 200
    ledger = client.app.state.budgets.ledger  # type: ignore[attr-defined]
    assert ledger.value("user:anna", "output_tokens_day") == 90
    assert ledger.value("user:anna", "requests_minute") == 3
    assert ledger.value("org", "gpu_seconds_day") == pytest.approx(0.09)  # mock: 1 ms of GPU per output token
    assert ledger.value("group:developers", "usd_day") > 0


def test_rate_limit_blocks_the_burst(make_client) -> None:  # type: ignore[no-untyped-def]
    def patch(b: dict[str, Any]) -> None:
        b["default_user"] = {**b["default_user"], "requests_per_minute": 2}

    client = make_client(patch)
    codes = [chat(client, "hi", model="local").status_code for _ in range(4)]
    assert codes == [200, 200, 403, 403]


def decide(client: TestClient, command: str, session: str = "agent-1", user: str = "anna") -> Any:
    """A client-local tool call evaluated through the shared seam `/v1/decide` and the MCP proxy use."""
    app = client.app

    async def run() -> Any:
        _, decision = await evaluate_point(
            app,
            make_principal(user, ["developers"]),
            point=InspectionPoint.tool_call,
            payload=ToolCallPayload(tool="opencode.bash", arguments={"command": command}),
            client_session=session,
        )
        return decision

    return client.portal.call(run)  # type: ignore[union-attr]


def test_repeated_tool_call_is_blocked_through_evaluate_point_and_counted(make_client) -> None:  # type: ignore[no-untyped-def]
    client = make_client()
    actions = [decide(client, "pytest -x").action.value for _ in range(4)]
    assert actions[:2] == ["allow", "allow"] and actions[2:] == ["block", "block"]
    assert "SEC-LOOP-01.REPEAT" in decide(client, "pytest -x").rule_ids
    assert decide(client, "ls").action.value == "allow"  # different arguments
    assert decide(client, "pytest -x", session="agent-2").action.value == "allow"  # another session starts fresh
    loops = [e for e in breach_details(client) if e.get("rule_ids") == ["SEC-LOOP-01.REPEAT"]]
    assert len(loops) == 1  # one runaway event per minute and session, not one per blocked call


# =============================================================================== persistence


def test_counters_and_breakers_survive_a_restart(tmp_path: Path) -> None:
    patch = small_day_budget
    app = build(tmp_path, patch)
    with TestClient(app) as client:
        assert chat(client, "[[mock:tokens 200]] hi").status_code == 200
        assert chat(client, "again").status_code == 403
        assert app.state.budgets.breakers.view("user:anna").state == "open"
    # a new process: same database, same policy
    app2 = build(tmp_path, patch)
    with TestClient(app2) as client2:
        svc = app2.state.budgets
        assert svc.ledger.value("user:anna", "tokens_day") >= 200
        assert svc.breakers.view("user:anna").state == "open"
        assert chat(client2, "hi").status_code == 403


def test_scenario7_gpu_second_overrun_opens_the_session_breaker(make_client) -> None:  # type: ignore[no-untyped-def]
    """The seed policy as shipped: default_user.gpu_seconds_session = 120, mock = 1 ms of GPU per output token."""
    client = make_client()
    sid = {"X-Session-Id": "runaway-1"}
    assert chat(client, "[[mock:tokens 125000]] keep going", model="local", headers=sid).status_code == 200
    refused = chat(client, "and again", model="local", headers=sid)
    assert refused.status_code == 403 and "circuit breaker" in refused.text
    assert chat(client, "another session", model="local", headers={"X-Session-Id": "runaway-2"}).status_code == 200
    breakers = client.get("/admin/v1/budgets/breakers", headers=_headers(**ADMIN)).json()
    assert len(breakers) == 1 and breakers[0]["id"].startswith("session:") and breakers[0]["state"] == "open"
    assert any(d.get("meter") == "gpu_seconds_session" for d in breach_details(client))
