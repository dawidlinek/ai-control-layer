"""Read side of the admin API for the Rogatka Dashboard: narration templates, enriched events, trace, transcript,
user stats, overview cost / timeline and model usage. Unit tests build `AuditEvent`s by hand; the API tests drive real
traffic through `/v1/chat/completions` (mock connectors) and read it back through `/admin/v1`."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from acl.audit import narrate
from acl.audit.builder import last_message_text
from acl.audit.queries import bucket_seconds, decision_timeline
from acl.contracts.audit import (
    GENESIS_HASH,
    AuditDecision,
    AuditEvent,
    AuditFinding,
    AuditPrincipal,
    AuditVerdict,
    EventType,
    Usage,
)
from acl.contracts.common import (
    Action,
    AuthMethod,
    ConnectorTier,
    DataClass,
    InspectionPoint,
    Phase,
    PrincipalKind,
    Versions,
)
from acl.contracts.decision import ApprovalRef, RouteInfo
from acl.contracts.inspection import ClientInfo, Principal, SessionLabels
from acl.main import create_app
from acl.settings import Settings

REPO = Path(__file__).resolve().parents[2]
BASE = "/admin/v1"
PESEL = "44051401359"
T0 = datetime(2026, 10, 3, 14, 3, 12, tzinfo=UTC)

# ================================================================ unit: narration


def _verdict(
    control_id: str,
    action: Action = Action.allow,
    *,
    phase: Phase = Phase.deterministic,
    rule_ids: list[str] | None = None,
    entities: list[str] | None = None,
    score: float | None = None,
    latency_ms: float = 1.0,
) -> AuditVerdict:
    return AuditVerdict(
        control_id=control_id,
        control_type=control_id.lower(),
        phase=phase,
        action=action,
        score=score,
        latency_ms=latency_ms,
        rule_ids=rule_ids or ([control_id] if action != Action.allow else []),
        findings=[
            AuditFinding(
                entity_type=e, field="messages[0].content", start=i * 10, end=i * 10 + 5, value_hash="deadbeef"
            )
            for i, e in enumerate(entities or [])
        ],
    )


def _event(
    action: Action = Action.allow,
    *,
    point: InspectionPoint = InspectionPoint.ingress,
    user: str = "Anna Nowak",
    rule_ids: list[str] | None = None,
    applied: list[Action] | None = None,
    verdicts: list[AuditVerdict] | None = None,
    decided_by: str | None = None,
    tool: str | None = None,
    server: str | None = None,
    model: str | None = "gemini/flash",
    model_requested: str | None = None,
    route: RouteInfo | None = None,
    labels: SessionLabels | None = None,
    would_action: Action | None = None,
    approval: ApprovalRef | None = None,
    seq: int = 0,
    session_id: str | None = "ns:s-1",
    usage: Usage | None = None,
    timestamp: datetime = T0,
) -> AuditEvent:
    return AuditEvent(
        event_id=f"e-{seq}",
        seq=seq,
        timestamp=timestamp,
        event_type=EventType.decision,
        trace_id=f"t-{seq}",
        session_id=session_id,
        principal=AuditPrincipal(
            subject=f"sub-{user}",
            kind=PrincipalKind.user,
            username=user,
            groups=["developers"],
            auth_method=AuthMethod.jwt,
        ),
        client=ClientInfo(app="librechat"),
        point=point,
        tool=tool,
        server=server,
        model_requested=model_requested,
        model=model,
        decision=AuditDecision(
            action=action,
            applied=applied if applied is not None else ([action] if action != Action.allow else []),
            would_action=would_action,
            decided_by=decided_by,
            rule_ids=rule_ids or [],
            risk_score=0.31 if action != Action.allow else 0.0,
        ),
        verdicts=verdicts or [],
        route=route,
        approval=approval,
        labels_after=labels,
        usage=usage,
        versions=Versions(policy="p1"),
        prev_hash=GENESIS_HASH,
        hash=GENESIS_HASH,
    )


def _route(model: str = "local/qwen3.8-27b", tier: ConnectorTier = ConnectorTier.local, **factors: Any) -> RouteInfo:
    return RouteInfo(
        model_requested="auto",
        model=model,
        connector=model.split("/")[0],
        tier=tier,
        reason=f"auto → {model}",
        factors=factors,
    )


def test_pii_pseudonymise_sentence() -> None:
    ev = _event(
        Action.pseudonymise,
        rule_ids=["SEC-PII-01"],
        decided_by="SEC-PII-01",
        verdicts=[_verdict("SEC-PII-01", Action.pseudonymise, entities=["PESEL", "IBAN", "PERSON"])],
    )
    assert narrate.summary(ev) == (
        "Anna Nowak's prompt contained a PESEL, an IBAN and a name. "
        "They were replaced with placeholders before the model saw them."
    )


def test_pii_pseudonymise_and_route_local_sentence() -> None:
    ev = _event(
        Action.pseudonymise,
        applied=[Action.pseudonymise, Action.route_local],
        rule_ids=["SEC-PII-01"],
        decided_by="SEC-PII-01",
        verdicts=[_verdict("SEC-PII-01", Action.pseudonymise, entities=["PESEL"])],
        route=_route(data_class="confidential"),
        labels=SessionLabels(confidentiality=DataClass.confidential),
    )
    text = narrate.summary(ev)
    assert text.startswith("Anna Nowak's prompt contained a PESEL. It was replaced with a placeholder")
    assert text.endswith("and the request stayed on a local model because the data is confidential.")


def test_repeated_entities_are_counted() -> None:
    ev = _event(
        Action.redact,
        rule_ids=["SEC-PII-01"],
        decided_by="SEC-PII-01",
        verdicts=[_verdict("SEC-PII-01", Action.redact, entities=["PESEL", "PESEL", "EMAIL"])],
    )
    assert narrate.summary(ev).startswith("Anna Nowak's prompt contained 2 PESELs and an e-mail address.")


def test_session_label_sentence_uses_the_since_time() -> None:
    ev = _event(
        Action.route_local,
        rule_ids=["SEC-SESSION-01"],
        decided_by="SEC-SESSION-01",
        verdicts=[_verdict("SEC-SESSION-01", Action.route_local)],
        labels=SessionLabels(confidentiality=DataClass.confidential, since=T0),
    )
    assert narrate.summary(ev) == "This session is confidential since 14:03 UTC, so the request stayed on local models."


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        (
            {
                "action": Action.redact,
                "rule_ids": ["SEC-SECRET-01"],
                "verdicts": [_verdict("SEC-SECRET-01", Action.redact, entities=["API_KEY"])],
                "point": InspectionPoint.tool_result,
                "tool": "opencode.read",
            },
            "The opencode.read result for Anna Nowak contained an API key. It was removed before the model saw it.",
        ),
        (
            {
                "action": Action.block,
                "rule_ids": ["SEC-SECRET-01"],
                "verdicts": [_verdict("SEC-SECRET-01", Action.block, entities=["AWS_ACCESS_KEY"])],
            },
            "Anna Nowak's prompt contained an AWS access key, so the secret is never passed on. It was blocked.",
        ),
        (
            {
                "action": Action.sanitize,
                "rule_ids": ["SEC-PI-01"],
                "point": InspectionPoint.tool_result,
                "tool": "web.search",
                "verdicts": [_verdict("SEC-PI-01", Action.sanitize, phase=Phase.semantic_l1, entities=["INJECTION"])],
            },
            "The web.search result for Anna Nowak looked like it contained instructions aimed at the agent. "
            "The injected part was removed and the rest passed on.",
        ),
        (
            {
                "action": Action.require_approval,
                "rule_ids": ["SEC-FLOW-01", "SEC-FLOW-01.TRIFECTA"],
                "decided_by": "SEC-FLOW-01",
                "point": InspectionPoint.tool_call,
                "tool": "opencode.bash",
                "approval": ApprovalRef(approval_id="a1", approver_scope="admin"),
            },
            "Anna Nowak's agent tried to run opencode.bash after reading untrusted content and handling sensitive "
            "data (the Rule of Two). It is waiting for approval from the security team.",
        ),
        (
            {
                "action": Action.block,
                "rule_ids": ["SEC-TOOL-01"],
                "point": InspectionPoint.tool_call,
                "tool": "opencode.bash",
            },
            "Anna Nowak tried to use opencode.bash, but that is not allowed for them. "
            "The call was blocked before it ran.",
        ),
        (
            {
                "action": Action.block,
                "rule_ids": ["SEC-TOOL-01", "SEC-TOOL-01.UNKNOWN_TOOL"],
                "point": InspectionPoint.tool_call,
                "tool": "evil.tool",
            },
            "Anna Nowak tried to use evil.tool, which Rogatka does not know. The call was blocked before it ran.",
        ),
        (
            {"action": Action.block, "rule_ids": ["SEC-EXFIL-01"], "point": InspectionPoint.egress},
            "The answer to Anna Nowak contained a link that could send data to an outside address. It was blocked.",
        ),
        (
            {
                "action": Action.block,
                "rule_ids": ["SEC-MCP-01"],
                "point": InspectionPoint.mcp_tools_list,
                "server": "docs-search",
                "verdicts": [_verdict("SEC-MCP-01", Action.block, entities=["MCP_TOOL_DRIFT"])],
            },
            "The docs-search MCP server changed a tool description after it was approved. "
            "The tool was quarantined and an incident was opened.",
        ),
        (
            {
                "action": Action.block,
                "rule_ids": ["SIG-PKG-LITELLM-01"],
                "point": InspectionPoint.tool_call,
                "tool": "opencode.bash",
                "verdicts": [
                    _verdict("SEC-SIG-01", Action.block, rule_ids=["SIG-PKG-LITELLM-01"], entities=["SIGNATURE"])
                ],
            },
            "Anna Nowak's opencode.bash call matched a known-bad package on the known-threat list "
            "(SIG-PKG-LITELLM-01). It was blocked.",
        ),
        (
            {
                "action": Action.block,
                "rule_ids": ["FEED-CMD-0003"],
                "point": InspectionPoint.tool_call,
                "tool": "opencode.bash",
            },
            "Anna Nowak's opencode.bash call matched a dangerous command on the known-threat list (FEED-CMD-0003). "
            "It was blocked.",
        ),
        (
            {"action": Action.block, "rule_ids": ["SEC-BUDGET-01"]},
            "Anna Nowak reached a spending or usage limit, so the prompt was blocked.",
        ),
        (
            {"action": Action.block, "rule_ids": ["SEC-BUDGET-01", "SEC-BUDGET-01.BREAKER"]},
            "The circuit breaker on Anna Nowak's budget is open, so the prompt was blocked until it cools down.",
        ),
        (
            {"action": Action.route_local, "rule_ids": ["SEC-BUDGET-01"]},
            "Anna Nowak's budget is used up, so the request was served by a local model instead.",
        ),
        (
            {
                "action": Action.block,
                "rule_ids": ["SEC-LOOP-01", "SEC-LOOP-01.REPEAT"],
                "point": InspectionPoint.tool_call,
                "tool": "web.search",
            },
            "Anna Nowak's agent repeated web.search with the same arguments several times in a short while. "
            "The loop detector blocked it.",
        ),
        (
            {"action": Action.block, "rule_ids": ["SEC-MODEL-01"], "model_requested": "local-pl", "model": None},
            "Anna Nowak asked for local-pl, which they are not allowed to use. "
            "The request was blocked and an incident was opened.",
        ),
        (
            {"action": Action.block, "rule_ids": ["SEC-NOVEL-99"]},
            "Anna Nowak's prompt was blocked by rule SEC-NOVEL-99.",
        ),
        (
            {"action": Action.require_approval, "rule_ids": ["SEC-NOVEL-99"]},
            "Anna Nowak's prompt is waiting for a person's approval (SEC-NOVEL-99).",
        ),
    ],
)
def test_sentence_per_rule_family(kwargs: dict[str, Any], expected: str) -> None:
    assert narrate.summary(_event(**kwargs)) == expected


def test_monitor_mode_and_allow_sentences() -> None:
    monitored = _event(
        Action.monitor,
        would_action=Action.block,
        rule_ids=["SEC-SAFE-PL-01"],
        decided_by="SEC-SAFE-PL-01",
        point=InspectionPoint.egress,
    )
    assert narrate.summary(monitored) == (
        "The content-safety check flagged the answer to Anna Nowak. "
        "Monitor mode: it was logged, not enforced (it would have been block)."
    )
    assert narrate.summary(_event(user="Jan Kowalski")) == "Jan Kowalski's prompt went to gemini/flash unchanged."
    assert narrate.summary(_event(point=InspectionPoint.egress)) == (
        "The answer from gemini/flash to Anna Nowak passed the output checks unchanged."
    )


def test_possessive_and_fallback_name() -> None:
    assert narrate.summary(_event(user="Aleksandros")).startswith("Aleksandros' prompt")
    ev = _event()
    ev.principal.username = None  # type: ignore[union-attr]
    assert narrate.summary(ev).startswith("sub-Anna Nowak's prompt")


def test_summary_never_contains_raw_values_or_hashes() -> None:
    leaky = _verdict("SEC-PII-01", Action.pseudonymise, entities=["PESEL"])
    leaky.reason = f"found {PESEL}"  # a (wrongly) leaky reason must never reach the sentence or the changed steps
    ev = _event(Action.pseudonymise, rule_ids=["SEC-PII-01"], decided_by="SEC-PII-01", verdicts=[leaky])
    for text in (narrate.summary(ev), *narrate.changed_steps(ev).values()):
        assert PESEL not in text and "deadbeef" not in text and PESEL[:5] not in text


def test_system_event_sentences() -> None:
    ev = AuditEvent(
        event_id="s1",
        seq=3,
        timestamp=T0,
        event_type=EventType.system_alert,
        detail={"event": "kill_switch", "connector": "gemini", "engaged": True},
        versions=Versions(policy="p1"),
        prev_hash=GENESIS_HASH,
        hash=GENESIS_HASH,
    )
    assert narrate.summary(ev) == "An administrator engaged the kill switch for connector gemini."
    assert narrate.trace_steps(ev) == [] and narrate.changed_steps(ev) == {}


# ================================================================ unit: trace steps


def test_trace_steps_order_changed_flags_and_ms() -> None:
    ev = _event(
        Action.pseudonymise,
        applied=[Action.pseudonymise, Action.route_local],
        rule_ids=["SEC-PII-01"],
        decided_by="SEC-PII-01",
        verdicts=[
            _verdict("SEC-NORM-01", phase=Phase.normalise, latency_ms=0.4),
            _verdict("SEC-PII-01", Action.pseudonymise, entities=["PESEL", "IBAN"], latency_ms=2.0),
            _verdict("SEC-SECRET-01", latency_ms=1.0),
            _verdict("SEC-SIM-01", phase=Phase.similarity, latency_ms=14.0),
            _verdict("SEC-NER-01", Action.pseudonymise, phase=Phase.semantic_l1, entities=["PERSON"], score=0.97),
            _verdict("SEC-HYG-01", phase=Phase.egress_hygiene, latency_ms=5.0),
        ],
        route=_route(data_class="confidential"),
    )
    steps = narrate.trace_steps(ev)
    assert [s.step for s in steps] == [
        "identity",
        "normalise",
        "rules",
        "similarity",
        "classifier",
        "judge",
        "decide",
        "route",
        "output",
    ]
    by = {s.step: s for s in steps}
    assert by["rules"].changed and by["rules"].ms == 3.0
    assert [c.control_id for c in by["rules"].controls] == ["SEC-PII-01", "SEC-SECRET-01"]
    assert by["rules"].controls[0].findings == ["PESEL", "IBAN"]  # entity types only
    assert "a PESEL and an IBAN" in by["rules"].result
    assert by["classifier"].changed and "a name" in by["classifier"].result and "0.97" in by["classifier"].result
    assert not by["normalise"].changed and not by["similarity"].changed and not by["judge"].changed
    assert by["judge"].ms is None and by["similarity"].ms == 14.0
    assert by["decide"].changed and "pseudonymise + route_local" in by["decide"].result
    assert by["route"].changed and "auto → local/qwen3.8-27b (local)" in by["route"].result
    assert not by["output"].changed and by["output"].ms == 5.0
    assert narrate.changed_steps(ev).keys() == {"rules", "classifier", "decide", "route"}
    assert not any(PESEL in s.result for s in steps)


def test_approval_step_only_when_held() -> None:
    held = _event(
        Action.require_approval,
        point=InspectionPoint.tool_call,
        tool="opencode.bash",
        rule_ids=["SEC-FLOW-01"],
        approval=ApprovalRef(approval_id="a1", approver_scope="admin", expires_at=T0 + timedelta(minutes=10)),
    )
    names = [s.step for s in narrate.trace_steps(held)]
    assert names.index("approval") == names.index("decide") + 1 and names.index("route") == names.index("approval") + 1
    approval = next(s for s in narrate.trace_steps(held) if s.step == "approval")
    assert approval.changed and "14:13 UTC" in approval.result
    assert "approval" not in [s.step for s in narrate.trace_steps(_event())]


def test_session_label_helpers() -> None:
    assert narrate.model_saw_note(_event()) == ""
    ev = _event(Action.pseudonymise, verdicts=[_verdict("SEC-PII-01", Action.pseudonymise, entities=["PESEL", "IBAN"])])
    assert narrate.model_saw_note(ev) == "2 values replaced with placeholders; the original values never left Rogatka."
    sanitized = _event(Action.sanitize, verdicts=[_verdict("SEC-PI-01", Action.sanitize, entities=["INJECTION"])])
    assert narrate.content_changed(sanitized) and "removed" in narrate.model_saw_note(sanitized)
    assert not narrate.content_changed(_event(Action.route_local))


def test_last_message_text_picks_the_final_message_only() -> None:
    pairs = [
        ("messages[0].content", "first <PESEL_1>"),
        ("messages[1].content", "answer"),
        ("messages[2].content[0].text", "new "),
        ("messages[2].content[1].text", "turn"),
        ("messages[2].name", "ignored"),
        ("params.stop[0]", "x"),
    ]
    assert last_message_text(pairs) == "new \nturn"
    assert last_message_text([("content", "no chat")]) is None


def test_timeline_buckets() -> None:
    assert [bucket_seconds(timedelta(minutes=m)) for m in (15, 60)] == [60, 300]
    assert bucket_seconds(timedelta(hours=24)) == 3600 and bucket_seconds(timedelta(days=7)) == 86400
    now = datetime(2026, 10, 3, 14, 3, 30, tzinfo=UTC)
    rows = [(now - timedelta(seconds=5), "allow"), (now - timedelta(seconds=10), "allow"), (now, "block")]
    buckets = decision_timeline(rows, now - timedelta(minutes=15), now, 60)
    assert len(buckets) == 16 and buckets[-1].start == datetime(2026, 10, 3, 14, 3, tzinfo=UTC)
    assert buckets[-1].counts == {"allow": 2, "block": 1} and buckets[0].counts == {}


# ================================================================ API


def hdr(user: str, groups: str, roles: str = "") -> dict[str, str]:
    h = {"X-ACL-Dev-User": user, "X-ACL-Dev-Groups": groups}
    if roles:
        h["X-ACL-Dev-Roles"] = roles
    return h


ANNA = hdr("anna", "developers")
JAN = hdr("jan", "credit-analysts")
ANALYST = hdr("ola", "security-analysts", "acl-analyst")
VIEWER = hdr("vera", "security-analysts", "acl-viewer")
SESSION = "conv-1"
PROMPT = f"Przygotuj notatke dla klienta, PESEL {PESEL}, prosze."


@pytest.fixture
def app(tmp_path: Path) -> Iterator[Any]:
    settings = Settings(
        policy_dir=REPO / "policy",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'acl.db'}",
        audit_path=tmp_path / "audit.jsonl",
        deterministic=True,
        value_hash_salt="test-salt",  # type: ignore[arg-type]
    )
    application = create_app(settings, allow_anonymous_dev=True)
    with TestClient(application) as client:
        application.state.test_client = client
        yield application


def chat(app: Any, who: dict[str, str], messages: list[dict[str, str]], *, session: str = SESSION, **extra: Any):
    headers = {**who, "X-Session-Id": session, "X-Client-App": "librechat"}
    body = {"model": "auto", "messages": messages, **extra}
    return app.state.test_client.post("/v1/chat/completions", headers=headers, json=body)


def traffic(app: Any) -> None:
    """Anna: a PESEL prompt, then a PII-free turn in the same session, then a forbidden model. Jan: a plain prompt."""
    assert chat(app, ANNA, [{"role": "user", "content": PROMPT}]).status_code == 200
    follow_up = [
        {"role": "user", "content": PROMPT},
        {"role": "assistant", "content": "Gotowe."},
        {"role": "user", "content": "Podsumuj to w trzech punktach."},
    ]
    assert chat(app, ANNA, follow_up).status_code == 200
    assert chat(app, JAN, [{"role": "user", "content": "Hello there"}], session="j-1").status_code == 200
    forbidden = chat(app, ANNA, [{"role": "user", "content": "hi"}], session="s-bad", model="local-pl")
    assert forbidden.status_code == 403


def get(app: Any, path: str, who: dict[str, str] = ANALYST, **params: Any):
    return app.state.test_client.get(f"{BASE}{path}", headers=who, params=params)


def events(app: Any, **params: Any) -> list[dict[str, Any]]:
    r = get(app, "/events", limit=200, **params)
    assert r.status_code == 200, r.text
    return r.json()


def test_events_are_enriched(app) -> None:
    traffic(app)
    rows = events(app)
    first = next(e for e in rows if e["point"] == "ingress" and e["rule_ids"] == ["SEC-PII-01"])
    assert first["username"] == "anna" and first["client_app"] == "librechat"
    assert first["action"] == "pseudonymise" and "pseudonymise" in first["applied"]
    assert first["data_class"] == "confidential" and first["tier"] == "local" and first["degraded"] is False
    assert first["summary"].startswith("anna's prompt contained a PESEL. It was replaced with a placeholder")
    assert PESEL not in json.dumps(rows) and PESEL[:6] not in first["summary"]
    assert set(first["changed_steps"]) >= {"rules", "decide", "route"}
    assert first["session_label"]["data_class"] == "confidential" and first["session_label"]["local_only"] is True
    assert first["session_label"]["trust"] == "trusted" and first["session_label"]["since"]
    ref = first["client_ref"]
    assert ref["kind"] == "conversation" and ref["client"] == "librechat" and ref["id"].endswith(f":{SESSION}")
    assert ref["message_count"] == 2 and ref["started_at"]  # two ingress events in this conversation
    # a later turn without PII is pinned to local models by the session label
    pinned = next(e for e in rows if "SEC-SESSION-01" in e["rule_ids"])
    assert pinned["summary"].startswith("This session is confidential since ")
    assert pinned["summary"].endswith("UTC, so the request stayed on local models.")
    assert pinned["session_label"]["local_only"] is True
    # answers carry tokens; plain allows read as one unchanged sentence
    answer = next(e for e in rows if e["point"] == "egress" and e["username"] == "jan")
    assert answer["tokens_in"] > 0 and answer["tokens_out"] > 0 and answer["applied"] == []
    plain = next(e for e in rows if e["point"] == "ingress" and e["username"] == "jan")
    assert plain["summary"].startswith("jan's prompt went to ") and plain["summary"].endswith(" unchanged.")
    assert plain["changed_steps"] == {} and plain["session_label"]["local_only"] is False
    blocked = next(e for e in rows if e["action"] == "block")
    assert blocked["rule_ids"][0] == "SEC-MODEL-01"
    assert blocked["summary"] == (
        "anna asked for local-pl, which they are not allowed to use. "
        "The request was blocked and an incident was opened."
    )
    assert blocked["applied"] == ["block"]


def test_event_trace(app) -> None:
    traffic(app)
    ev = next(e for e in events(app) if e["point"] == "ingress" and e["rule_ids"] == ["SEC-PII-01"])
    r = get(app, f"/events/{ev['event_id']}/trace", VIEWER)  # viewers may read traces
    assert r.status_code == 200, r.text
    trace = r.json()
    assert [s["step"] for s in trace["steps"]] == [
        "identity",
        "normalise",
        "rules",
        "similarity",
        "classifier",
        "judge",
        "decide",
        "route",
        "output",
    ]
    steps = {s["step"]: s for s in trace["steps"]}
    assert steps["rules"]["changed"] and steps["rules"]["controls"][0]["control_id"] in {"SEC-PII-01", "SEC-MODEL-01"}
    pii = next(c for c in steps["rules"]["controls"] if c["control_id"] == "SEC-PII-01")
    assert pii["findings"] == ["PESEL"] and pii["action"] == "pseudonymise"
    assert steps["route"]["changed"] is True and "local" in steps["route"]["result"]
    assert trace["event"]["event_id"] == ev["event_id"] and trace["record"]["event_id"] == ev["event_id"]
    assert "<PESEL_1>" in trace["model_saw"] and PESEL not in trace["model_saw"]
    assert trace["model_saw_note"] == "1 value replaced with placeholders; the original values never left Rogatka."
    assert PESEL not in json.dumps(trace)
    # an unchanged event shows no "what the model saw"
    plain = next(e for e in events(app) if e["username"] == "jan" and e["point"] == "ingress")
    plain_trace = get(app, f"/events/{plain['event_id']}/trace", VIEWER).json()
    assert plain_trace["model_saw"] is None and plain_trace["model_saw_note"] == ""
    assert get(app, "/events/nope/trace", VIEWER).status_code == 404


def test_session_transcript(app) -> None:
    traffic(app)
    ref = next(e for e in events(app) if e["rule_ids"] == ["SEC-PII-01"])["client_ref"]
    sid = ref["id"]
    assert ":" in sid
    t = get(app, f"/sessions/{quote(sid, safe='')}/transcript")  # the id contains a colon; works URL-encoded
    assert t.status_code == 200, t.text
    body = t.json()
    assert body["session_id"] == sid and body["username"] == "anna" and body["groups"] == ["developers"]
    assert body["client_ref"]["kind"] == "conversation" and body["client_ref"]["message_count"] == 2
    assert body["session_label"]["data_class"] == "confidential" and body["session_label"]["local_only"] is True
    assert body["started_at"] <= body["last_at"] and body["truncated"] is False
    roles = [x["role"] for x in body["turns"]]
    assert roles == ["user", "assistant", "user", "assistant"]
    user1, assistant1, user2, _ = body["turns"]
    assert user1["retained"] and "<PESEL_1>" in user1["text"] and PESEL not in user1["text"]
    assert user1["text"] == "Przygotuj notatke dla klienta, PESEL <PESEL_1>, prosze."  # the last message only
    assert user2["text"] == "Podsumuj to w trzech punktach."  # history is not repeated in later turns
    assert assistant1["retained"] and PESEL not in assistant1["text"]
    assert user1["action"] == "pseudonymise" and user1["rule_ids"] == ["SEC-PII-01"] and user1["summary"]
    assert [x["seq"] for x in body["turns"]] == sorted(x["seq"] for x in body["turns"])
    assert PESEL not in t.text
    # limit / truncated
    short = get(app, f"/sessions/{quote(sid, safe='')}/transcript", limit=2).json()
    assert short["truncated"] is True and len(short["turns"]) == 2
    # analysts only, and unknown sessions are 404
    assert get(app, f"/sessions/{quote(sid, safe='')}/transcript", VIEWER).status_code == 403
    assert get(app, "/sessions/ns%3Anone/transcript").status_code == 404


def test_transcript_without_stored_payloads_has_no_text(app) -> None:
    app.state.engine.policy.global_.store_redacted_payloads = False
    assert chat(app, ANNA, [{"role": "user", "content": PROMPT}]).status_code == 200
    sid = events(app)[0]["session_id"]
    body = get(app, f"/sessions/{quote(sid, safe='')}/transcript").json()
    assert body["turns"] and all(t["text"] is None and t["retained"] is False for t in body["turns"])


def test_user_stats_preset_and_activity(app) -> None:
    traffic(app)
    c = app.state.test_client
    for who in (ANNA, JAN):  # JIT-provision the people (dev-header principals are not authenticated through JWT)
        p = Principal(
            subject=f"dev-{who['X-ACL-Dev-User']}",
            username=who["X-ACL-Dev-User"],
            groups=[who["X-ACL-Dev-Groups"]],
        )
        c.portal.call(app.state.identity.users.provision, p)
    users = {u["username"]: u for u in get(app, "/users", VIEWER).json()}
    anna, jan = users["anna"], users["jan"]
    assert anna["preset"] == "balanced" and jan["preset"] == "strict"
    stats = anna["stats_7d"]
    # anna: 2 PESEL prompts + 1 forbidden-model prompt started; 2 answers are replies
    assert stats["window"] == "7d" and stats["requests"] == 3 and stats["blocks"] == 1
    assert stats["tokens_in"] > 0 and stats["tokens_out"] > 0 and stats["last_active"]
    assert jan["stats_7d"]["requests"] == 1 and jan["stats_7d"]["blocks"] == 0
    one = get(app, f"/users/{anna['id']}", VIEWER).json()
    assert one["stats_7d"]["requests"] == 3 and one["preset"] == "balanced"
    # activity: analysts see the person's enriched events, newest first
    act = get(app, f"/users/{anna['id']}/activity")
    assert act.status_code == 200
    rows = act.json()
    assert rows and {r["username"] for r in rows} == {"anna"} and all(r["summary"] for r in rows)
    assert [r["seq"] for r in rows] == sorted((r["seq"] for r in rows), reverse=True)
    assert get(app, f"/users/{anna['id']}/activity", VIEWER).status_code == 403
    assert get(app, "/users/nobody/activity").status_code == 404


def test_overview_cost_timeline_and_budget_fields(app) -> None:
    traffic(app)
    ov = get(app, "/metrics/overview", VIEWER, window="15m").json()
    assert ov["decisions_total"] == sum(ov["decisions_by_action"].values()) > 0
    assert (
        len(ov["timeline"]) in (15, 16)
        and sum(sum(b["counts"].values()) for b in ov["timeline"]) == ov["decisions_total"]
    )
    assert all(b["start"] for b in ov["timeline"])
    assert {m["model"] for m in ov["cost_by_model"]} >= {"local/qwen3.8-27b"}
    local = next(m for m in ov["cost_by_model"] if m["model"] == "local/qwen3.8-27b")
    assert local["tier"] == "local" and local["tokens_in"] > 0 and local["tokens_out"] > 0 and local["gpu_seconds"] > 0
    assert abs(sum(m["share"] for m in ov["cost_by_model"]) - 1.0) < 1e-3
    assert ov["cost_by_model"] == sorted(ov["cost_by_model"], key=lambda m: -(m["tokens_in"] + m["tokens_out"]))
    assert ov["usd_today"] >= 0 and ov["usd_forecast_day"] >= ov["usd_today"]
    assert ov["gpu_seconds_today"] > 0 and ov["gpu_seconds_limit_day"] == 3600
    assert ov["usd_limit_day"] == pytest.approx(100 / 30)  # org usd_month / 30 (no org usd_day in the seed)
    assert ov["incidents_by_severity"] and sum(ov["incidents_by_severity"].values()) == ov["open_incidents"]
    assert 0 <= ov["posture_score"] <= 100
    day = get(app, "/metrics/overview", VIEWER, window="7d").json()
    assert len(day["timeline"]) in (7, 8) and day["decisions_total"] == ov["decisions_total"]
    hour = get(app, "/metrics/overview", VIEWER, window="1h").json()
    assert len(hour["timeline"]) in (12, 13)


def test_models_carry_role_and_usage(app) -> None:
    traffic(app)
    models = {m["id"]: m for m in get(app, "/models", VIEWER).json()}
    local = models["local/qwen3.8-27b"]
    assert local["requests_day"] >= 2 and local["tokens_in_day"] > 0 and local["tokens_out_day"] > 0
    assert local["gpu_seconds_day"] > 0 and local["usd_day"] >= 0 and local["role"] is None
    assert models["local/embed"]["requests_day"] == 0 and models["local/embed"]["tokens_in_day"] == 0
    # a `role` tag shows up as the model's role
    app.state.engine.policy.models[0].tags["role"] = "local, all confidential work"
    again = {m["id"]: m for m in get(app, "/models", VIEWER).json()}
    assert again[app.state.engine.policy.models[0].id]["role"] == "local, all confidential work"


def test_sse_summaries_are_enriched(app) -> None:
    hub = app.state.event_stream
    seen: list[Any] = []
    with hub.subscribe() as sub:
        assert chat(app, ANNA, [{"role": "user", "content": PROMPT}]).status_code == 200
        while not sub.queue.empty():
            seen.append(sub.queue.get_nowait())
    first = next(s for s in seen if s.point == InspectionPoint.ingress)
    assert (
        first.summary.startswith("anna's prompt contained a PESEL") and first.changed_steps and first.client_ref is None
    )
    assert PESEL not in first.model_dump_json()
