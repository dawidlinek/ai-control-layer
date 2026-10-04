"""Typed admin fields: approval details (approver label, data class, client, flags, preview, reasons) and typed
incident evidence. Additive: the old free-form fields keep their content."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import TypeAdapter

from acl.approvals.typed import approver_label, preview_of, reasons_of
from acl.audit.evidence import evidence_for
from acl.contracts.admin import Approval, GenericEvidence, Incident, IncidentEvidence
from acl.contracts.common import Action
from acl.contracts.decision import Verdict
from acl.main import create_app
from acl.settings import Settings

REPO = Path(__file__).resolve().parents[2]
WS = "/work/proj"
BASE = "/admin/v1"


def hdr(user: str, groups: str, roles: str = "") -> dict[str, str]:
    h = {"X-ACL-Dev-User": user, "X-ACL-Dev-Groups": groups}
    if roles:
        h["X-ACL-Dev-Roles"] = roles
    return h


ANNA = hdr("anna", "developers")
VIEWER = hdr("vera", "security-analysts", "acl-viewer")


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


def decide(app: Any, tool: str, args: dict[str, Any], *, session: str, who: dict[str, str] = ANNA) -> dict[str, Any]:
    action = {"tool": tool, "arguments": args, "workspace_root": WS, "cwd": WS}
    r = app.state.test_client.post(
        "/v1/decide", json={"session_id": session, "action": action, "client": {"app": "opencode"}}, headers=who
    )
    assert r.status_code == 200, r.text
    return r.json()


def admin_approval(app: Any, approval_id: str) -> dict[str, Any]:
    r = app.state.test_client.get(f"{BASE}/approvals/{approval_id}", headers=VIEWER)
    assert r.status_code == 200, r.text
    return r.json()


# ============================================================ approvals


def test_rule_of_two_hold_carries_typed_fields(app) -> None:
    decide(app, "opencode.read", {"filePath": "README.md"}, session="t-r2")
    r = decide(app, "web.fetch", {"url": "https://example.org/collect?d=1"}, session="t-r2")
    assert r["action"] == "require_approval"
    a = admin_approval(app, r["approval"]["approval_id"])
    Approval.model_validate(a)
    assert a["approver_scope"] == "admin" and a["approver_label"] == "Security team"
    assert a["data_class"] in ("confidential", "restricted")
    assert a["client"] == "opencode"
    assert {"untrusted input", "sensitive data", "external egress"} <= set(a["flags"])
    assert a["reasons"] and any("untrusted input" in x for x in a["reasons"])
    assert a["preview"]["type"] == "text" and a["preview"]["body"].startswith("web.fetch")
    assert "example.org" in a["preview"]["body"]
    # the old free-form fields are untouched
    assert a["arguments_preview"] == a["preview"]["body"] and a["reason"] and "SEC-FLOW-01" in a["rule_ids"]


def test_user_scope_hold_has_team_lead_label_and_no_flow_flags(app) -> None:
    r = decide(app, "opencode.bash", {"command": "make deploy"}, session="t-user")
    a = admin_approval(app, r["approval"]["approval_id"])
    assert a["approver_scope"] == "user" and a["approver_label"] == "Team lead"
    assert a["data_class"] == "public" and a["client"] == "opencode"
    assert "untrusted input" not in a["flags"] and "sensitive data" not in a["flags"]
    assert a["reasons"] and all(isinstance(x, str) and x for x in a["reasons"])
    assert a["preview"]["type"] == "text" and "make deploy" in a["preview"]["body"]


def test_mail_tool_preview_is_an_email(app) -> None:
    mail = {"to": "a@corp.example", "subject": "Quarterly numbers", "body": "SECRETBODY"}
    r = decide(app, "mail.send", mail, session="t-mail")
    a = admin_approval(app, r["approval"]["approval_id"])
    assert a["preview"]["type"] == "email"
    assert "a@corp.example" in a["preview"]["body"] and "Quarterly numbers" in a["preview"]["body"]
    assert "SECRETBODY" not in json.dumps(a)  # undisplayed fields appear only as `key=<n chars>`


def test_listing_and_user_api_expose_the_same_typed_fields(app) -> None:
    r = decide(app, "opencode.bash", {"command": "make deploy"}, session="t-list")
    aid = r["approval"]["approval_id"]
    listed = app.state.test_client.get(f"{BASE}/approvals", headers=VIEWER).json()
    row = next(x for x in listed if x["id"] == aid)
    assert row["approver_label"] == "Team lead"
    assert row["reasons"] and row["preview"] and row["client"] == "opencode"
    # decided approvals keep the typed fields
    app.state.test_client.post(f"/v1/approvals/{aid}/decision", json={"decision": "deny"}, headers=ANNA)
    denied = admin_approval(app, aid)
    assert denied["status"] == "denied" and denied["reasons"] == row["reasons"] and denied["preview"] == row["preview"]


def test_rows_created_before_the_typed_fields_still_load(app) -> None:
    """An approval whose `detail` column is empty (older rows) gets safe defaults and a derived approver label."""
    import asyncio

    from acl.approvals.db_models import ApprovalRow

    r = decide(app, "opencode.bash", {"command": "make deploy"}, session="t-old")
    aid = r["approval"]["approval_id"]
    svc = app.state.approvals

    async def blank() -> None:
        async with svc._sessions()() as s:
            row = await s.get(ApprovalRow, aid)
            row.detail = {}
            await s.commit()

    app.state.test_client.portal.call(blank) if hasattr(app.state.test_client, "portal") else asyncio.run(blank())
    a = admin_approval(app, aid)
    assert a["approver_label"] == "Team lead"
    assert a["data_class"] is None and a["client"] is None and a["preview"] is None
    assert a["flags"] == [] and a["reasons"] == []


def test_approver_label_mapping() -> None:
    assert approver_label("admin") == "Security team" and approver_label("security") == "Security team"
    assert approver_label("user") == "Team lead" and approver_label("team_lead") == "Team lead"
    assert approver_label("nobody") is None


@pytest.mark.parametrize(
    ("tool", "text", "kind"),
    [
        ("bash", "bash\ncommand: git push origin main", "text"),
        ("mail.send", "mail.send\nto: a@corp.example", "email"),
        ("email.send", "email.send\nsubject: hi", "email"),
        ("fs.patch", "fs.patch\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b", "diff"),
        ("bash", "bash\ncommand: terraform apply\nPlan: 2 to add, 1 to change, 0 to destroy", "plan"),
        ("opencode.write", "opencode.write\npath: a.py\ncontent=<12 chars>", "text"),
    ],
)
def test_preview_type(tool: str, text: str, kind: str) -> None:
    p = preview_of(tool, text)
    assert p is not None and p.type == kind and p.body == text


def test_preview_of_nothing_is_none() -> None:
    assert preview_of("bash", "\n\n") is None


def test_reasons_are_distinct_sentences_from_the_holding_controls() -> None:
    def v(reason: str | None, action: Action = Action.require_approval) -> Verdict:
        return Verdict(
            control_id="c",
            control_type="tool_policy",
            phase="decide",
            cost_tier="deterministic",
            action=action,
            reason=reason,
        )  # type: ignore[arg-type]

    out = reasons_of([v("a is risky; b is risky"), v("a is risky"), v(None), v("  ")])
    assert out == ["a is risky", "b is risky"]


# ============================================================ incidents: evidence

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def ev(category: str, detail: dict[str, Any]) -> dict[str, Any]:
    out = evidence_for(category, detail, NOW)
    return TypeAdapter(IncidentEvidence).dump_python(out, mode="json")


def test_rug_pull_evidence_from_the_producer_detail() -> None:
    e = ev(
        "mcp_rug_pull",
        {
            "server": "docs-search",
            "tool": "search_docs",
            "tool_id": "docs-search.search_docs",
            "status": "quarantined",
            "reasons": ["hidden instruction", "reads ~/.ssh"],
            "pinned_hash": "9c1e44b2f0d3a07b",
            "current_hash": "41f2c8e57b19d9e0",
            "description_diff": "+<IMPORTANT>\n-old",
            "pinned_at": "2026-10-01T09:00:00+00:00",
            "changed_at": None,
        },
    )
    assert e["kind"] == "mcp_rug_pull" and e["server"] == "docs-search" and e["tool_id"] == "docs-search.search_docs"
    assert e["approved_hash"] == "9c1e44b2f0d3a07b" and e["new_hash"] == "41f2c8e57b19d9e0"
    assert e["approved_at"].startswith("2026-10-01T09:00:00")
    assert e["changed_at"].startswith("2026-10-04T12:00:00")  # falls back to the incident's creation time
    assert e["findings"] == ["hidden instruction", "reads ~/.ssh"] and e["description_diff"] == "+<IMPORTANT>\n-old"
    assert "quarantined" in e["summary"]


@pytest.mark.parametrize("category", ["mcp_tool_poisoning", "mcp_name_collision"])
def test_flagged_tool_evidence(category: str) -> None:
    e = ev(category, {"server": "s", "tool": "t", "tool_id": "s.t", "status": "quarantined", "reasons": ["x"]})
    assert e["kind"] == category and e["tool_id"] == "s.t" and e["findings"] == ["x"]


def test_budget_breach_evidence_for_breaker_hard_soft_and_loop() -> None:
    trip = ev(
        "budget_breach",
        {"level": "hard", "breaker": "open", "node": "session:s_77c1", "meter": "gpu_seconds_session", "limit": 120,
         "used": 120.0, "cooldown_s": 300, "rule_ids": ["SEC-BUDGET-01.BREAKER"]},
    )  # fmt: skip
    assert trip["kind"] == "budget_breach" and trip["breaker"] == "open" and trip["session_id"] == "s_77c1"
    assert trip["limit"] == 120.0 and trip["used"] == 120.0 and trip["cooldown_s"] == 300
    assert "circuit breaker" in trip["summary"]
    soft = ev("budget_breach", {"level": "soft", "node": "user:jan", "meter": "usd_day", "limit": 5, "used": 4.2,
                                "projected": 4.6, "action": "alert"})  # fmt: skip
    assert soft["level"] == "soft" and soft["session_id"] is None and soft["breaker"] is None
    assert soft["projected"] == 4.6 and soft["action"] == "alert"
    loop = ev("budget_breach", {"level": "loop", "rule_ids": ["SEC-LOOP-01.REPEAT"], "action": "block"})
    assert loop["level"] == "loop" and loop["loop_rule"] == "SEC-LOOP-01.REPEAT"


def test_other_category_evidence() -> None:
    assert ev("forbidden_model", {"model": "local-pl"})["model"] == "local-pl"
    blocked = ev("blocked_request", {"point": "ingress", "decided_by": "SEC-PII-01"})
    assert blocked["kind"] == "blocked_request" and blocked["decided_by"] == "SEC-PII-01"
    assert ev("blocked_response", {})["kind"] == "blocked_response"
    proto = ev("mcp_protocol_violation", {"server": "s", "violations": ["MCP_ORIGIN_MISMATCH"]})
    assert proto["violations"] == ["MCP_ORIGIN_MISMATCH"]
    canary = ev("canary_triggered", {"tool": "t", "server": "s", "canary_occurrences": 2})
    assert canary["occurrences"] == 2
    bypass = ev("plugin_bypass", {"tool": "bash", "tool_call_id_hash": "ab12", "explanation": "x"})
    assert bypass["tool"] == "bash" and bypass["tool_call_id_hash"] == "ab12"


def test_unknown_category_and_malformed_detail_fall_back_to_generic() -> None:
    g = ev("something_new", {"title": "A thing", "count": 3, "nested": {"a": 1}, "flag": True, "long": "x" * 500})
    assert g["kind"] == "generic" and g["category"] == "something_new" and g["summary"] == "A thing"
    assert g["facts"]["count"] == 3 and g["facts"]["flag"] is True and len(g["facts"]["long"]) == 200
    assert "nested" not in g["facts"]
    assert isinstance(evidence_for("something_new", None), GenericEvidence)
    # wrong types never raise: the known builder is skipped for a generic view
    weird = ev("budget_breach", {"level": ["x"], "limit": "lots", "node": 5, "cooldown_s": "soon"})
    assert weird["kind"] == "budget_breach" and weird["limit"] is None and weird["node"] is None


def test_incident_model_round_trips_with_and_without_evidence() -> None:
    base = {
        "id": "i1",
        "title": "t",
        "category": "forbidden_model",
        "severity": "medium",
        "status": "open",
        "created_at": NOW,
        "updated_at": NOW,
    }
    plain = Incident.model_validate(base)
    assert plain.evidence is None and plain.detail == {}
    typed = Incident.model_validate({**base, "evidence": {"kind": "forbidden_model", "model": "m"}})
    assert typed.evidence is not None and typed.evidence.kind == "forbidden_model"
    with pytest.raises(ValueError):
        Incident.model_validate({**base, "evidence": {"kind": "nope"}})


def test_forbidden_model_incident_through_the_admin_api(app) -> None:
    c = app.state.test_client
    headers = {**ANNA, "X-Session-Id": "s-bad", "X-Client-App": "librechat"}
    bad = c.post(
        "/v1/chat/completions",
        headers=headers,
        json={"model": "local-pl", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert bad.status_code == 403
    incidents = c.get(f"{BASE}/incidents", headers=VIEWER).json()
    inc = next(i for i in incidents if i["category"] == "forbidden_model")
    Incident.model_validate(inc)
    assert inc["detail"]["model"] == "local-pl" and inc["detail"]["category"] == "forbidden_model"  # detail unchanged
    assert inc["evidence"]["kind"] == "forbidden_model" and inc["evidence"]["model"] == "local-pl"
    one = c.get(f"{BASE}/incidents/{inc['id']}", headers=VIEWER).json()
    assert one["evidence"] == inc["evidence"]
