"""CP1 demo slice against the running stack (`make up`, then `make e2e`).

Written against the documented interfaces (concept §5, §11, §13, contracts/admin-api.openapi.yaml); they fail
until the owning tasks (1A API/audit/SSE, 1B hot reload, 1C identity, 1D controls/feed) are merged and skip
cleanly when the stack is down. Demo users and groups come from deploy/keycloak/realm-export.json:
jan (credit-analysts, preset strict), adam (admins). Secrets never appear in assertion messages.
"""

from __future__ import annotations

import re
import time
import uuid

import pytest
from e2e.helpers import PESEL_EXAMPLE, SseEvent, add_feed_rule, remove_feed_rule
from oracle.leak import LeakOracle

pytestmark = pytest.mark.e2e

SSE_DEADLINE_S = 1.0
HOT_RELOAD_DEADLINE_S = 2.0


def _is_decision_for(user: str, since: float):  # type: ignore[no-untyped-def]
    return lambda e: e.data.get("username") == user and e.data.get("event_type") == "decision" and e.t >= since - 0.5


def test_cp1_pesel_pseudonymised_routed_local_and_audited(stack, sse) -> None:
    """(a) PESEL from jan: placeholder upstream, local route, full trace in the audit log, live on SSE within 1 s."""
    sent = time.monotonic()
    r = stack.chat("jan", f"Mój PESEL to {PESEL_EXAMPLE}, proszę o podsumowanie.")
    answered = time.monotonic()
    assert r.status_code == 200, f"chat failed: HTTP {r.status_code} {r.text[:300]}"
    body = r.json()

    oracle = LeakOracle({"pesel": PESEL_EXAMPLE})
    oracle.assert_clean(body, channel="chat_response", what="the response to jan")
    content = body["choices"][0]["message"]["content"] or ""
    if content.startswith("MOCK["):  # deterministic mode: the mock echoes what the upstream received
        assert "<PESEL" in content, "upstream should have received a placeholder, not the raw value"

    ev = sse.wait_for(_is_decision_for("jan", sent), timeout=SSE_DEADLINE_S)
    assert ev is not None, f"no decision event for jan on the SSE stream within {SSE_DEADLINE_S}s of the response"
    assert ev.t - answered <= SSE_DEADLINE_S

    event_id = ev.data["event_id"]
    got = stack.admin("GET", f"/events/{event_id}")
    assert got.status_code == 200, f"GET /events/{event_id}: HTTP {got.status_code}"
    audit = got.json()
    oracle.assert_clean(audit, channel="audit_record", what="the audit record")  # rule 2: no raw values at rest
    decision = audit["decision"]
    applied = set(decision["applied"])
    assert applied & {"pseudonymise", "route_local"}, f"PESEL must be transformed, applied={sorted(applied)}"
    assert any(f["entity_type"] == "PESEL" for v in audit["verdicts"] for f in v["findings"]), "no PESEL finding"
    assert audit["route"]["tier"] == "local", f"route must be local, got {audit.get('route')}"
    assert audit["versions"]["policy"] and audit["prev_hash"] and audit["hash"]
    assert audit["principal"]["username"] == "jan"
    assert audit["trace_id"] == ev.data.get("trace_id")


def test_cp1_forbidden_model_is_403(stack) -> None:
    """(b) jan's group may not use `smart` (cloud): 403 `forbidden_model`."""
    r = stack.chat("jan", "Hello", model="smart")
    assert r.status_code == 403, f"expected 403, got HTTP {r.status_code}: {r.text[:300]}"
    assert "forbidden_model" in r.text


def test_cp1_feed_rule_blocks_next_matching_request(stack, sse) -> None:
    """(c) A rule published through the feed server + `POST /admin/v1/feed/sync` blocks the next matching request."""
    marker = f"ACLE2E{uuid.uuid4().hex[:12].upper()}"
    rule_id = f"SIG-E2E-{marker}"
    prompt = f"Please summarise the note tagged {marker}."
    before = stack.chat("anna", prompt)
    assert before.status_code == 200, f"baseline request should pass, got HTTP {before.status_code} {before.text[:200]}"

    entry = {
        "id": rule_id,
        "type": "regex",
        "pattern": marker,
        "severity": "high",
        "action": "block",
        "stages": ["ingress"],
        "description": "e2e: temporary rule",
        "source": "internal",
    }
    if not add_feed_rule(stack, entry):
        pytest.skip("feed server rule publishing unavailable (POST /entries; FEED_ADMIN_TOKEN set?)")
    try:
        synced = stack.admin("POST", "/feed/sync")
        assert synced.status_code == 200, f"feed sync failed: HTTP {synced.status_code} {synced.text[:200]}"
        after = stack.chat("anna", prompt)
        assert after.status_code in (400, 403, 451), f"request should be blocked, got HTTP {after.status_code}"
        ev = sse.wait_for(
            lambda e: e.data.get("event_type") == "decision" and rule_id in (e.data.get("rule_ids") or []),
            timeout=SSE_DEADLINE_S,
        )
        assert ev is not None, f"no event naming rule {rule_id}"
        assert ev.data.get("action") == "block"
    finally:
        remove_feed_rule(stack, rule_id)
        stack.admin("POST", "/feed/sync")


def _policy_version(stack) -> str:
    r = stack.admin("GET", "/policy")
    if r.status_code != 200:
        pytest.skip(f"GET /admin/v1/policy unavailable (HTTP {r.status_code}); Phase 1B to provide")
    return r.json()["version"]


def _decision_after(stack, sse: object, since: float) -> tuple[str, str]:
    """(policy version, action) of the newest decision event for jan after `since`."""
    ev: SseEvent | None = sse.wait_for(_is_decision_for("jan", since), timeout=SSE_DEADLINE_S)  # type: ignore[attr-defined]
    assert ev is not None, "no decision event on the SSE stream"
    audit = stack.admin("GET", f"/events/{ev.data['event_id']}").json()
    return audit["versions"]["policy"], audit["decision"]["action"]


def test_cp1_policy_hot_reload_changes_next_request_within_2s(stack, sse) -> None:
    """(d) Edit a group preset in policy/groups.yaml; the next request reflects it within 2 s. File restored after."""
    from acl.policy.loader import load_policy_dir

    policy_dir = stack.cfg.policy_dir
    groups_file = policy_dir / "groups.yaml"
    if _policy_version(stack) != load_policy_dir(policy_dir).version:
        pytest.skip(
            f"the running gateway does not serve {policy_dir}; set ACL_E2E_POLICY_DIR to the directory mounted into it"
        )
    original = groups_file.read_bytes()
    text = original.decode("utf-8")
    new_text, n = re.subn(r"(credit-analysts:\s*\n(?:[^\n]*\n)*?\s+preset:\s*)strict", r"\1monitor", text, count=1)
    assert n == 1, "could not find `preset: strict` under credit-analysts in groups.yaml"

    prompt = f"Mój PESEL to {PESEL_EXAMPLE}."
    since = time.monotonic()
    assert stack.chat("jan", prompt).status_code == 200
    version0, action0 = _decision_after(stack, sse, since)
    try:
        groups_file.write_bytes(new_text.encode("utf-8"))
        written = time.monotonic()
        deadline = written + HOT_RELOAD_DEADLINE_S
        version1 = action1 = ""
        while time.monotonic() < deadline:
            since = time.monotonic()
            stack.chat("jan", prompt)
            version1, action1 = _decision_after(stack, sse, since)
            if version1 != version0:
                break
            time.sleep(0.1)
        assert version1 != version0, f"policy version unchanged {HOT_RELOAD_DEADLINE_S}s after the edit"
        if action0 not in ("allow", "monitor"):  # the PII control is live: strict vs monitor must differ
            assert action1 != action0, f"preset change did not change the decision (still {action0})"
    finally:
        groups_file.write_bytes(original)  # never leave policy/ modified
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and _policy_version(stack) == version1:
        time.sleep(0.2)
    assert _policy_version(stack) == version0, "restoring the file should restore the original policy version"
