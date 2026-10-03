"""CP3: SEC-SESSION-01 on the live stack — a confidential session stays on local models (HANDOFF §7.2)."""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.e2e

PESEL = "44051401359"  # synthetic, checksum-valid


def test_cp3_confidential_session_keeps_later_requests_local(stack) -> None:
    """adam (admins, may use `smart`): after a PESEL turn, a harmless follow-up in the same session stays local."""
    session = f"e2e-sess-{uuid.uuid4().hex[:10]}"
    hdr = {"X-Session-Id": session}
    first = stack.http.post(
        f"{stack.cfg.gateway}/v1/chat/completions",
        json={"model": "smart", "messages": [{"role": "user", "content": f"Check the record of PESEL {PESEL}."}]},
        headers={**stack.auth("adam"), **hdr},
        timeout=60,
    )
    assert first.status_code == 200, f"HTTP {first.status_code}: {first.text[:300]}"
    assert first.headers.get("x-acl-model", "").startswith("local/"), first.headers.get("x-acl-model")

    later = stack.http.post(
        f"{stack.cfg.gateway}/v1/chat/completions",
        json={"model": "smart", "messages": [{"role": "user", "content": "Thanks, now suggest three titles."}]},
        headers={**stack.auth("adam"), **hdr},
        timeout=60,
    )
    assert later.status_code == 200, f"HTTP {later.status_code}: {later.text[:300]}"
    assert later.headers.get("x-acl-model", "").startswith("local/"), later.headers.get("x-acl-model")
    assert later.headers.get("x-acl-session-label") == "confidential; local-only; rule=SEC-SESSION-01"

    events = stack.admin("GET", "/events", params={"rule_id": "SEC-SESSION-01", "limit": 5}).json()
    assert any(e.get("trace_id") == later.headers.get("x-acl-trace-id") for e in events), "rule hit not in audit"
