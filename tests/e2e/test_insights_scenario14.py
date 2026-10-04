"""Demo scenario 14 (Automation Insights) against the running stack (`make up`, then the command below).

Story: analysts keep asking the assistant the same thing every morning (summarising a loan application). Rogatka
notices the repeated task in redacted prompts (k-anonymous, opted-in groups only), drafts a skill, and an admin
publishes it for the credit-analysts group. The skill then shows up for analysts only, runs on its own pinned
model with the personal data pseudonymised first, and the Insights page reports its measured cost.

Steps scripted here, in order, in one test (so a failure names the step):
  1. admin (`adam`) opts `credit-analysts` and `developers` in to mining and recomputes; no `last_error`
  2. the daily "loan" cluster of credit-analysts: >= k distinct users, 20-80 min/day, `{placeholder}` template,
     `confidential` data class
  3. "try with an example": preview renders the template with no errors
  4. publish (idempotent: reuses an earlier publication, or retries with a suffixed skill id) -> `published`, v<N>
  5. the analyst (`jan`) sees `skill/...` in /v1/models; a developer (`anna`) does not and gets 403 `SEC-MODEL-01`
  6. the analyst runs the skill on a text with a synthetic PESEL: 200, `x-acl-model` is the skill's model, and the
     PESEL does not come back (it was pseudonymised before the model saw it)
  7. /admin/v1/insights/skills lists the skill with runs_30d >= 1 and an observed "before" cost

Run:  uv run python scripts/dev.py e2e -k insights

Users come from deploy/keycloak/realm-export.json: jan (credit-analysts), anna (developers), adam (admins).
Needs the gateway to have an insights history to mine (seed `deploy/seed/insights`, `ACL_INSIGHTS_SEED_DIR`).
"""

from __future__ import annotations

import re
import time
from typing import Any

import pytest
from e2e.helpers import PESEL_EXAMPLE

pytestmark = [pytest.mark.e2e, pytest.mark.timeout(300)]

ANALYST = "jan"
DEVELOPER = "anna"
ADMIN = "adam"
ANALYST_GROUP = "credit-analysts"
GROUPS = (ANALYST_GROUP, "developers")


def _ok(r, what: str, status: int = 200) -> Any:  # type: ignore[no-untyped-def]
    assert r.status_code == status, f"{what}: HTTP {r.status_code} {r.text[:400]}"
    return r.json()


def _example_inputs(schema: dict[str, Any]) -> dict[str, Any]:
    """Example values for every property of the draft's input schema; string properties get a marker text."""
    inputs: dict[str, Any] = {}
    for name, spec in (schema.get("properties") or {}).items():
        kind = spec.get("type", "string") if isinstance(spec, dict) else "string"
        if kind == "integer":
            inputs[name] = 3
        elif kind == "number":
            inputs[name] = 1.5
        elif kind == "boolean":
            inputs[name] = True
        else:
            inputs[name] = "Loan application E2E-PREVIEW-MARKER: applicant requests 120000 PLN for 60 months."
    return inputs


def _enable_groups(stack) -> int:  # type: ignore[no-untyped-def]
    settings = _ok(stack.admin("GET", "/insights/settings", user=ADMIN), "get settings")
    groups = settings["groups"]
    for name in GROUPS:
        row = next((g for g in groups if g["group"] == name), None)
        if row is None:
            groups.append({"group": name, "enabled": True, "personal": False})
        else:
            row["enabled"] = True
    updated = _ok(stack.admin("PUT", "/insights/settings", user=ADMIN, json=settings), "put settings")
    enabled = {g["group"] for g in updated["groups"] if g["enabled"]}
    assert set(GROUPS) <= enabled, updated
    return int(updated["k"])


def _find_cluster(stack) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    clusters = _ok(stack.admin("GET", "/insights/clusters", user=ADMIN, params={"group": ANALYST_GROUP}), "clusters")
    candidates = [
        c
        for c in clusters
        if c["recurrence"] == "daily" and "loan" in c["label"].lower() and c["status"] != "dismissed"
    ]
    assert candidates, (
        f"no daily 'loan' cluster for {ANALYST_GROUP}: {[(c['label'], c['recurrence']) for c in clusters]}"
    )
    # an earlier run of this scenario may have published one already; prefer it so reruns stay idempotent
    candidates.sort(key=lambda c: (c["status"] != "published", -c["size"]))
    return candidates[0]


def _publish(stack, cluster: dict[str, Any]) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    draft = cluster["draft_skill"]
    body = {
        "skill_id": draft["skill_id"],
        "model": draft["model"],
        "preset": "strict",
        "groups": [ANALYST_GROUP],
        "reason": "e2e scenario 14: publish the repeated loan summary as a skill",
    }
    path = f"/insights/clusters/{cluster['id']}/publish"
    r = stack.admin("POST", path, user=ADMIN, json=body)
    if r.status_code == 422 and "already exists" in r.text:  # skill id taken by an earlier run's publication
        base = re.sub(r"-e2e-\d+$", "", draft["skill_id"])[:40]
        body["skill_id"] = f"{base}-e2e-{int(time.time())}"
        r = stack.admin("POST", path, user=ADMIN, json=body)
    return _ok(r, "publish")


def _model_ids(stack, user: str) -> list[str]:  # type: ignore[no-untyped-def]
    r = stack.http.get(f"{stack.cfg.gateway}/v1/models", headers=stack.auth(user))
    return [m["id"] for m in _ok(r, f"/v1/models as {user}")["data"]]


def test_scenario14_automation_insights_end_to_end(stack) -> None:  # type: ignore[no-untyped-def]
    if stack.admin("GET", "/insights/settings", user=ADMIN).status_code == 501:
        pytest.skip("insights are not installed on the running gateway")

    # 1. opt the groups in and mine
    k = _enable_groups(stack)
    status = _ok(stack.admin("POST", "/insights/recompute", user=ADMIN), "recompute")
    assert status["last_error"] is None, status["last_error"]
    assert status["clusters_visible"] >= 1, status

    # 2. the daily loan cluster
    cluster = _find_cluster(stack)
    draft = cluster["draft_skill"]
    assert cluster["distinct_users"] >= k, cluster
    assert 20 <= cluster["est_minutes_per_day"] <= 80, cluster["est_minutes_per_day"]
    assert re.search(r"\{[^{}]+\}", draft["template"]), draft["template"]
    assert "confidential" in draft["data_classes"], draft["data_classes"]

    # 3. try with an example
    inputs = _example_inputs(draft["input_schema"])
    assert inputs, f"draft has no input properties: {draft['input_schema']}"
    preview = _ok(
        stack.admin("POST", f"/insights/clusters/{cluster['id']}/preview", user=ADMIN, json={"inputs": inputs}),
        "preview",
    )
    assert preview["errors"] == [], preview
    first_text = next(v for v in inputs.values() if isinstance(v, str))
    assert preview["prompt"] and first_text in preview["prompt"], preview

    # 4. publish (or reuse an earlier publication)
    published = cluster if cluster["status"] == "published" else _publish(stack, cluster)
    assert published["status"] == "published", published
    skill_id = published["published_skill"]
    assert skill_id and skill_id.startswith("skill/"), published
    assert isinstance(published["published_version_id"], int), published
    skill_model = published["draft_skill"]["model"]

    # 5. visibility and access
    assert skill_id in _model_ids(stack, ANALYST), f"{skill_id} missing from {ANALYST}'s /v1/models"
    assert skill_id not in _model_ids(stack, DEVELOPER), f"{skill_id} leaked into {DEVELOPER}'s /v1/models"
    denied = stack.chat(DEVELOPER, "Loan application: please summarise.", model=skill_id)
    assert denied.status_code == 403, f"HTTP {denied.status_code} {denied.text[:300]}"
    assert denied.json()["error"]["code"] == "SEC-MODEL-01", denied.text[:300]

    # 6. the analyst runs it; personal data is pseudonymised before the model sees it
    application = (
        "Loan application, applicant Jan Testowy, PESEL "
        f"{PESEL_EXAMPLE}, requests 120000 PLN for 60 months, monthly income 9500 PLN, no other liabilities."
    )
    run = stack.chat(ANALYST, application, model=skill_id)
    assert run.status_code == 200, f"HTTP {run.status_code} {run.text[:300]}"
    assert run.headers.get("x-acl-model") == skill_model, dict(run.headers)
    assert PESEL_EXAMPLE not in run.text, "the PESEL came back in the response"

    # 7. the skill appears in the Insights page with observed runs and a "before" cost (the audit write can lag)
    entry: dict[str, Any] | None = None
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        skills = _ok(stack.admin("GET", "/insights/skills", user=ADMIN), "skills")
        entry = next((s for s in skills if s["skill_id"] == skill_id), None)
        if entry is not None and entry["runs_30d"] >= 1:
            break
        time.sleep(1.0)
    assert entry is not None, f"{skill_id} not listed in /insights/skills"
    assert entry["runs_30d"] >= 1, entry
    assert entry["cost_per_run_before_usd"] is not None, entry
    assert ANALYST_GROUP in entry["groups"], entry
