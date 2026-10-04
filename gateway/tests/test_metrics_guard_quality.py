"""`GET /admin/v1/metrics/guard-quality` serves the latest self-test suite summary (`ACL_GUARD_SUMMARY_PATH`)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from acl.contracts.admin import (
    AdaptiveTierSummary,
    GuardQualitySummary,
    MutantResult,
    MutationCoverage,
    RateWithCI,
)
from acl.main import create_app
from acl.settings import Settings

REPO = Path(__file__).resolve().parents[2]
VIEWER = {"X-ACL-Dev-User": "vera", "X-ACL-Dev-Groups": "security-analysts", "X-ACL-Dev-Roles": "acl-viewer"}
URL = "/admin/v1/metrics/guard-quality"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        policy_dir=REPO / "policy",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'acl.db'}",
        audit_path=tmp_path / "audit.jsonl",
        deterministic=True,
        value_hash_salt="test-salt",  # type: ignore[arg-type]
    )
    with TestClient(create_app(settings, allow_anonymous_dev=True)) as c:
        yield c


def _summary() -> GuardQualitySummary:
    now = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    return GuardQualitySummary(
        generated_at=now,
        suite="system-cases",
        mode="deterministic",
        asr=RateWithCI(value=0.1, ci_low=0.02, ci_high=0.4, n=10),
        mutation=MutationCoverage(
            generated_at=now,
            suite="system-cases",
            controls_mutated=2,
            controls_killed=1,
            score=0.5,
            survivors=["SEC-X-01"],
            results=[
                MutantResult(control_id="SEC-PII-01", enabled=True, killed=True, failing_cells=3),
                MutantResult(control_id="SEC-X-01", enabled=True, killed=False),
            ],
        ),
        adaptive=AdaptiveTierSummary(
            generated_at=now,
            variants=40,
            detection=RateWithCI(value=0.8, ci_low=0.65, ci_high=0.9, n=40),
            by_technique={"base64": RateWithCI(value=1.0, ci_low=0.5, ci_high=1.0, n=4)},
            layer_attribution={"deterministic": 32},
        ),
    )


def test_valid_summary_round_trips_with_mutation_and_adaptive(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "summary.json"
    expected = _summary()
    path.write_text(expected.model_dump_json(), encoding="utf-8")
    monkeypatch.setenv("ACL_GUARD_SUMMARY_PATH", str(path))
    r = client.get(URL, headers=VIEWER)
    assert r.status_code == 200, r.text
    assert GuardQualitySummary.model_validate(r.json()) == expected
    body = r.json()
    assert body["mutation"]["survivors"] == ["SEC-X-01"] and body["mutation"]["results"][0]["killed"] is True
    assert body["adaptive"]["by_technique"]["base64"]["n"] == 4 and body["asr"]["ci_high"] == 0.4


def test_missing_report_is_404_with_a_hint(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACL_GUARD_SUMMARY_PATH", str(tmp_path / "nope.json"))
    r = client.get(URL, headers=VIEWER)
    assert r.status_code == 404
    assert "make test" in r.json()["detail"]


@pytest.mark.parametrize("content", ["not json {", json.dumps({"suite": "x"}), json.dumps([1, 2])])
def test_invalid_report_is_503_and_never_echoes_content(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: str
) -> None:
    path = tmp_path / "summary.json"
    path.write_text(content, encoding="utf-8")
    monkeypatch.setenv("ACL_GUARD_SUMMARY_PATH", str(path))
    r = client.get(URL, headers=VIEWER)
    assert r.status_code == 503
    assert content not in r.text


def test_requires_a_viewer(client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ACL_GUARD_SUMMARY_PATH", str(tmp_path / "nope.json"))
    r = client.get(URL, headers={"X-ACL-Dev-User": "ann", "X-ACL-Dev-Groups": "developers"})
    assert r.status_code == 403
