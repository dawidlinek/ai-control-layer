"""Gateway unit-test defaults."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_audit_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test gets its own audit log: the chain has a single-writer OS lock, so tests (and xdist
    workers) must never share the default `logs/audit.jsonl`. Tests that pass `audit_path=` explicitly win."""
    monkeypatch.setenv("ACL_AUDIT_PATH", str(tmp_path / "audit" / "audit.jsonl"))
