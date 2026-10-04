"""S2: ArtifactStore (SQL persistence + in-memory index) and the migration."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from acl.artifacts.store import ArtifactStore, new_scan_id
from acl.contracts.admin import ArtifactFinding, ArtifactScanResult
from acl.contracts.common import Severity
from acl.db import create_all, make_engine, make_sessionmaker
from acl.policy.models import ArtifactRef

SHA_A = "a" * 64
SHA_B = "b" * 64
T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def result(sha: str, verdict: str, minutes: int = 0, **kw) -> ArtifactScanResult:
    return ArtifactScanResult(
        id=new_scan_id(),
        filename="m.safetensors",
        sha256=sha,
        size=10,
        format_detected="safetensors",
        verdict=verdict,  # type: ignore[arg-type]
        findings=kw.pop("findings", []),
        scanned_at=T0 + timedelta(minutes=minutes),
        **kw,
    )


@pytest.fixture
async def sessions(tmp_path: Path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'art.db'}")
    await create_all(engine)
    yield make_sessionmaker(engine)
    await engine.dispose()


async def test_record_get_list_newest_first_and_reload(sessions) -> None:
    store = ArtifactStore(lambda: sessions)
    finding = ArtifactFinding(
        rule_id="ART-PICKLE-01",
        severity=Severity.critical,
        message="Pickle references dangerous global os.system.",
        detail="GLOBAL os.system via REDUCE at offset 2",
        cve=["CVE-2025-32434"],
    )
    first = await store.record(result(SHA_A, "safe", 0, source="upload", scanned_by="adam"))
    second = await store.record(result(SHA_B, "malicious", 5, findings=[finding], decision_id="dec-1"))
    third = await store.record(result(SHA_A, "blocked_format", 9, exception=None))
    assert [r.id for r in await store.list()] == [third.id, second.id, first.id]
    assert [r.id for r in await store.list(limit=2)] == [third.id, second.id]
    assert (await store.get(second.id)) == second and (await store.get("art-nope")) is None

    reloaded = ArtifactStore(lambda: sessions)
    assert await reloaded.list() == []  # nothing until load()
    await reloaded.load()
    assert [r.id for r in await reloaded.list()] == [third.id, second.id, first.id]
    got = await reloaded.get(second.id)
    assert got == second and got.findings[0].cve == ["CVE-2025-32434"] and got.scanned_at.tzinfo is not None
    assert reloaded.passing(SHA_A) is None  # the newest scan of SHA_A (third) did not pass
    assert reloaded.latest(SHA_A) == third


async def test_passing_latest_and_status() -> None:
    store = ArtifactStore()  # in-memory only
    assert store.passing(SHA_A) is None and store.latest(SHA_A) is None
    assert store.status(ArtifactRef(sha256=SHA_A)) == "unscanned"
    assert store.status(None) == "n/a" and store.gate_problem(None) is None

    bad = await store.record(result(SHA_A, "blocked_format", 0))
    assert store.status(ArtifactRef(sha256=SHA_A)) == "scanned_bad"
    assert store.gate_problem(ArtifactRef(sha256=SHA_A)) == f"artifact {SHA_A[:12]} has no passing scan"
    assert store.latest(SHA_A) == bad and store.passing(SHA_A) is None

    ok = await store.record(result(SHA_A, "safe", 1))
    assert store.passing(SHA_A) == ok.id and store.status(ArtifactRef(sha256=SHA_A)) == "scanned_ok"
    assert store.gate_problem(ArtifactRef(sha256=SHA_A)) is None

    # the newest scan decides: a failing re-scan (e.g. a new feed signature) revokes the earlier pass
    await store.record(result(SHA_A, "suspicious", 2))
    assert store.passing(SHA_A) is None and store.status(ArtifactRef(sha256=SHA_A)) == "scanned_bad"
    assert store.gate_problem(ArtifactRef(sha256=SHA_A)) is not None
    # ... and only a newer passing scan restores it
    newer = await store.record(result(SHA_A, "safe", 3))
    assert store.passing(SHA_A) == newer.id
    assert [r.verdict for r in store.scans_for(SHA_A)] == ["blocked_format", "safe", "suspicious", "safe"]
    assert store.passing(SHA_B) is None


async def test_scan_id_pin() -> None:
    store = ArtifactStore()
    bad = await store.record(result(SHA_A, "blocked_format", 0))
    ok = await store.record(result(SHA_A, "safe", 1))
    other = await store.record(result(SHA_B, "safe", 2))
    assert store.passes(ArtifactRef(sha256=SHA_A, scan_id=ok.id))
    assert not store.passes(ArtifactRef(sha256=SHA_A, scan_id=bad.id))
    assert not store.passes(ArtifactRef(sha256=SHA_A, scan_id=other.id))  # passing, but a different file
    assert not store.passes(ArtifactRef(sha256=SHA_A, scan_id="art-missing"))
    assert store.status(ArtifactRef(sha256=SHA_A, scan_id=other.id)) == "unscanned"  # pin names no scan of this file


async def test_failed_write_does_not_make_a_model_loadable(sessions) -> None:
    store = ArtifactStore(lambda: sessions)
    first = await store.record(result(SHA_A, "safe", 0))
    duplicate = first.model_copy()  # same primary key: the insert fails
    with pytest.raises(IntegrityError):
        await store.record(duplicate)
    assert len(await store.list()) == 1


async def test_store_without_a_database_still_works_and_load_is_a_noop() -> None:
    store = ArtifactStore(None)
    await store.load()
    saved = await store.record(result(SHA_A, "safe"))
    assert (await store.get(saved.id)) is not None


def test_migration_matches_the_model() -> None:
    import importlib

    from acl.artifacts.db_models import ArtifactScanRow

    mod = importlib.import_module("acl.migrations.versions.4a_artifacts")
    assert mod.down_revision == "0001_base" and mod.revision == "4a_artifacts"
    assert ArtifactScanRow.__tablename__ == "artifact_scans"
    assert {"id", "sha256", "verdict", "findings", "scanned_at"} <= set(ArtifactScanRow.__table__.columns.keys())
