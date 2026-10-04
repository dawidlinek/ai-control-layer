"""Scan result store: SQL table + an in-memory index (by id and by sha256) loaded at startup.

The index serves the synchronous consumers: the registry load gate (consulted per request) and the admin
`models()` listing. `record` writes the row first and then updates the index, so a failed write never makes a
model loadable. Findings and report facts only; never file content.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acl.artifacts.db_models import ArtifactScanRow
from acl.contracts.admin import ArtifactFinding, ArtifactScanResult
from acl.contracts.common import Severity
from acl.policy.models import ArtifactRef

log = logging.getLogger(__name__)


def result_from_row(row: ArtifactScanRow) -> ArtifactScanResult:
    scanned_at = row.scanned_at
    return ArtifactScanResult(
        id=row.id,
        filename=row.filename,
        sha256=row.sha256,
        size=row.size,
        format_detected=row.format,
        verdict=row.verdict,  # type: ignore[arg-type]
        findings=[
            ArtifactFinding(
                rule_id=f["rule_id"],
                severity=Severity(f["severity"]),
                message=f["message"],
                detail=f.get("detail"),
                cve=list(f.get("cve") or []),
            )
            for f in (row.findings or [])
        ],
        scanned_at=scanned_at,
        source=row.source,
        exception=row.exception,
        decision_id=row.decision_id,
        scanned_by=row.scanned_by,
    )


def row_from_result(result: ArtifactScanResult) -> ArtifactScanRow:
    return ArtifactScanRow(
        id=result.id,
        filename=result.filename[:255],
        sha256=result.sha256,
        size=result.size,
        format=result.format_detected[:32],
        verdict=result.verdict,
        findings=[f.model_dump(mode="json") for f in result.findings],
        source=result.source,
        exception=result.exception,
        decision_id=result.decision_id,
        scanned_by=result.scanned_by,
        scanned_at=result.scanned_at,
    )


class ArtifactStore:
    def __init__(self, sessions: Callable[[], async_sessionmaker[AsyncSession]] | None = None) -> None:
        self._sessions = sessions
        self._by_id: dict[str, ArtifactScanResult] = {}
        self._by_sha: dict[str, list[str]] = {}  # chronological scan ids per sha256

    # ------------------------------------------------------------------ persistence

    async def load(self) -> None:
        """Fill the in-memory index from the table (startup)."""
        if self._sessions is None:
            return
        async with self._sessions()() as s:
            rows = (await s.execute(select(ArtifactScanRow).order_by(ArtifactScanRow.scanned_at))).scalars().all()
        self._by_id.clear()
        self._by_sha.clear()
        for row in rows:
            self._index(result_from_row(row))

    async def record(self, result: ArtifactScanResult) -> ArtifactScanResult:
        if self._sessions is not None:
            async with self._sessions()() as s:
                s.add(row_from_result(result))
                await s.commit()
        self._index(result)
        return result

    def _index(self, result: ArtifactScanResult) -> None:
        if result.id not in self._by_id:
            self._by_sha.setdefault(result.sha256, []).append(result.id)
        self._by_id[result.id] = result

    # ------------------------------------------------------------------ queries

    async def list(self, limit: int = 200) -> list[ArtifactScanResult]:
        """Newest first."""
        ordered = sorted(self._by_id.values(), key=lambda r: r.scanned_at, reverse=True)
        return ordered[: max(limit, 0)]

    async def get(self, scan_id: str) -> ArtifactScanResult | None:
        return self._by_id.get(scan_id)

    def scans_for(self, sha256: str) -> list[ArtifactScanResult]:
        """Chronological (oldest first)."""
        return [self._by_id[i] for i in self._by_sha.get(sha256, [])]

    def passing(self, sha256: str) -> str | None:
        """Id of the newest scan of this file content if that scan passed (`safe`), else None.

        The newest scan decides: a re-scan that fails (e.g. after the feed gained an `opcode` signature) revokes
        an earlier pass, and only a newer passing scan restores it.
        """
        latest = self.latest(sha256)
        return latest.id if latest is not None and latest.verdict == "safe" else None

    def latest(self, sha256: str) -> ArtifactScanResult | None:
        ids = self._by_sha.get(sha256)
        return self._by_id[ids[-1]] if ids else None

    # ------------------------------------------------------------------ model registry view

    def passes(self, ref: ArtifactRef) -> bool:
        """A model's artifact ref is loadable: the newest scan of that sha256 passed (and, when the ref pins a
        `scan_id`, that very scan is a passing scan of that sha256 and no newer scan of the file failed)."""
        current = self.passing(ref.sha256)
        if current is None:
            return False
        if ref.scan_id is not None:
            scan = self._by_id.get(ref.scan_id)
            return scan is not None and scan.sha256 == ref.sha256 and scan.verdict == "safe"
        return True

    def status(self, ref: ArtifactRef | None) -> str:
        """`ModelInfo.artifact_status`: n/a | scanned_ok | scanned_bad | unscanned."""
        if ref is None:
            return "n/a"
        if self.passes(ref):
            return "scanned_ok"
        latest = self.latest(ref.sha256)
        if latest is not None and latest.verdict != "safe":
            return "scanned_bad"
        return "unscanned"

    def gate_problem(self, ref: ArtifactRef | None) -> str | None:
        if ref is None or self.passes(ref):
            return None
        return f"artifact {ref.sha256[:12]} has no passing scan"


def new_scan_id() -> str:
    import uuid

    return f"art-{uuid.uuid4().hex[:12]}"


__all__ = ["ArtifactStore", "new_scan_id", "result_from_row", "row_from_result"]
