"""Model-artifact scan results (concept 9.2). One row per scan: findings and facts, never file content."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from acl.db import Base
from acl.identity.db_models import UtcDateTime, utcnow


class ArtifactScanRow(Base):
    __tablename__ = "artifact_scans"
    __table_args__ = (Index("ix_artifact_scans_sha256", "sha256"), Index("ix_artifact_scans_scanned_at", "scanned_at"))

    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # art-<hex>
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    source: Mapped[str | None] = mapped_column(Text)
    exception: Mapped[str | None] = mapped_column(Text)
    decision_id: Mapped[str | None] = mapped_column(String(64))
    scanned_by: Mapped[str | None] = mapped_column(String(255))
    scanned_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
