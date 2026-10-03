"""Policy version snapshots (concept §11.1). Migration: `migrations/versions/1b_policy_versions.py`."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from acl.db import Base


def _now() -> datetime:
    return datetime.now(UTC)


class PolicyVersionRow(Base):
    """One successfully loaded, distinct policy version: full file contents plus the diff to the previous one."""

    __tablename__ = "policy_versions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)  # file | panel | rollback | startup
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    files_changed: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    files: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    diff: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (Index("ix_policy_versions_version", "version"),)
