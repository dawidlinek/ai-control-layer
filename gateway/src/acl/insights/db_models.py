"""Insights tables: clusters (group + personal), published skills, settings and personal opt-ins."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from acl.db import Base


class InsightClusterRow(Base):
    __tablename__ = "insight_clusters"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    group_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    owner: Mapped[str | None] = mapped_column(String(256), index=True)  # personal suggestions only
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    distinct_users: Mapped[int] = mapped_column(Integer, nullable=False)
    members: Mapped[list[str]] = mapped_column(JSON, default=list)  # record keys, bounded; for stable ids
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)  # InsightCluster
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class InsightSkillRow(Base):
    __tablename__ = "insight_skills"

    skill_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    cluster_id: Mapped[str | None] = mapped_column(String(40))
    groups: Mapped[list[str]] = mapped_column(JSON, default=list)
    before_usd_per_run: Mapped[float | None] = mapped_column(Float)
    before_gpu_seconds_per_run: Mapped[float | None] = mapped_column(Float)
    projected_usd_per_run: Mapped[float | None] = mapped_column(Float)
    projected_gpu_seconds_per_run: Mapped[float | None] = mapped_column(Float)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    published_by: Mapped[str | None] = mapped_column(String(256))
    policy_version: Mapped[str | None] = mapped_column(String(64))
    version_id: Mapped[int | None] = mapped_column(Integer)


class InsightSettingRow(Base):
    """`key` = `global` (k, window_days) or `group:<name>` (enabled, personal)."""

    __tablename__ = "insight_settings"

    key: Mapped[str] = mapped_column(String(160), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(256))


class InsightOptInRow(Base):
    __tablename__ = "insight_opt_ins"

    subject: Mapped[str] = mapped_column(String(256), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
