"""Query index for the audit log (the hash-chained JSONL file stays the source of truth).

`audit_events` holds summary columns for filtering/metrics plus the full record as JSON.
List-valued filters (groups, rules, controls, taxonomy tags) are stored as `|a|b|` strings so a
portable `LIKE '%|x|%'` works on both SQLite and Postgres.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from acl.db import Base


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    trace_id: Mapped[str | None] = mapped_column(String(64), index=True)
    session_id: Mapped[str | None] = mapped_column(String(128), index=True)
    subject: Mapped[str | None] = mapped_column(String(256), index=True)
    username: Mapped[str | None] = mapped_column(String(256))
    groups_text: Mapped[str] = mapped_column(Text, default="")
    agent_id: Mapped[str | None] = mapped_column(String(128))
    point: Mapped[str | None] = mapped_column(String(32))
    model: Mapped[str | None] = mapped_column(String(128))
    connector: Mapped[str | None] = mapped_column(String(64))
    tier: Mapped[str | None] = mapped_column(String(16))
    degraded: Mapped[bool] = mapped_column(Boolean, default=False)
    tool: Mapped[str | None] = mapped_column(String(256))
    action: Mapped[str | None] = mapped_column(String(24), index=True)
    would_action: Mapped[str | None] = mapped_column(String(24))
    rules_text: Mapped[str] = mapped_column(Text, default="")
    controls_text: Mapped[str] = mapped_column(Text, default="")
    tags_text: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[float | None] = mapped_column(Float)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    usd: Mapped[float] = mapped_column(Float, default=0.0)
    gpu_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (Index("ix_audit_events_connector_timestamp", "connector", "timestamp"),)


class IncidentRow(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    assignee: Mapped[str | None] = mapped_column(String(256))
    subject: Mapped[str | None] = mapped_column(String(256), index=True)
    event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    notes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
