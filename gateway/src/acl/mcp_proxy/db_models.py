"""MCP proxy tables: bound servers and pinned tool manifests (concept §9 "MCP integrity")."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from acl.db import Base
from acl.identity.db_models import UtcDateTime, utcnow


class McpServerRow(Base):
    """What the gateway bound at `initialize`: identity (origin/url), declared capabilities, health."""

    __tablename__ = "mcp_servers"

    server_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    transport: Mapped[str] = mapped_column(String(24), nullable=False)
    bound_url: Mapped[str | None] = mapped_column(String(1024))
    bound_origin: Mapped[str | None] = mapped_column(String(512))
    protocol_version: Mapped[str | None] = mapped_column(String(24))
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    server_info: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")  # ok | unreachable | blocked
    last_error: Mapped[str | None] = mapped_column(String(300))
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(UtcDateTime)


class McpToolRow(Base):
    """One upstream tool of one server, with its pin.

    `status`: pinned (callable, hash == pinned_hash) | pending_approval (name collision) | drifted (change seen but
    not enforced, monitor mode) | quarantined (hidden, calls blocked until an admin re-approves).
    """

    __tablename__ = "mcp_tools"
    __table_args__ = (Index("ix_mcp_tools_tool_id", "tool_id", unique=True), Index("ix_mcp_tools_status", "status"))

    server_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), primary_key=True)
    tool_id: Mapped[str] = mapped_column(String(300), nullable=False)  # policy id, else `<server>:<name>`
    policy_tool_id: Mapped[str | None] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pinned")
    pinned_hash: Mapped[str | None] = mapped_column(String(64))
    current_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    pinned_description: Mapped[str | None] = mapped_column(Text)
    current_description: Mapped[str | None] = mapped_column(Text)
    pinned_schema: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    current_schema: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    description_diff: Mapped[str | None] = mapped_column(Text)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)  # value-free flag labels
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    drift_detected_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    approved_by: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    decision_note: Mapped[str | None] = mapped_column(String(500))
