"""Approval queue table (concept §9 "Approvals", §6.3 `require_approval`).

One row per held tool call. A decided row with `elevation_until` in the future is also the time-boxed elevation for
`(session_id, tool)`: SEC-TOOL-01 skips its own approval reasons while it is active. No raw arguments are stored:
`arguments_preview` is the redacted preview shown to the approver, `args_hash` a salted hash for correlation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from acl.db import Base
from acl.identity.db_models import UtcDateTime, utcnow


class ApprovalRow(Base):
    __tablename__ = "approvals"
    __table_args__ = (
        Index("ix_approvals_status_expires", "status", "expires_at"),
        Index("ix_approvals_session_tool", "session_id", "tool"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="pending")
    approver_scope: Mapped[str] = mapped_column(String(8), nullable=False)  # user | admin
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    requester_subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)  # display name (username or subject)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(64), nullable=False)
    decision_id: Mapped[str | None] = mapped_column(String(64))
    tool: Mapped[str | None] = mapped_column(String(255))
    server: Mapped[str | None] = mapped_column(String(100))
    arguments_preview: Mapped[str] = mapped_column(Text, nullable=False, default="")
    args_hash: Mapped[str | None] = mapped_column(String(64))
    egress: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rule_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    note: Mapped[str | None] = mapped_column(Text)
    elevation_scope: Mapped[str | None] = mapped_column(String(255))
    elevation_until: Mapped[datetime | None] = mapped_column(UtcDateTime)
    # "approve once": set when the approved call was executed (redeemed); a consumed row never waives again
    consumed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
