"""Identity tables: users (JIT-provisioned), API keys, grants, append-only grant changes, grants version."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from acl.db import Base


class UtcDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetimes on every backend (SQLite drops tzinfo)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


_BIGINT = BigInteger().with_variant(Integer, "sqlite")  # SQLite only autoincrements INTEGER primary keys


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    subject: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    email: Mapped[str | None] = mapped_column(String(320))
    display_name: Mapped[str | None] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="user")
    groups: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    roles: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(UtcDateTime)
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ApiKeyRow(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # HMAC-SHA256 hex; the key itself is never stored
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class GrantRow(Base):
    __tablename__ = "grants"
    __table_args__ = (Index("ix_grants_subject", "subject_type", "subject"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(8), nullable=False)  # user | group
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(16), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    effect: Mapped[str] = mapped_column(String(8), nullable=False, default="allow")
    constraints: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    revoked_by: Mapped[str | None] = mapped_column(String(255))


class GrantChangeRow(Base):
    """Append-only journal of grant lifecycle events (create / revoke / expire). Never updated or deleted."""

    __tablename__ = "grant_changes"
    __table_args__ = (UniqueConstraint("grant_id", "change", name="uq_grant_changes_grant_change"),)

    id: Mapped[int] = mapped_column(_BIGINT, primary_key=True, autoincrement=True)
    grant_id: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    change: Mapped[str] = mapped_column(String(8), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class GrantsMetaRow(Base):
    """Single row (id=1): the monotonic grants version, bumped in the same transaction as every change."""

    __tablename__ = "grants_meta"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(_BIGINT, nullable=False, default=0)
