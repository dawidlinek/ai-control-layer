"""Budget ledger persistence (concept §8). Migration: `migrations/versions/2d_budgets.py`.

The hot path is in memory; `acl.budgets.store.BudgetStore` flushes dirty rows periodically and reloads them on
startup. Timestamps are epoch seconds (floats) so SQLite and Postgres behave identically.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from acl.db import Base


class BudgetNodeRow(Base):
    """One node of the hierarchy org → group → user → agent → session."""

    __tablename__ = "budget_nodes"

    node_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    level: Mapped[str] = mapped_column(String(16), nullable=False)
    parent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    last_seen: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    __table_args__ = (Index("ix_budget_nodes_level", "level"),)


class BudgetCounterRow(Base):
    """Current-window value of one meter of one node (`tokens_day`, `usd_month`, `gpu_seconds_session`, ...)."""

    __tablename__ = "budget_counters"

    node_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    meter: Mapped[str] = mapped_column(String(48), primary_key=True)
    window: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    soft_notified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    hard_notified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)


class BudgetBreakerRow(Base):
    """Circuit breaker state per node (closed rows are kept so a reset shows up in the admin list)."""

    __tablename__ = "budget_breakers"

    node_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    state: Mapped[str] = mapped_column(String(12), nullable=False)
    opened_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    cooldown_until: Mapped[float | None] = mapped_column(Float, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    probes_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_probe_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    cooldown_s: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    half_open_probes: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
