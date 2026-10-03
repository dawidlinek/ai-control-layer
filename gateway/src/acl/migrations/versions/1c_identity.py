"""Identity: users, api_keys, grants, grant_changes (append-only), grants_meta.

Revision ID: 1c_identity
Revises: 0001_base
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "1c_identity"
down_revision = "0001_base"
branch_labels = None
depends_on = None

_BIGINT = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("email", sa.String(320), nullable=True),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("groups", sa.JSON(), nullable=False),
        sa.Column("roles", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("subject", name="uq_users_subject"),
    )
    op.create_index("ix_users_username", "users", ["username"])

    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("prefix", sa.String(16), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_api_keys_user_id_users"),
        sa.UniqueConstraint("prefix", name="uq_api_keys_prefix"),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])

    op.create_table(
        "grants",
        sa.Column("id", sa.String(40), nullable=False),
        sa.Column("subject_type", sa.String(8), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("resource_type", sa.String(16), nullable=False),
        sa.Column("resource", sa.String(255), nullable=False),
        sa.Column("effect", sa.String(8), nullable=False),
        sa.Column("constraints", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_grants"),
    )
    op.create_index("ix_grants_subject", "grants", ["subject_type", "subject"])

    op.create_table(
        "grant_changes",
        sa.Column("id", _BIGINT, autoincrement=True, nullable=False),
        sa.Column("grant_id", sa.String(40), nullable=False),
        sa.Column("change", sa.String(8), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_grant_changes"),
        sa.UniqueConstraint("grant_id", "change", name="uq_grant_changes_grant_change"),
    )
    op.create_index("ix_grant_changes_grant_id", "grant_changes", ["grant_id"])

    op.create_table(
        "grants_meta",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("version", _BIGINT, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_grants_meta"),
    )
    op.execute("INSERT INTO grants_meta (id, version) VALUES (1, 0)")


def downgrade() -> None:
    op.drop_table("grants_meta")
    op.drop_index("ix_grant_changes_grant_id", table_name="grant_changes")
    op.drop_table("grant_changes")
    op.drop_index("ix_grants_subject", table_name="grants")
    op.drop_table("grants")
    op.drop_index("ix_api_keys_user_id", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
