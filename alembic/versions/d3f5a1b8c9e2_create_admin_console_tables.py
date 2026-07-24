"""create admin console tables

Adds the operator-console foundation: admin_audit_log (append-only action
record), admin_thresholds (per-metric warn/alert %), admin_alert_prefs
(per-admin red-state email opt-in), and kill_switches (feature gates). User FKs
that record who-did-something SET NULL so audit/config survive a hard-deleted
actor; alert prefs cascade with the account.

Revision ID: d3f5a1b8c9e2
Revises: c7a9e1f4b2d0
Create Date: 2026-07-24 12:40:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "d3f5a1b8c9e2"
down_revision: str | Sequence[str] | None = "c7a9e1f4b2d0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "admin_audit_log",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("actor_user_id", sa.UUID(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=True),
        sa.Column("target_id", sa.Text(), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name="fk_admin_audit_log_actor_user_id_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_admin_audit_log_actor_created",
        "admin_audit_log",
        ["actor_user_id", sa.text("created_at DESC")],
    )
    op.create_index(
        "ix_admin_audit_log_created",
        "admin_audit_log",
        [sa.text("created_at DESC")],
    )

    op.create_table(
        "admin_thresholds",
        sa.Column("metric", sa.String(length=64), nullable=False),
        sa.Column("warn_pct", sa.Integer(), nullable=False),
        sa.Column("alert_pct", sa.Integer(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("updated_by_user_id", sa.UUID(), nullable=True),
        sa.CheckConstraint("warn_pct BETWEEN 0 AND 100", name="ck_admin_thresholds_warn_range"),
        sa.CheckConstraint("alert_pct BETWEEN 0 AND 100", name="ck_admin_thresholds_alert_range"),
        sa.ForeignKeyConstraint(
            ["updated_by_user_id"],
            ["users.id"],
            name="fk_admin_thresholds_updated_by_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("metric"),
    )

    op.create_table(
        "admin_alert_prefs",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("metric", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("last_emailed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_admin_alert_prefs_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", "metric"),
    )

    op.create_table(
        "kill_switches",
        sa.Column("name", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column(
            "toggled_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("toggled_by_user_id", sa.UUID(), nullable=True),
        sa.CheckConstraint(
            "name IN ('mode2', 'anon_link', 'maintenance_mode')",
            name="ck_kill_switches_name",
        ),
        sa.ForeignKeyConstraint(
            ["toggled_by_user_id"],
            ["users.id"],
            name="fk_kill_switches_toggled_by_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("name"),
    )


def downgrade() -> None:
    op.drop_table("kill_switches")
    op.drop_table("admin_alert_prefs")
    op.drop_table("admin_thresholds")
    op.drop_index("ix_admin_audit_log_created", table_name="admin_audit_log")
    op.drop_index("ix_admin_audit_log_actor_created", table_name="admin_audit_log")
    op.drop_table("admin_audit_log")
