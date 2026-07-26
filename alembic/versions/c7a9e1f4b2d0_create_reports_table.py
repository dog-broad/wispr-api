"""create reports table

Adds the Mode 2 (PIN-share) takedown-report table plus its two enums. A report
references the reported snippet via a nullable FK that SET-NULLs on snippet
deletion, so the report survives as an audit record after its snippet is purged
or its owner's account is deleted. Reporter and resolver FKs also SET NULL so a
deleted account leaves the report intact.

Revision ID: c7a9e1f4b2d0
Revises: af345a0c09d4
Create Date: 2026-07-24 10:12:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c7a9e1f4b2d0"
down_revision: str | Sequence[str] | None = "af345a0c09d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        # Nullable + SET NULL so the report outlives its snippet (audit record).
        sa.Column("snippet_id", sa.String(length=12), nullable=True),
        # SHA-256 hex of the peppered reporter IP — 64 chars; rate-limit only.
        sa.Column("reporter_ip", sa.String(length=64), nullable=False),
        sa.Column("reporter_user_id", sa.UUID(), nullable=True),
        sa.Column(
            "reason_category",
            sa.Enum(
                "spam", "malware", "illegal", "harassment", "other", name="report_reason_category"
            ),
            nullable=False,
        ),
        sa.Column("reason_text", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by_user_id", sa.UUID(), nullable=True),
        sa.Column(
            "resolution",
            sa.Enum("dismissed", "taken_down", name="report_resolution"),
            nullable=True,
        ),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "reason_text IS NULL OR char_length(reason_text) <= 1024",
            name="ck_reports_reason_text_len",
        ),
        sa.ForeignKeyConstraint(
            ["snippet_id"],
            ["snippets.id"],
            name="fk_reports_snippet_id_snippets",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["reporter_user_id"],
            ["users.id"],
            name="fk_reports_reporter_user_id_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["resolved_by_user_id"],
            ["users.id"],
            name="fk_reports_resolved_by_user_id_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_reports_snippet_id", "reports", ["snippet_id"], unique=False)
    op.create_index(
        "ix_reports_pending",
        "reports",
        ["created_at"],
        unique=False,
        postgresql_where=sa.text("resolved_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_reports_pending",
        table_name="reports",
        postgresql_where=sa.text("resolved_at IS NULL"),
    )
    op.drop_index("ix_reports_snippet_id", table_name="reports")
    op.drop_table("reports")
    # Drop the ENUM types last — dropping the table removes the column
    # references, not the type definitions, so a re-upgrade would otherwise
    # fail with "type already exists".
    sa.Enum(name="report_resolution").drop(op.get_bind(), checkfirst=False)
    sa.Enum(name="report_reason_category").drop(op.get_bind(), checkfirst=False)
