"""create snippets table

Single table covers all four share modes. The first ship cycle only writes
rows with ``share_mode='link'``; pin-share and sync columns are present as
nullable from day one (gated by CHECK constraints) so later phases can fill
them in without a destructive schema change.

Revision ID: 619b664ae9d0
Revises:
Create Date: 2026-05-24 13:51:03.576865

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "619b664ae9d0"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "snippets",
        # Identity
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column(
            "share_mode",
            sa.Enum("link", "pin_share", "sync", name="share_mode"),
            nullable=False,
        ),
        sa.Column(
            "content_type",
            sa.Enum("text", "code", "url", "file", name="content_type"),
            nullable=False,
        ),
        # Payload (encrypted on the client)
        sa.Column("encrypted_metadata", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext_inline", sa.LargeBinary(), nullable=True),
        sa.Column("storage_object_key", sa.Text(), nullable=True),
        sa.Column("chunk_count", sa.Integer(), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        # PIN-share (Mode 2): nullable, gated by ck_snippets_pin_columns
        sa.Column("pin", sa.String(length=4), nullable=True),
        sa.Column("encrypted_content_key", sa.LargeBinary(), nullable=True),
        sa.Column("content_key_iv", sa.LargeBinary(), nullable=True),
        sa.Column("key_version", sa.Integer(), nullable=True),
        sa.Column(
            "pin_failed_attempts",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        # Sync (Mode 4): nullable, gated by ck_snippets_sync_columns
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=True),
        sa.Column("wrapped_dek_iv", sa.LargeBinary(), nullable=True),
        # Lifecycle
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("max_reads", sa.Integer(), nullable=True),
        sa.Column(
            "read_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        # Optional server-side password gate (access control only)
        sa.Column("password_hash", sa.LargeBinary(), nullable=True),
        sa.Column("password_salt", sa.LargeBinary(), nullable=True),
        # Ownership / derivation
        sa.Column("owner_user_id", sa.UUID(), nullable=True),
        sa.Column("parent_snippet_id", sa.String(length=12), nullable=True),
        # Moderation (admin take-down; Mode 2 only in practice)
        sa.Column("taken_down_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("taken_down_reason", sa.Text(), nullable=True),
        # Mode invariants
        sa.CheckConstraint(
            "share_mode <> 'link' OR ("
            " pin IS NULL"
            " AND encrypted_content_key IS NULL"
            " AND content_key_iv IS NULL"
            " AND key_version IS NULL"
            " AND wrapped_dek IS NULL"
            " AND wrapped_dek_iv IS NULL"
            " AND (max_reads IS NULL OR max_reads <= 1)"
            ")",
            name="ck_snippets_link_columns",
        ),
        sa.CheckConstraint(
            "share_mode <> 'pin_share' OR ("
            " pin IS NOT NULL"
            " AND encrypted_content_key IS NOT NULL"
            " AND content_key_iv IS NOT NULL"
            " AND key_version IS NOT NULL"
            " AND owner_user_id IS NOT NULL"
            " AND wrapped_dek IS NULL"
            " AND wrapped_dek_iv IS NULL"
            ")",
            name="ck_snippets_pin_columns",
        ),
        sa.CheckConstraint(
            "share_mode <> 'sync' OR ("
            " owner_user_id IS NOT NULL"
            " AND wrapped_dek IS NOT NULL"
            " AND wrapped_dek_iv IS NOT NULL"
            " AND pin IS NULL"
            " AND key_version IS NULL"
            ")",
            name="ck_snippets_sync_columns",
        ),
        # Counter / size sanity
        sa.CheckConstraint("read_count >= 0", name="ck_snippets_read_count_nonneg"),
        sa.CheckConstraint(
            "pin_failed_attempts >= 0", name="ck_snippets_pin_attempts_nonneg"
        ),
        sa.CheckConstraint("size_bytes >= 0", name="ck_snippets_size_nonneg"),
        # PIN format
        sa.CheckConstraint(
            "pin IS NULL OR pin ~ '^[0-9]{4}$'",
            name="ck_snippets_pin_format",
        ),
        # Keys
        sa.ForeignKeyConstraint(
            ["parent_snippet_id"], ["snippets.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_snippets_expires_at", "snippets", ["expires_at"], unique=False
    )
    op.create_index(
        "ix_snippets_owner_user_id", "snippets", ["owner_user_id"], unique=False
    )
    op.create_index(
        "uq_snippets_pin_active",
        "snippets",
        ["pin"],
        unique=True,
        postgresql_where=sa.text("pin IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_snippets_pin_active",
        table_name="snippets",
        postgresql_where=sa.text("pin IS NOT NULL"),
    )
    op.drop_index("ix_snippets_owner_user_id", table_name="snippets")
    op.drop_index("ix_snippets_expires_at", table_name="snippets")
    op.drop_table("snippets")
    # Drop the ENUM types last; dropping the table only removes the column
    # references, not the type definitions, so a subsequent upgrade would
    # otherwise fail with "type X already exists".
    sa.Enum(name="content_type").drop(op.get_bind(), checkfirst=False)
    sa.Enum(name="share_mode").drop(op.get_bind(), checkfirst=False)
