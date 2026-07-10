"""create accounts tables

Adds the member-account foundation: users, invites, sessions, magic-link
tokens, passphrase lockouts, and email-change requests. Also wires the
snippets.owner_user_id foreign key now that a users table exists to target;
deleting an owner cascades to their snippets (account-deletion cascade).

Revision ID: dceb4da027ad
Revises: 619b664ae9d0
Create Date: 2026-07-10 09:34:34.246539

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "dceb4da027ad"
down_revision: str | Sequence[str] | None = "619b664ae9d0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("email", sa.String(length=320), nullable=False),
        # Credential columns are null until first-time passphrase setup; a row
        # exists from the moment a sign-up link is consumed.
        sa.Column("auth_credential_hash", sa.LargeBinary(), nullable=True),
        sa.Column("auth_credential_salt", sa.LargeBinary(), nullable=True),
        sa.Column("master_key_salt", sa.LargeBinary(), nullable=True),
        sa.Column(
            "master_key_version",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column("invited_by", sa.UUID(), nullable=True),
        sa.Column("is_admin", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["invited_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    # Email is unique only among live accounts; a soft-deleted address frees up
    # during the 24h tombstone window.
    op.create_index(
        "uq_users_email_active",
        "users",
        ["email"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    op.create_table(
        "invites",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("code", sa.String(length=8), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=False),
        sa.Column("used_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["used_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code"),
    )

    op.create_table(
        "magic_link_tokens",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column(
            "purpose",
            sa.Enum("sign_in", "sign_up", "change_email", name="magic_link_purpose"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("new_email", sa.String(length=320), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("request_ip", sa.String(length=45), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        "ix_magic_link_tokens_expires_at",
        "magic_link_tokens",
        ["expires_at"],
        unique=False,
    )

    op.create_table(
        "passphrase_lockouts",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column(
            "failed_attempts",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "window_started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_email_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )

    op.create_table(
        "sessions",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("device_label", sa.String(length=256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"], unique=False)

    op.create_table(
        "email_change_requests",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("old_email", sa.String(length=320), nullable=False),
        sa.Column("new_email", sa.String(length=320), nullable=False),
        sa.Column("magic_link_token_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["magic_link_token_id"], ["magic_link_tokens.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # Now that users exists, wire the ownership FK on snippets. The index
    # ix_snippets_owner_user_id already exists from the base migration.
    op.create_foreign_key(
        "fk_snippets_owner_user_id_users",
        "snippets",
        "users",
        ["owner_user_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint("fk_snippets_owner_user_id_users", "snippets", type_="foreignkey")
    op.drop_table("email_change_requests")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_table("sessions")
    op.drop_table("passphrase_lockouts")
    op.drop_index("ix_magic_link_tokens_expires_at", table_name="magic_link_tokens")
    op.drop_table("magic_link_tokens")
    op.drop_table("invites")
    op.drop_index(
        "uq_users_email_active",
        table_name="users",
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.drop_table("users")
    # Drop the ENUM type last — dropping magic_link_tokens removes the column
    # reference, not the type definition, so a later re-upgrade would fail with
    # "type magic_link_purpose already exists" without this.
    sa.Enum(name="magic_link_purpose").drop(op.get_bind(), checkfirst=False)
