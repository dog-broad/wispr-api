"""add magic_link_tokens invite_id

Ties a pending sign-up magic link to the invite it will consume when the
account is created at verify time.

Revision ID: af345a0c09d4
Revises: dceb4da027ad
Create Date: 2026-07-10 09:46:52.052904

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "af345a0c09d4"
down_revision: str | Sequence[str] | None = "dceb4da027ad"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FK_NAME = "fk_magic_link_tokens_invite_id_invites"


def upgrade() -> None:
    op.add_column("magic_link_tokens", sa.Column("invite_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        _FK_NAME,
        "magic_link_tokens",
        "invites",
        ["invite_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(_FK_NAME, "magic_link_tokens", type_="foreignkey")
    op.drop_column("magic_link_tokens", "invite_id")
