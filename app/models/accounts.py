from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

# Postgres 16 ships gen_random_uuid() in core (no pgcrypto extension needed),
# so UUID primary keys default server-side rather than round-tripping a
# Python-generated value.
_UUID_PK = text("gen_random_uuid()")

# RFC 5321 caps an address at 320 octets; size the email columns to match so a
# pathological input fails at the boundary instead of silently truncating.
_EMAIL_LEN = 320


class MagicLinkPurpose(enum.StrEnum):
    sign_in = "sign_in"
    sign_up = "sign_up"
    change_email = "change_email"


class User(Base):
    """A member account.

    The credential columns are nullable because a row is created the moment a
    sign-up magic link is consumed, but the passphrase (and therefore the
    derived auth credential + salts) isn't set until the separate first-time
    setup step. A user with null credentials has verified their email but not
    yet finished onboarding; the auth layer treats that as "must set
    passphrase" rather than "can sign in".
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=_UUID_PK
    )
    email: Mapped[str] = mapped_column(String(_EMAIL_LEN), nullable=False)

    # argon2id(client-derived auth_token, server_pepper); compared on login.
    auth_credential_hash: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Client PBKDF2-100k salt, domain label "wispr-auth-v1".
    auth_credential_salt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Client PBKDF2-600k salt, domain label "wispr-master-v1". Independent chain
    # from the auth salt so the server can never derive the master key.
    master_key_salt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Bumped on passphrase change; other devices see the mismatch on their next
    # authed call and force a re-prompt.
    master_key_version: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("1")
    )

    invited_by: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    # Soft-delete tombstone; a janitor hard-deletes the row 24h later.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # Email is unique only among live accounts. A soft-deleted address is
        # freed for re-signup during the 24h tombstone window; the partial
        # index skips tombstoned rows so that re-use doesn't collide.
        Index(
            "uq_users_email_active",
            "email",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class Invite(Base):
    """A single-use sign-up code issued by an admin."""

    __tablename__ = "invites"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=_UUID_PK
    )
    code: Mapped[str] = mapped_column(String(8), nullable=False, unique=True)
    created_by: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    used_by: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Session(Base):
    """An authenticated device session.

    The cookie carries an opaque 32-byte token; only its SHA-256 lives here in
    ``token_hash`` (never the raw token). ``id`` is the non-secret handle used
    to revoke a specific device and is never placed in the cookie.
    """

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=_UUID_PK
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    device_label: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    __table_args__ = (Index("ix_sessions_user_id", "user_id"),)


class MagicLinkToken(Base):
    """A single-use, 15-minute email link for sign-in, sign-up, or email change.

    Only ``token_hash`` (SHA-256 of the opaque 32-byte token) is stored; the
    raw token exists only in the emailed URL.
    """

    __tablename__ = "magic_link_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=_UUID_PK
    )
    # Null for sign-up-with-invite; resolved to the new user when consumed.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
    )
    email: Mapped[str] = mapped_column(String(_EMAIL_LEN), nullable=False)
    purpose: Mapped[MagicLinkPurpose] = mapped_column(
        Enum(MagicLinkPurpose, name="magic_link_purpose", native_enum=True),
        nullable=False,
    )
    # Set only for purpose=sign_up: ties the pending link to the invite that
    # gets consumed when the account is created at verify time.
    invite_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("invites.id", ondelete="SET NULL"),
        nullable=True,
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    new_email: Mapped[str | None] = mapped_column(String(_EMAIL_LEN), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    request_ip: Mapped[str] = mapped_column(String(45), nullable=False)

    __table_args__ = (Index("ix_magic_link_tokens_expires_at", "expires_at"),)


class PassphraseLockout(Base):
    """Per-user passphrase brute-force state.

    One row per user (the user id is the primary key). Ten wrong attempts in a
    rolling 15-minute window lock the account for an hour; the audit email is
    throttled to at most one per 24h via ``last_email_sent_at``.
    """

    __tablename__ = "passphrase_lockouts"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    window_started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_email_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class EmailChangeRequest(Base):
    """An in-flight email change, confirmed by a magic link to the new address."""

    __tablename__ = "email_change_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=_UUID_PK
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    old_email: Mapped[str] = mapped_column(String(_EMAIL_LEN), nullable=False)
    new_email: Mapped[str] = mapped_column(String(_EMAIL_LEN), nullable=False)
    magic_link_token_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("magic_link_tokens.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
