from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class ShareMode(enum.StrEnum):
    link = "link"
    pin_share = "pin_share"
    sync = "sync"


class ContentType(enum.StrEnum):
    text = "text"
    code = "code"
    url = "url"
    file = "file"


class Snippet(Base):
    """A unit of shared content.

    One table covers all four share modes (anonymous Link, member PIN-share,
    live Pair, and personal Sync) with mode-specific columns nullable and
    guarded by CHECK constraints. M1 only exercises ``share_mode='link'``;
    the pin-share and sync columns exist from day one so later phases can
    fill them in without a destructive migration.
    """

    __tablename__ = "snippets"

    # --- Identity ----------------------------------------------------------
    # 12-char base62; generated in Python at create time. Stored as TEXT
    # of fixed length so the encoding stays opaque to the database.
    id: Mapped[str] = mapped_column(String(12), primary_key=True)

    share_mode: Mapped[ShareMode] = mapped_column(
        Enum(ShareMode, name="share_mode", native_enum=True),
        nullable=False,
    )
    content_type: Mapped[ContentType] = mapped_column(
        Enum(ContentType, name="content_type", native_enum=True),
        nullable=False,
    )

    # --- Payload (encrypted on the client) ---------------------------------
    encrypted_metadata: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext_inline: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    storage_object_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    chunk_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # --- PIN-share columns (Mode 2, all NULL unless share_mode='pin_share') -
    pin: Mapped[str | None] = mapped_column(String(4), nullable=True)
    encrypted_content_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    content_key_iv: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    key_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pin_failed_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )

    # --- Sync columns (Mode 4, all NULL unless share_mode='sync') ----------
    wrapped_dek: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    wrapped_dek_iv: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # --- Lifecycle ---------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    max_reads: Mapped[int | None] = mapped_column(Integer, nullable=True)
    read_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )

    # --- Optional password gate (access control only, not part of crypto) --
    password_hash: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    password_salt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # --- Ownership / derivation -------------------------------------------
    # Null only for anonymous link shares. Deleting the owner hard-deletes
    # their snippets (account-deletion cascade), so the FK is ON DELETE CASCADE.
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE", name="fk_snippets_owner_user_id_users"),
        nullable=True,
    )
    parent_snippet_id: Mapped[str | None] = mapped_column(
        String(12), ForeignKey("snippets.id", ondelete="SET NULL"), nullable=True
    )

    # --- Moderation (admin take-down, Mode 2 only) -------------------------
    taken_down_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    taken_down_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        # Mode invariants: encoded so a misuse from the application layer
        # surfaces as a constraint violation, not a silent inconsistency.
        CheckConstraint(
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
        CheckConstraint(
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
        CheckConstraint(
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
        CheckConstraint("read_count >= 0", name="ck_snippets_read_count_nonneg"),
        CheckConstraint("pin_failed_attempts >= 0", name="ck_snippets_pin_attempts_nonneg"),
        CheckConstraint("size_bytes >= 0", name="ck_snippets_size_nonneg"),
        # PIN format: four ASCII digits when set
        CheckConstraint(
            "pin IS NULL OR pin ~ '^[0-9]{4}$'",
            name="ck_snippets_pin_format",
        ),
        # One active PIN at a time across the row population
        Index(
            "uq_snippets_pin_active",
            "pin",
            unique=True,
            postgresql_where=text("pin IS NOT NULL"),
        ),
        # Purge job sweeps by expiry; /me/snippets queries by owner
        Index("ix_snippets_expires_at", "expires_at"),
        Index("ix_snippets_owner_user_id", "owner_user_id"),
    )
