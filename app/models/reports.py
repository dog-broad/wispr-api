from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

_UUID_PK = text("gen_random_uuid()")

# A SHA-256 hex digest is 64 chars. The IP is peppered and hashed before it
# lands here: the value exists only to rate-limit and de-duplicate reporters,
# never to recover the address.
_IP_HASH_LEN = 64

# Free-text explanation cap. Matches the 1 KiB the request schema enforces so a
# payload that slips past validation still fails at the storage boundary.
_REASON_TEXT_MAX = 1024


class ReportReasonCategory(enum.StrEnum):
    spam = "spam"
    malware = "malware"
    illegal = "illegal"
    harassment = "harassment"
    other = "other"


class ReportResolution(enum.StrEnum):
    dismissed = "dismissed"
    taken_down = "taken_down"


class Report(Base):
    """A receiver's takedown report against a PIN-share.

    Only PIN shares (server-key mode) can be reviewed and taken down, so a
    report always references one at submit time. The snippet it points at is
    ephemeral (it can expire and be purged, or vanish when its owner deletes
    their account), but the report itself is kept as an audit record, with the
    pointer nulled once the snippet is gone. The remaining fields (reason,
    reporter, timestamps, resolution) stay intact regardless.
    """

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=_UUID_PK
    )
    # Nullable + SET NULL: the report outlives the snippet. Validated as a live
    # pin_share when it's filed; only ever goes null when that snippet is later
    # purged or hard-deleted.
    snippet_id: Mapped[str | None] = mapped_column(
        String(12),
        ForeignKey("snippets.id", ondelete="SET NULL", name="fk_reports_snippet_id_snippets"),
        nullable=True,
    )
    reporter_ip: Mapped[str] = mapped_column(String(_IP_HASH_LEN), nullable=False)
    # Null for an anonymous receiver; nulled (not cascaded) if a signed-in
    # reporter later deletes their account, so the report survives for audit.
    reporter_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL", name="fk_reports_reporter_user_id_users"),
        nullable=True,
    )
    reason_category: Mapped[ReportReasonCategory] = mapped_column(
        Enum(ReportReasonCategory, name="report_reason_category", native_enum=True),
        nullable=False,
    )
    reason_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    # --- Resolution (set by the operator review flow) ----------------------
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL", name="fk_reports_resolved_by_user_id_users"),
        nullable=True,
    )
    resolution: Mapped[ReportResolution | None] = mapped_column(
        Enum(ReportResolution, name="report_resolution", native_enum=True),
        nullable=True,
    )
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        CheckConstraint(
            f"reason_text IS NULL OR char_length(reason_text) <= {_REASON_TEXT_MAX}",
            name="ck_reports_reason_text_len",
        ),
        # Admin review joins a report to its snippet.
        Index("ix_reports_snippet_id", "snippet_id"),
        # The operator queue lists unresolved reports oldest-first; a partial
        # index keeps that read cheap as resolved rows accumulate.
        Index(
            "ix_reports_pending",
            "created_at",
            postgresql_where=text("resolved_at IS NULL"),
        ),
    )
