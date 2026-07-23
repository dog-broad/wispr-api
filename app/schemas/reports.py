from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.reports import ReportReasonCategory, ReportResolution
from app.models.snippets import ContentType

# Free-text explanation cap — 1 KiB, matched by a CHECK constraint on the column.
REASON_TEXT_MAX_LEN = 1024
# Operator's resolution note cap — same ceiling as the reporter's detail.
RESOLUTION_NOTES_MAX_LEN = 1024


class CreateReportRequest(BaseModel):
    """Body for the public `POST /reports`. ``snippet_id`` is the id a receiver
    got back from resolving a PIN; ``turnstile_token`` is supplied once the
    per-IP hourly threshold makes a challenge mandatory."""

    model_config = ConfigDict(extra="forbid")

    snippet_id: str = Field(..., min_length=1, max_length=12)
    reason_category: ReportReasonCategory
    reason_text: str | None = Field(default=None, max_length=REASON_TEXT_MAX_LEN)
    turnstile_token: str | None = None


class ReportAcceptedResponse(BaseModel):
    """201 body. Deliberately opaque — filing a report reveals nothing about the
    snippet beyond the fact that it existed as a PIN-share when reported."""

    ok: bool = True


# --- admin review + resolution -----------------------------------------------


class AdminReportItem(BaseModel):
    """A pending report as the operator sees it: the reporter's reason plus a
    summary of the referenced snippet. Content is not decrypted here — that's a
    separate operator-console concern."""

    id: uuid.UUID
    snippet_id: str | None
    reason_category: ReportReasonCategory
    reason_text: str | None
    created_at: datetime
    # True when a signed-in member filed it (vs an anonymous receiver).
    from_member: bool
    # Snippet summary — null/false when the referenced row is already gone
    # (purged or the owner's account was deleted, which nulls snippet_id).
    snippet_present: bool
    snippet_content_type: ContentType | None
    snippet_taken_down: bool


class AdminReportListResponse(BaseModel):
    reports: list[AdminReportItem]


class ResolveReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolution: ReportResolution
    notes: str | None = Field(default=None, max_length=RESOLUTION_NOTES_MAX_LEN)


class ResolveReportResponse(BaseModel):
    id: uuid.UUID
    resolution: ReportResolution
    resolved_at: datetime
    # True when this resolution took the referenced snippet down (false for a
    # dismissal or when the snippet was already gone).
    snippet_taken_down: bool
