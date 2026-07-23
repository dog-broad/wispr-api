from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.models.reports import ReportReasonCategory

# Free-text explanation cap — 1 KiB, matched by a CHECK constraint on the column.
REASON_TEXT_MAX_LEN = 1024


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
