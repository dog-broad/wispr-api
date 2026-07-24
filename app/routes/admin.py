from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.lib.audit import (
    ACTION_REPORT_DISMISSED,
    ACTION_SNIPPET_TAKEN_DOWN,
    record_action,
)
from app.lib.auth import AdminUser
from app.models.reports import Report, ReportResolution
from app.models.snippets import Snippet
from app.schemas.reports import (
    AdminReportItem,
    AdminReportListResponse,
    ResolveReportRequest,
    ResolveReportResponse,
)

# All operator-console endpoints live under /me/admin and require an admin.
# The moderation review of reports lands here first; the status-board surfaces
# join it later.
router = APIRouter(prefix="/me/admin", tags=["admin"])

DbSession = Annotated[AsyncSession, Depends(get_session)]


@router.get("/reports", response_model=AdminReportListResponse)
async def list_reports(admin: AdminUser, session: DbSession) -> AdminReportListResponse:
    """Pending (unresolved) takedown reports, oldest-first so the queue is FIFO.
    Each carries a summary of its snippet; a null snippet means the referenced
    share is already gone (purged, or its owner's account was deleted)."""
    _ = admin  # gate only; the query isn't user-scoped
    rows = (
        await session.execute(
            select(Report, Snippet)
            .outerjoin(Snippet, Report.snippet_id == Snippet.id)
            .where(Report.resolved_at.is_(None))
            .order_by(Report.created_at.asc())
        )
    ).all()
    return AdminReportListResponse(
        reports=[
            AdminReportItem(
                id=report.id,
                snippet_id=report.snippet_id,
                reason_category=report.reason_category,
                reason_text=report.reason_text,
                created_at=report.created_at,
                from_member=report.reporter_user_id is not None,
                snippet_present=snippet is not None,
                snippet_content_type=snippet.content_type if snippet is not None else None,
                snippet_taken_down=snippet is not None and snippet.taken_down_at is not None,
            )
            for report, snippet in rows
        ]
    )


@router.post("/reports/{report_id}/resolve", response_model=ResolveReportResponse)
async def resolve_report(
    report_id: uuid.UUID,
    body: ResolveReportRequest,
    admin: AdminUser,
    session: DbSession,
) -> ResolveReportResponse:
    """Resolve a report by taking the reported snippet down or dismissing it.

    A takedown stamps the snippet's ``taken_down_at`` + ``taken_down_reason`` so
    every future receive returns the gone-taken-down state; the row is kept (not
    deleted) precisely so that render works. A dismissal leaves the snippet
    untouched. Either way the report is stamped resolved with who/why."""
    report = await session.scalar(select(Report).where(Report.id == report_id))
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if report.resolved_at is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="report already resolved")

    now = datetime.now(tz=UTC)
    took_down = False
    if body.resolution is ReportResolution.taken_down and report.snippet_id is not None:
        snippet = await session.scalar(select(Snippet).where(Snippet.id == report.snippet_id))
        # A snippet that expired/purged between the report and now is already
        # gone; the report still resolves, but there's nothing to take down.
        if snippet is not None:
            if snippet.taken_down_at is None:
                snippet.taken_down_at = now
                snippet.taken_down_reason = body.notes or report.reason_category.value
            took_down = True

    report.resolved_at = now
    report.resolved_by_user_id = admin.id
    report.resolution = body.resolution
    report.resolution_notes = body.notes
    await record_action(
        session,
        actor_id=admin.id,
        action=(
            ACTION_SNIPPET_TAKEN_DOWN
            if body.resolution is ReportResolution.taken_down
            else ACTION_REPORT_DISMISSED
        ),
        target_type="snippet",
        target_id=report.snippet_id,
        metadata={
            "report_id": str(report.id),
            "resolution": body.resolution.value,
            "notes": body.notes,
        },
    )
    await session.commit()

    return ResolveReportResponse(
        id=report.id,
        resolution=body.resolution,
        resolved_at=now,
        snippet_taken_down=took_down,
    )
