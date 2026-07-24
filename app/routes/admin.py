from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db import get_session
from app.lib.audit import (
    ACTION_REPORT_DISMISSED,
    ACTION_SNIPPET_TAKEN_DOWN,
    ACTION_THRESHOLD_UPDATED,
    record_action,
)
from app.lib.auth import AdminUser
from app.lib.dashboard import build_dashboard, build_quota_history
from app.lib.killswitch import get_switch, set_switch
from app.lib.providers import CAPPED_QUOTA_KEYS
from app.models.admin import AdminAlertPref, AdminThreshold, KillSwitchName
from app.models.reports import Report, ReportResolution
from app.models.snippets import Snippet
from app.redis_client import get_redis
from app.schemas.admin import (
    AlertPrefRequest,
    AlertPrefResponse,
    KillSwitchState,
    SetKillSwitchRequest,
    SetThresholdRequest,
    ThresholdItem,
    ThresholdListResponse,
)
from app.schemas.dashboard import DashboardResponse, QuotaHistoryResponse
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
RedisDep = Annotated[Redis, Depends(get_redis)]

_KILL_SWITCH_NAMES = frozenset(s.value for s in KillSwitchName)

_DASHBOARD_CACHE_KEY = "admin:dashboard"
_DASHBOARD_CACHE_TTL = 30


def _http_client(request: Request) -> httpx.AsyncClient:
    client: httpx.AsyncClient = request.app.state.http_client
    return client


@router.get("/dashboard", response_model=DashboardResponse)
async def dashboard(
    request: Request,
    admin: AdminUser,
    session: DbSession,
    redis_client: RedisDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> DashboardResponse:
    """Aggregated console payload, cached 30 s. Internal metrics are real;
    provider metrics show a yellow '?' until their key is configured + reachable."""
    _ = admin
    cached = await redis_client.get(_DASHBOARD_CACHE_KEY)
    if cached is not None:
        return DashboardResponse.model_validate_json(cached)
    payload = await build_dashboard(session, redis_client, _http_client(request), settings)
    await redis_client.set(_DASHBOARD_CACHE_KEY, payload.model_dump_json(), ex=_DASHBOARD_CACHE_TTL)
    return payload


@router.get("/quotas/{metric}/history", response_model=QuotaHistoryResponse)
async def quota_history(metric: str, admin: AdminUser, session: DbSession) -> QuotaHistoryResponse:
    """7-day daily series for a metric's drill-down. Derived on the fly for
    DB-backed metrics (snippets, signups); provider metrics report no history
    until a snapshot store exists."""
    _ = admin
    return await build_quota_history(session, metric)


@router.get("/thresholds", response_model=ThresholdListResponse)
async def list_thresholds(admin: AdminUser, session: DbSession) -> ThresholdListResponse:
    """Configured per-metric warn/alert thresholds. Metrics without a row use
    the dashboard defaults."""
    _ = admin
    rows = list(await session.scalars(select(AdminThreshold).order_by(AdminThreshold.metric)))
    return ThresholdListResponse(
        thresholds=[
            ThresholdItem(metric=t.metric, warn_pct=t.warn_pct, alert_pct=t.alert_pct) for t in rows
        ]
    )


@router.put("/thresholds/{metric}", response_model=ThresholdItem)
async def set_threshold(
    metric: str,
    body: SetThresholdRequest,
    admin: AdminUser,
    session: DbSession,
    redis_client: RedisDep,
) -> ThresholdItem:
    """Set a capped quota's warn/alert percentages. Upserts, audits, and busts
    the dashboard cache so the new colouring shows immediately."""
    if metric not in CAPPED_QUOTA_KEYS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown metric")
    row = await session.scalar(select(AdminThreshold).where(AdminThreshold.metric == metric))
    if row is None:
        row = AdminThreshold(metric=metric)
        session.add(row)
    row.warn_pct = body.warn_pct
    row.alert_pct = body.alert_pct
    row.updated_at = datetime.now(tz=UTC)
    row.updated_by_user_id = admin.id
    await record_action(
        session,
        actor_id=admin.id,
        action=ACTION_THRESHOLD_UPDATED,
        target_type="metric",
        target_id=metric,
        metadata={"warn_pct": body.warn_pct, "alert_pct": body.alert_pct},
    )
    await session.commit()
    await redis_client.delete(_DASHBOARD_CACHE_KEY)
    return ThresholdItem(metric=metric, warn_pct=body.warn_pct, alert_pct=body.alert_pct)


@router.post("/alerts/preferences", response_model=AlertPrefResponse)
async def set_alert_preference(
    body: AlertPrefRequest, admin: AdminUser, session: DbSession
) -> AlertPrefResponse:
    """Opt this admin in/out of red-state email alerts for one metric. Personal
    preference — upserted for the caller only, not audited."""
    if body.metric not in CAPPED_QUOTA_KEYS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown metric")
    row = await session.scalar(
        select(AdminAlertPref).where(
            AdminAlertPref.user_id == admin.id, AdminAlertPref.metric == body.metric
        )
    )
    if row is None:
        row = AdminAlertPref(user_id=admin.id, metric=body.metric)
        session.add(row)
    row.enabled = body.enabled
    await session.commit()
    return AlertPrefResponse(metric=body.metric, enabled=body.enabled)


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


def _valid_switch(name: str) -> str:
    if name not in _KILL_SWITCH_NAMES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown kill switch")
    return name


@router.get("/kill-switch/{name}", response_model=KillSwitchState)
async def read_kill_switch(
    name: str, admin: AdminUser, session: DbSession, redis_client: RedisDep
) -> KillSwitchState:
    """Current state of one kill switch (off if never toggled)."""
    _ = admin
    enabled, message = await get_switch(redis_client, session, _valid_switch(name))
    return KillSwitchState(name=name, enabled=enabled, message=message)


@router.post("/kill-switch/{name}", response_model=KillSwitchState)
async def toggle_kill_switch(
    name: str,
    body: SetKillSwitchRequest,
    admin: AdminUser,
    session: DbSession,
    redis_client: RedisDep,
) -> KillSwitchState:
    """Toggle a feature kill switch. Persists, busts the 30 s cache, and logs
    the change. ``message`` is the public banner text for ``maintenance_mode``."""
    enabled, message = await set_switch(
        session,
        redis_client,
        name=_valid_switch(name),
        enabled=body.enabled,
        message=body.message,
        actor_id=admin.id,
    )
    return KillSwitchState(name=name, enabled=enabled, message=message)
