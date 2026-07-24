from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db import async_session_maker, get_session
from app.jobs.purge import purge_expired, sweep_orphans
from app.lib.audit import (
    ACTION_BACKUP_RUN,
    ACTION_BROADCAST_SENT,
    ACTION_PURGE_RUN,
    ACTION_REPORT_DISMISSED,
    ACTION_SNIPPET_TAKEN_DOWN,
    ACTION_THRESHOLD_UPDATED,
    record_action,
)
from app.lib.auth import AdminUser
from app.lib.backup import create_backup
from app.lib.dashboard import DASHBOARD_CACHE_KEY, build_quota_history, load_dashboard
from app.lib.email import EmailMessage, EmailTransport, get_email_transport
from app.lib.killswitch import get_switch, set_switch
from app.lib.providers import CAPPED_QUOTA_KEYS
from app.lib.reauth import reauth
from app.lib.storage import ObjectStoreDep
from app.models.accounts import User
from app.models.admin import AdminAlertPref, AdminThreshold, KillSwitchName
from app.models.reports import Report, ReportResolution
from app.models.snippets import Snippet
from app.redis_client import get_redis
from app.schemas.admin import (
    AlertPrefRequest,
    AlertPrefResponse,
    BackupResult,
    BroadcastRequest,
    BroadcastResult,
    KillSwitchState,
    PurgeResult,
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
SettingsDep = Annotated[Settings, Depends(get_settings)]
EmailDep = Annotated[EmailTransport, Depends(get_email_transport)]

_KILL_SWITCH_NAMES = frozenset(s.value for s in KillSwitchName)


def _http_client(request: Request) -> httpx.AsyncClient:
    client: httpx.AsyncClient = request.app.state.http_client
    return client


@router.get("/dashboard", response_model=DashboardResponse)
async def dashboard(
    request: Request,
    admin: AdminUser,
    session: DbSession,
    redis_client: RedisDep,
    settings: SettingsDep,
) -> DashboardResponse:
    """Aggregated console payload, cached 30 s. Internal metrics are real;
    provider metrics show a yellow '?' until their key is configured + reachable."""
    _ = admin
    return await load_dashboard(session, redis_client, _http_client(request), settings)


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
    await redis_client.delete(DASHBOARD_CACHE_KEY)
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
    await redis_client.delete(DASHBOARD_CACHE_KEY)  # ops panel reflects the toggle
    return KillSwitchState(name=name, enabled=enabled, message=message)


# --- actions -----------------------------------------------------------------


@router.post("/actions/purge", response_model=PurgeResult)
async def run_purge(
    admin: AdminUser, session: DbSession, store: ObjectStoreDep, redis_client: RedisDep
) -> PurgeResult:
    """Run the expired-snippet purge + orphan sweep now, instead of waiting for
    the next scheduled tick."""
    deleted = await purge_expired(async_session_maker, store)
    swept = await sweep_orphans(async_session_maker, store)
    await record_action(
        session,
        actor_id=admin.id,
        action=ACTION_PURGE_RUN,
        metadata={"deleted": deleted, "swept_orphans": swept},
    )
    await session.commit()
    await redis_client.delete(DASHBOARD_CACHE_KEY)  # counts changed
    return PurgeResult(deleted=deleted, swept_orphans=swept)


@router.post("/actions/backup", response_model=BackupResult)
async def run_backup(
    admin: AdminUser, session: DbSession, store: ObjectStoreDep, settings: SettingsDep
) -> BackupResult:
    """Dump the database and upload it to R2 under ``backups/`` now."""
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="object storage not configured"
        )
    try:
        key, size = await create_backup(store, settings.database_url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"backup failed: {exc}"
        ) from exc
    await record_action(
        session,
        actor_id=admin.id,
        action=ACTION_BACKUP_RUN,
        target_type="backup",
        target_id=key,
        metadata={"size_bytes": size},
    )
    await session.commit()
    return BackupResult(key=key, size_bytes=size)


async def _send_lockout_alert(transport: EmailTransport, to: str, app_base_url: str) -> None:
    await transport.send(
        EmailMessage(
            to=to,
            subject="Your Wispr account was locked",
            text_body=(
                "Your Wispr account was locked for one hour after 10 failed "
                "passphrase attempts.\n\nIf this wasn't you, sign in and review "
                f"your devices: {app_base_url}/me/settings"
            ),
        )
    )


@router.post("/actions/broadcast-email", response_model=None)
async def broadcast_email(
    body: BroadcastRequest,
    admin: AdminUser,
    session: DbSession,
    settings: SettingsDep,
    email_transport: EmailDep,
    background: BackgroundTasks,
) -> BroadcastResult | JSONResponse:
    """Email every live member. First call previews (no send, no re-auth); a
    confirmed call re-auths with the current passphrase, then sends."""
    recipient_count = (
        await session.scalar(
            select(func.count()).select_from(User).where(User.deleted_at.is_(None))
        )
    ) or 0

    if not body.confirm:
        return BroadcastResult(
            preview=True, recipient_count=recipient_count, subject=body.subject, sent=0
        )

    if admin.auth_credential_hash is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="set a passphrase before broadcasting"
        )
    if not body.current_auth_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="passphrase required to send"
        )
    now = datetime.now(tz=UTC)
    outcome = await reauth(
        session, admin, base64.b64decode(body.current_auth_token), settings.server_pepper, now
    )
    if not outcome.ok:
        await session.commit()  # persist the failed-attempt / lockout counters
        if outcome.send_email:
            background.add_task(
                _send_lockout_alert, email_transport, admin.email, settings.app_base_url
            )
        reason = "locked" if outcome.locked else "wrong_passphrase"
        code = status.HTTP_423_LOCKED if outcome.locked else status.HTTP_401_UNAUTHORIZED
        return JSONResponse(status_code=code, content={"reason": reason}, background=background)

    emails = list(await session.scalars(select(User.email).where(User.deleted_at.is_(None))))
    for address in emails:
        background.add_task(
            email_transport.send,
            EmailMessage(to=address, subject=body.subject, text_body=body.body),
        )
    await record_action(
        session,
        actor_id=admin.id,
        action=ACTION_BROADCAST_SENT,
        metadata={"subject": body.subject, "recipient_count": len(emails)},
    )
    await session.commit()
    response = BroadcastResult(
        preview=False, recipient_count=len(emails), subject=body.subject, sent=len(emails)
    )
    return JSONResponse(content=response.model_dump(), background=background)
