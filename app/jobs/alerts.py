from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta

import httpx
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.lib.dashboard import DASHBOARD_CACHE_KEY, DASHBOARD_CACHE_TTL, build_dashboard
from app.lib.email import EmailMessage, EmailTransport
from app.models.accounts import User
from app.models.admin import AdminAlertPref
from app.schemas.dashboard import DashboardResponse, Metric, MetricStatus

logger = logging.getLogger(__name__)

# At most one alert email per (admin, metric) per hour.
_THROTTLE = timedelta(hours=1)


def _alerting(dashboard: DashboardResponse) -> list[Metric]:
    sections = (
        dashboard.quotas,
        dashboard.health,
        dashboard.business,
        dashboard.abuse,
        dashboard.ops,
    )
    return [m for section in sections for m in section if m.status is MetricStatus.alert]


async def send_metric_alerts(
    session: AsyncSession,
    dashboard: DashboardResponse,
    transport: EmailTransport,
    app_base_url: str,
    now: datetime,
) -> int:
    """Email opted-in admins about each red (alert) metric, throttled to one per
    (admin, metric) per hour. Returns the number of emails sent."""
    alerting = _alerting(dashboard)
    if not alerting:
        return 0

    sent = 0
    for metric in alerting:
        prefs = list(
            await session.scalars(
                select(AdminAlertPref).where(
                    AdminAlertPref.metric == metric.key, AdminAlertPref.enabled.is_(True)
                )
            )
        )
        for pref in prefs:
            if pref.last_emailed_at is not None and now - pref.last_emailed_at < _THROTTLE:
                continue
            user = await session.get(User, pref.user_id)
            if user is None or user.deleted_at is not None:
                continue
            await transport.send(
                EmailMessage(
                    to=user.email,
                    subject=f"Wispr alert: {metric.label} is critical",
                    text_body=(
                        f"{metric.label} has crossed its alert threshold"
                        f"{f' ({metric.value})' if metric.value else ''}.\n\n"
                        f"Check the operator console: {app_base_url}/me/admin"
                    ),
                )
            )
            pref.last_emailed_at = now
            sent += 1

    await session.commit()
    return sent


async def _poll_once(
    session_factory: async_sessionmaker[AsyncSession],
    redis: Redis,
    http_client: httpx.AsyncClient,
    settings: Settings,
    transport: EmailTransport,
) -> None:
    async with session_factory() as session:
        dashboard = await build_dashboard(session, redis, http_client, settings)
        # Warm the cache so the GET/WS read path hits it instead of rebuilding.
        await redis.set(DASHBOARD_CACHE_KEY, dashboard.model_dump_json(), ex=DASHBOARD_CACHE_TTL)
        sent = await send_metric_alerts(
            session, dashboard, transport, settings.app_base_url, datetime.now(tz=UTC)
        )
    if sent:
        logger.info("alerts: sent %d red-state email(s)", sent)


async def run_alert_poll_loop(
    session_factory: async_sessionmaker[AsyncSession],
    redis: Redis,
    http_client: httpx.AsyncClient,
    settings: Settings,
    transport: EmailTransport,
    interval_seconds: int,
    stop_event: asyncio.Event,
) -> None:
    """Every ``interval_seconds`` build the dashboard, warm its cache, and email
    any red-state alerts. Mirrors the purge loop; ``interval_seconds <= 0``
    disables it. Errors are logged and swallowed so a transient outage doesn't
    kill the loop."""
    if interval_seconds <= 0:
        logger.info("alerts: disabled (interval=%d)", interval_seconds)
        await stop_event.wait()
        return

    while not stop_event.is_set():
        try:
            await _poll_once(session_factory, redis, http_client, settings, transport)
        except Exception:
            logger.exception("alerts: poll failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except TimeoutError:
            continue
