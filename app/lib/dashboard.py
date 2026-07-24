from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta

import httpx
from redis.asyncio import Redis
from sqlalchemy import Select, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.lib.killswitch import get_switch
from app.lib.pair_signaling import registry
from app.lib.providers import collect_quotas
from app.lib.sync_bus import bus as sync_bus
from app.models.accounts import PassphraseLockout, User
from app.models.accounts import Session as SessionRow
from app.models.admin import AdminAuditLog, KillSwitchName
from app.models.reports import Report
from app.models.snippets import ShareMode, Snippet
from app.schemas.dashboard import (
    AuditEntry,
    DashboardResponse,
    Metric,
    MetricStatus,
    QuotaHistoryPoint,
    QuotaHistoryResponse,
)

_RECENT_ACTIONS = 20


def _unknown(key: str, label: str, detail: str) -> Metric:
    return Metric(key=key, label=label, status=MetricStatus.unknown, detail=detail)


async def _scalar_int(session: AsyncSession, stmt: Select[tuple[int]]) -> int | None:
    """Run a scalar count, returning None on any error so the caller can render
    the metric as unknown instead of failing the whole dashboard."""
    try:
        value = await session.scalar(stmt)
    except Exception:
        return None
    return int(value) if value is not None else 0


def _count_metric(
    key: str, label: str, value: int | None, *, warn_if_positive: bool = False
) -> Metric:
    if value is None:
        return _unknown(key, label, "query failed")
    status = MetricStatus.warn if (warn_if_positive and value > 0) else MetricStatus.ok
    return Metric(key=key, label=label, status=status, value=str(value))


async def _pg_conns(session: AsyncSession) -> int | None:
    try:
        value = await session.scalar(text("SELECT count(*) FROM pg_stat_activity"))
    except Exception:
        return None
    return int(value) if value is not None else 0


async def _health(session: AsyncSession, redis: Redis) -> list[Metric]:
    out: list[Metric] = [Metric(key="api", label="api", status=MetricStatus.ok, value="up")]

    conns = await _pg_conns(session)
    out.append(
        Metric(key="postgres", label="postgres", status=MetricStatus.ok, value=f"{conns} conns")
        if conns is not None
        else _unknown("postgres", "postgres", "pg_stat_activity read failed")
    )

    try:
        info = await redis.info()
        mem = str(info.get("used_memory_human", "?"))
        clients = info.get("connected_clients", "?")
        out.append(
            Metric(
                key="redis",
                label="redis",
                status=MetricStatus.ok,
                value=f"{mem} · {clients} clients",
            )
        )
    except Exception:
        out.append(_unknown("redis", "redis", "INFO read failed"))

    out.append(
        Metric(
            key="ws_sync",
            label="ws sync",
            status=MetricStatus.ok,
            value=f"{sync_bus.connection_count()} conns",
        )
    )
    out.append(
        Metric(
            key="ws_pair",
            label="ws pair",
            status=MetricStatus.ok,
            value=f"{registry.active_count()} pairings",
        )
    )
    out.append(
        _unknown("cert_expiry", "cert expiry", "reads the Caddy cert volume — not wired yet")
    )
    out.append(_unknown("domain_expiry", "domain expiry", "WHOIS lookup — not wired yet"))
    out.append(_unknown("master_key", "master key age", "rotation timestamp not tracked yet"))
    return out


async def _business(session: AsyncSession, now: datetime) -> list[Metric]:
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    members = await _scalar_int(
        session, select(func.count()).select_from(User).where(User.deleted_at.is_(None))
    )
    active = await _scalar_int(
        session,
        select(func.count(func.distinct(SessionRow.user_id))).where(
            SessionRow.last_seen_at >= now - timedelta(days=1)
        ),
    )
    signups = await _scalar_int(
        session,
        select(func.count())
        .select_from(User)
        .where(User.created_at >= day_start, User.deleted_at.is_(None)),
    )

    snippets = _count_metric("snippets_today", "snippets today", None)
    try:
        rows = (
            (
                await session.execute(
                    select(Snippet.share_mode, func.count())
                    .where(Snippet.created_at >= day_start)
                    .group_by(Snippet.share_mode)
                )
            )
            .tuples()
            .all()
        )
        by_mode = dict(rows)
        total = sum(by_mode.values())
        breakdown = (
            f"link {by_mode.get(ShareMode.link, 0)} · "
            f"pin {by_mode.get(ShareMode.pin_share, 0)} · "
            f"sync {by_mode.get(ShareMode.sync, 0)}"
        )
        snippets = Metric(
            key="snippets_today",
            label="snippets today",
            status=MetricStatus.ok,
            value=f"{total} ({breakdown})",
        )
    except Exception:
        snippets = _unknown("snippets_today", "snippets today", "query failed")

    return [
        _count_metric("members", "members", members),
        _count_metric("active_24h", "active (24h)", active),
        snippets,
        _count_metric("signups_today", "sign-ups today", signups),
    ]


async def _abuse(session: AsyncSession, now: datetime) -> list[Metric]:
    reports = await _scalar_int(
        session, select(func.count()).select_from(Report).where(Report.resolved_at.is_(None))
    )
    locked = await _scalar_int(
        session,
        select(func.count())
        .select_from(PassphraseLockout)
        .where(PassphraseLockout.locked_until.is_not(None), PassphraseLockout.locked_until > now),
    )
    failed_pin = await _scalar_int(
        session,
        select(func.coalesce(func.sum(Snippet.pin_failed_attempts), 0)).where(
            Snippet.share_mode == ShareMode.pin_share
        ),
    )
    return [
        _count_metric("reports_pending", "reports pending", reports, warn_if_positive=True),
        _count_metric("locked_out", "locked-out users", locked, warn_if_positive=True),
        _count_metric("failed_pin", "failed PIN attempts", failed_pin),
    ]


async def _switch_metric(session: AsyncSession, redis: Redis, name: str, label: str) -> Metric:
    enabled, _ = await get_switch(redis, session, name)
    return Metric(
        key=f"switch_{name}",
        label=label,
        status=MetricStatus.warn if enabled else MetricStatus.ok,
        value="on" if enabled else "off",
    )


async def _ops(session: AsyncSession, redis: Redis) -> list[Metric]:
    return [
        await _switch_metric(session, redis, KillSwitchName.maintenance_mode.value, "maintenance"),
        await _switch_metric(session, redis, KillSwitchName.mode2.value, "mode 2 kill switch"),
        await _switch_metric(
            session, redis, KillSwitchName.anon_link.value, "anon link kill switch"
        ),
        _unknown("backups", "last backup", "backup job + R2 listing not wired yet"),
        _unknown("purge", "purge job", "last-run not tracked yet"),
    ]


async def _recent_actions(session: AsyncSession) -> list[AuditEntry]:
    try:
        rows = list(
            await session.scalars(
                select(AdminAuditLog)
                .order_by(AdminAuditLog.created_at.desc())
                .limit(_RECENT_ACTIONS)
            )
        )
    except Exception:
        return []
    return [
        AuditEntry(
            action=r.action,
            target_type=r.target_type,
            target_id=r.target_id,
            created_at=r.created_at,
        )
        for r in rows
    ]


def _overall_status(metrics: list[Metric]) -> MetricStatus:
    """Banner status: worst of alert > warn > ok. ``unknown`` is informational
    (a per-metric yellow "?") and never flips the banner."""
    statuses = {m.status for m in metrics}
    if MetricStatus.alert in statuses:
        return MetricStatus.alert
    if MetricStatus.warn in statuses:
        return MetricStatus.warn
    return MetricStatus.ok


async def build_dashboard(
    session: AsyncSession, redis: Redis, http_client: httpx.AsyncClient, settings: Settings
) -> DashboardResponse:
    now = datetime.now(tz=UTC)
    quotas = await collect_quotas(http_client, settings)
    health = await _health(session, redis)
    business = await _business(session, now)
    abuse = await _abuse(session, now)
    ops = await _ops(session, redis)
    actions = await _recent_actions(session)

    all_metrics: list[Metric] = [*quotas, *health, *business, *abuse, *ops]
    return DashboardResponse(
        generated_at=now,
        status=_overall_status(all_metrics),
        quotas=quotas,
        health=health,
        business=business,
        abuse=abuse,
        ops=ops,
        recent_actions=actions,
    )


# --- quota history (7-day drill-down) ----------------------------------------

_HISTORY_DAYS = 7
# Metrics with a per-day series reconstructable from existing rows.
_DERIVABLE_HISTORY = {"snippets", "signups"}


async def build_quota_history(session: AsyncSession, metric: str) -> QuotaHistoryResponse:
    if metric not in _DERIVABLE_HISTORY:
        # Provider usage has no historical row to derive from until a snapshot
        # store exists — surface "no history" rather than a fake series.
        return QuotaHistoryResponse(metric=metric, available=False, points=[])

    now = datetime.now(tz=UTC)
    start = (now - timedelta(days=_HISTORY_DAYS - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    created = User.created_at if metric == "signups" else Snippet.created_at
    source = User if metric == "signups" else Snippet
    day = func.date(created)
    counts: dict[str, int] = {}
    with contextlib.suppress(Exception):
        rows = (
            await session.execute(
                select(day, func.count()).select_from(source).where(created >= start).group_by(day)
            )
        ).all()
        counts = {str(d): int(c) for d, c in rows}

    points = []
    for offset in range(_HISTORY_DAYS):
        d = (start + timedelta(days=offset)).date()
        points.append(QuotaHistoryPoint(day=d, value=counts.get(str(d), 0)))
    return QuotaHistoryResponse(metric=metric, available=True, points=points)
