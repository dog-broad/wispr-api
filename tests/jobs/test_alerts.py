from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.jobs.alerts import send_metric_alerts
from app.lib.email import EmailMessage
from app.models.accounts import User
from app.models.admin import AdminAlertPref
from app.schemas.dashboard import (
    DashboardResponse,
    MetricStatus,
    QuotaMetric,
)

_METRIC = "sentry.events"
_NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)


class _Capture:
    def __init__(self) -> None:
        self.sent: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> None:
        self.sent.append(message)


def _dashboard(status: MetricStatus) -> DashboardResponse:
    return DashboardResponse(
        generated_at=_NOW,
        status=status,
        quotas=[
            QuotaMetric(
                key=_METRIC,
                label="Sentry",
                status=status,
                value="4,900 / 5,000",
                used=4900,
                total=5000,
            )
        ],
        health=[],
        business=[],
        abuse=[],
        ops=[],
        recent_actions=[],
    )


async def _admin_with_pref(
    db: AsyncSession, *, enabled: bool, email: str = "a@example.com"
) -> User:
    user = User(email=email, auth_credential_hash=b"x", is_admin=True)
    db.add(user)
    await db.flush()
    db.add(AdminAlertPref(user_id=user.id, metric=_METRIC, enabled=enabled))
    await db.commit()
    return user


async def test_alert_emails_opted_in_admin(db_session: AsyncSession) -> None:
    user = await _admin_with_pref(db_session, enabled=True)
    capture = _Capture()

    sent = await send_metric_alerts(
        db_session, _dashboard(MetricStatus.alert), capture, "https://wispr.example", _NOW
    )

    assert sent == 1
    assert capture.sent[0].to == user.email
    assert "Sentry" in capture.sent[0].subject
    # Throttle stamp recorded.
    pref = await db_session.scalar(select(AdminAlertPref).where(AdminAlertPref.user_id == user.id))
    assert pref is not None and pref.last_emailed_at == _NOW


async def test_alert_throttled_within_the_hour(db_session: AsyncSession) -> None:
    await _admin_with_pref(db_session, enabled=True)
    capture = _Capture()
    dashboard = _dashboard(MetricStatus.alert)

    first = await send_metric_alerts(db_session, dashboard, capture, "https://x", _NOW)
    # 30 min later — still inside the 1 h window.
    second = await send_metric_alerts(
        db_session, dashboard, capture, "https://x", _NOW + timedelta(minutes=30)
    )
    # An hour on, it fires again.
    third = await send_metric_alerts(
        db_session, dashboard, capture, "https://x", _NOW + timedelta(hours=1, minutes=1)
    )

    assert (first, second, third) == (1, 0, 1)
    assert len(capture.sent) == 2


async def test_no_email_when_opted_out(db_session: AsyncSession) -> None:
    await _admin_with_pref(db_session, enabled=False)
    capture = _Capture()
    sent = await send_metric_alerts(
        db_session, _dashboard(MetricStatus.alert), capture, "https://x", _NOW
    )
    assert sent == 0 and capture.sent == []


async def test_no_email_when_metric_not_alerting(db_session: AsyncSession) -> None:
    await _admin_with_pref(db_session, enabled=True)
    capture = _Capture()
    # Same opted-in admin, but the metric is only at warn — no alert email.
    sent = await send_metric_alerts(
        db_session, _dashboard(MetricStatus.warn), capture, "https://x", _NOW
    )
    assert sent == 0 and capture.sent == []
