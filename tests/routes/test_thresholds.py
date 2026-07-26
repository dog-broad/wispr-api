from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.lib.tokens import hash_token
from app.models.accounts import Session as SessionRow
from app.models.accounts import User
from app.models.admin import AdminAlertPref, AdminAuditLog, AdminThreshold


async def _sign_in(db: AsyncSession, email: str, *, is_admin: bool = False) -> str:
    user = User(email=email, auth_credential_hash=b"argon2-placeholder", is_admin=is_admin)
    db.add(user)
    await db.flush()
    token = f"session-{email}"
    db.add(SessionRow(user_id=user.id, token_hash=hash_token(token), device_label="t"))
    await db.commit()
    return token


async def _admin(db_client: AsyncClient, db: AsyncSession) -> None:
    db_client.cookies.set("wispr_session", await _sign_in(db, "boss@example.com", is_admin=True))


async def test_thresholds_require_admin(db_client: AsyncClient, db_session: AsyncSession) -> None:
    assert (await db_client.get("/me/admin/thresholds")).status_code == 401
    db_client.cookies.set("wispr_session", await _sign_in(db_session, "plain@example.com"))
    assert (await db_client.get("/me/admin/thresholds")).status_code == 403
    assert (
        await db_client.put(
            "/me/admin/thresholds/r2.storage", json={"warn_pct": 50, "alert_pct": 80}
        )
    ).status_code == 403


async def test_set_threshold_upserts_and_audits(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    await _admin(db_client, db_session)
    assert (await db_client.get("/me/admin/thresholds")).json()["thresholds"] == []

    resp = await db_client.put(
        "/me/admin/thresholds/r2.storage", json={"warn_pct": 60, "alert_pct": 85}
    )
    assert resp.status_code == 200
    assert resp.json() == {"metric": "r2.storage", "warn_pct": 60, "alert_pct": 85}

    # Persisted + listed.
    listed = (await db_client.get("/me/admin/thresholds")).json()["thresholds"]
    assert listed == [{"metric": "r2.storage", "warn_pct": 60, "alert_pct": 85}]

    # Audited.
    audit = await db_session.scalar(
        select(AdminAuditLog).where(AdminAuditLog.action == "threshold.updated")
    )
    assert audit is not None and audit.target_id == "r2.storage"
    assert audit.payload == {"warn_pct": 60, "alert_pct": 85}

    # Update (upsert) replaces, no duplicate row.
    await db_client.put("/me/admin/thresholds/r2.storage", json={"warn_pct": 70, "alert_pct": 90})
    rows = list(await db_session.scalars(select(AdminThreshold)))
    assert len(rows) == 1 and rows[0].warn_pct == 70


async def test_set_threshold_unknown_metric_404(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    await _admin(db_client, db_session)
    # Turnstile has no cap → not thresholdable.
    resp = await db_client.put(
        "/me/admin/thresholds/turnstile.today", json={"warn_pct": 50, "alert_pct": 80}
    )
    assert resp.status_code == 404


async def test_set_threshold_rejects_warn_above_alert(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    await _admin(db_client, db_session)
    resp = await db_client.put(
        "/me/admin/thresholds/sentry.events", json={"warn_pct": 95, "alert_pct": 80}
    )
    assert resp.status_code == 422


async def test_alert_preference_upserts(db_client: AsyncClient, db_session: AsyncSession) -> None:
    await _admin(db_client, db_session)

    on = await db_client.post(
        "/me/admin/alerts/preferences", json={"metric": "sentry.events", "enabled": True}
    )
    assert on.status_code == 200 and on.json() == {"metric": "sentry.events", "enabled": True}

    off = await db_client.post(
        "/me/admin/alerts/preferences", json={"metric": "sentry.events", "enabled": False}
    )
    assert off.json()["enabled"] is False

    rows = list(await db_session.scalars(select(AdminAlertPref)))
    assert len(rows) == 1 and rows[0].enabled is False


async def test_alert_preference_unknown_metric_404(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    await _admin(db_client, db_session)
    resp = await db_client.post(
        "/me/admin/alerts/preferences", json={"metric": "nope", "enabled": True}
    )
    assert resp.status_code == 404
