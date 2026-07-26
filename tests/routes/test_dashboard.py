from __future__ import annotations

from collections.abc import Iterator

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.lib.ids import new_snippet_id
from app.lib.tokens import hash_token
from app.main import app
from app.models.accounts import Session as SessionRow
from app.models.accounts import User
from app.models.reports import Report, ReportReasonCategory
from app.models.snippets import ContentType, ShareMode, Snippet

_NO_PROVIDER_KEYS = {
    "resend_api_key": None,
    "sentry_api_token": None,
    "sentry_org": None,
    "sentry_project": None,
    "cloudflare_api_token": None,
    "cloudflare_account_id": None,
    "cloudflare_zone_id": None,
}


@pytest.fixture(autouse=True)
def _no_provider_calls() -> Iterator[None]:
    """Null every provider key so the dashboard never makes a real external call
    during tests — the quota rows stay unknown (their intended local state)."""
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update=_NO_PROVIDER_KEYS
    )
    yield
    app.dependency_overrides.pop(get_settings, None)


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


async def _insert_link(db: AsyncSession) -> str:
    snippet = Snippet(
        id=new_snippet_id(),
        share_mode=ShareMode.link,
        content_type=ContentType.text,
        encrypted_metadata=b"m",
        ciphertext_inline=b"x",
        size_bytes=1,
        max_reads=1,
    )
    db.add(snippet)
    await db.commit()
    return snippet.id


def _statuses(section: list[dict[str, object]]) -> dict[str, str]:
    return {m["key"]: str(m["status"]) for m in section}


async def test_dashboard_requires_admin(db_client: AsyncClient, db_session: AsyncSession) -> None:
    assert (await db_client.get("/me/admin/dashboard")).status_code == 401
    db_client.cookies.set("wispr_session", await _sign_in(db_session, "plain@example.com"))
    assert (await db_client.get("/me/admin/dashboard")).status_code == 403


async def test_dashboard_internal_metrics_and_unknowns(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    await _insert_link(db_session)
    await _admin(db_client, db_session)

    resp = await db_client.get("/me/admin/dashboard")
    assert resp.status_code == 200
    body = resp.json()

    # Providers are all unknown (yellow "?"), never a false green.
    assert all(m["status"] == "unknown" for m in body["quotas"])

    health = _statuses(body["health"])
    assert health["api"] == "ok"
    assert health["postgres"] == "ok"  # pg_stat_activity read
    assert health["redis"] == "ok"  # INFO read
    assert health["ws_sync"] == "ok" and health["ws_pair"] == "ok"
    # Host reads not wired yet → unknown.
    assert health["cert_expiry"] == "unknown" and health["master_key"] == "unknown"

    business = {m["key"]: m for m in body["business"]}
    assert business["members"]["status"] == "ok" and int(business["members"]["value"]) >= 1
    assert "link 1" in business["snippets_today"]["value"]


async def test_dashboard_pending_report_warns(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    snippet_id = await _insert_link(db_session)
    db_session.add(
        Report(
            snippet_id=snippet_id, reporter_ip="a" * 64, reason_category=ReportReasonCategory.spam
        )
    )
    await db_session.commit()
    await _admin(db_client, db_session)

    body = (await db_client.get("/me/admin/dashboard")).json()
    abuse = _statuses(body["abuse"])
    assert abuse["reports_pending"] == "warn"
    # A warn metric lifts the overall banner off "ok".
    assert body["status"] == "warn"


async def test_dashboard_reflects_maintenance(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    await _admin(db_client, db_session)
    # Toggle first, then read: the dashboard hasn't been cached in this test yet.
    await db_client.post(
        "/me/admin/kill-switch/maintenance_mode", json={"enabled": True, "message": "brb"}
    )
    body = (await db_client.get("/me/admin/dashboard")).json()
    ops = {m["key"]: m for m in body["ops"]}
    assert ops["switch_maintenance_mode"]["status"] == "warn"
    assert ops["switch_maintenance_mode"]["value"] == "on"


async def test_dashboard_is_cached(db_client: AsyncClient, db_session: AsyncSession) -> None:
    await _admin(db_client, db_session)
    first = (await db_client.get("/me/admin/dashboard")).json()
    # A change after the first (cached) read isn't reflected until the 30 s TTL.
    await _insert_link(db_session)
    second = (await db_client.get("/me/admin/dashboard")).json()
    assert first["generated_at"] == second["generated_at"]


async def test_quota_history_snippets_derived(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    await _insert_link(db_session)
    await _admin(db_client, db_session)

    resp = await db_client.get("/me/admin/quotas/snippets/history")
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is True
    assert len(body["points"]) == 7
    assert sum(p["value"] for p in body["points"]) >= 1


async def test_quota_history_provider_unavailable(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    await _admin(db_client, db_session)
    body = (await db_client.get("/me/admin/quotas/resend.monthly/history")).json()
    assert body["available"] is False and body["points"] == []


async def test_history_requires_admin(db_client: AsyncClient) -> None:
    assert (await db_client.get("/me/admin/quotas/snippets/history")).status_code == 401
