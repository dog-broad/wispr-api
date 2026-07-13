from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.lib.auth import SESSION_COOKIE_NAME
from app.lib.email import EmailMessage, get_email_transport
from app.lib.ratelimit import magic_link_ip_limit
from app.main import app
from app.models.accounts import Invite, MagicLinkToken, Session, User


class _CapturingTransport:
    """Test email transport that records messages instead of sending."""

    def __init__(self) -> None:
        self.sent: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> None:
        self.sent.append(message)


async def _noop() -> None:
    return None


@pytest.fixture
async def auth_client(
    db_session: AsyncSession, redis_client: Redis
) -> AsyncIterator[tuple[AsyncClient, _CapturingTransport]]:
    """ASGI client wired for the auth routes: real DB + redis, a capturing
    email transport, the per-IP magic-link limit no-op'd (the per-email limit
    stays real, backed by the flushed test redis), and an http client for the
    Turnstile dependency (bypassed in tests since no secret is configured)."""
    _ = db_session
    app.state.redis = redis_client
    app.state.http_client = httpx.AsyncClient()
    capture = _CapturingTransport()
    app.dependency_overrides[get_email_transport] = lambda: capture
    app.dependency_overrides[magic_link_ip_limit] = _noop
    # Null the Turnstile secret so the challenge is bypassed regardless of what
    # the developer's local .env carries — these tests exercise the magic-link
    # logic, not Turnstile.
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={"turnstile_secret_key": None}
    )
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac, capture
    finally:
        await app.state.http_client.aclose()
        app.dependency_overrides.pop(get_email_transport, None)
        app.dependency_overrides.pop(magic_link_ip_limit, None)
        app.dependency_overrides.pop(get_settings, None)


def _token_from_link(message: EmailMessage) -> str:
    return message.text_body.split("token=", 1)[1].split()[0]


async def _seed_user(db: AsyncSession, email: str, *, is_admin: bool = False) -> User:
    user = User(email=email, is_admin=is_admin)
    db.add(user)
    await db.commit()
    return user


async def test_request_for_existing_user_sends_signin_link(
    auth_client: tuple[AsyncClient, _CapturingTransport], db_session: AsyncSession
) -> None:
    await _seed_user(db_session, "alice@example.com")
    client, emails = auth_client

    resp = await client.post("/auth/request-magic-link", json={"email": "Alice@Example.com"})

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert len(emails.sent) == 1
    assert "token=" in emails.sent[0].text_body
    token_row = await db_session.scalar(select(MagicLinkToken))
    assert token_row is not None
    assert token_row.email == "alice@example.com"  # normalized


async def test_request_for_unknown_email_is_silent(
    auth_client: tuple[AsyncClient, _CapturingTransport], db_session: AsyncSession
) -> None:
    client, emails = auth_client
    resp = await client.post("/auth/request-magic-link", json={"email": "nobody@example.com"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert emails.sent == []
    assert await db_session.scalar(select(func.count()).select_from(MagicLinkToken)) == 0


async def test_signin_verify_sets_cookie_and_session(
    auth_client: tuple[AsyncClient, _CapturingTransport], db_session: AsyncSession
) -> None:
    await _seed_user(db_session, "alice@example.com")
    client, emails = auth_client
    await client.post("/auth/request-magic-link", json={"email": "alice@example.com"})
    token = _token_from_link(emails.sent[0])

    resp = await client.get("/auth/verify", params={"token": token})

    assert resp.status_code == 200
    assert resp.json() == {"email": "alice@example.com", "needs_passphrase_setup": True}
    assert SESSION_COOKIE_NAME in resp.cookies
    assert await db_session.scalar(select(func.count()).select_from(Session)) == 1
    consumed = await db_session.scalar(select(MagicLinkToken))
    assert consumed is not None and consumed.consumed_at is not None


async def test_verify_is_single_use(
    auth_client: tuple[AsyncClient, _CapturingTransport], db_session: AsyncSession
) -> None:
    await _seed_user(db_session, "alice@example.com")
    client, emails = auth_client
    await client.post("/auth/request-magic-link", json={"email": "alice@example.com"})
    token = _token_from_link(emails.sent[0])

    first = await client.get("/auth/verify", params={"token": token})
    second = await client.get("/auth/verify", params={"token": token})

    assert first.status_code == 200
    assert second.status_code == 400
    assert second.json() == {"reason": "invalid_or_expired"}


async def test_verify_rejects_unknown_token(
    auth_client: tuple[AsyncClient, _CapturingTransport],
) -> None:
    client, _ = auth_client
    resp = await client.get("/auth/verify", params={"token": "not-a-real-token"})
    assert resp.status_code == 400
    assert resp.json() == {"reason": "invalid_or_expired"}


async def test_signup_with_invite_creates_account_and_consumes_invite(
    auth_client: tuple[AsyncClient, _CapturingTransport], db_session: AsyncSession
) -> None:
    admin = await _seed_user(db_session, "admin@example.com", is_admin=True)
    invite = Invite(code="ABCD1234", created_by=admin.id)
    db_session.add(invite)
    await db_session.commit()
    admin_id = admin.id
    invite_id = invite.id
    client, emails = auth_client

    await client.post(
        "/auth/request-magic-link",
        json={"email": "new@example.com", "invite_code": "ABCD1234"},
    )
    assert len(emails.sent) == 1
    token = _token_from_link(emails.sent[0])

    resp = await client.get("/auth/verify", params={"token": token})

    assert resp.status_code == 200
    assert resp.json()["email"] == "new@example.com"
    # Drop the identity-map snapshot so the re-query reflects the app's commit.
    db_session.expunge_all()
    new_user = await db_session.scalar(select(User).where(User.email == "new@example.com"))
    assert new_user is not None
    assert new_user.invited_by == admin_id
    refreshed = await db_session.scalar(select(Invite).where(Invite.id == invite_id))
    assert refreshed is not None
    assert refreshed.used_by == new_user.id
    assert refreshed.used_at is not None


async def test_request_without_invite_for_new_email_is_silent(
    auth_client: tuple[AsyncClient, _CapturingTransport], db_session: AsyncSession
) -> None:
    client, emails = auth_client
    resp = await client.post(
        "/auth/request-magic-link",
        json={"email": "new@example.com", "invite_code": "NOPE0000"},
    )
    assert resp.status_code == 200
    assert emails.sent == []
    assert await db_session.scalar(select(func.count()).select_from(User)) == 0


async def test_email_rate_limit_goes_silent_after_three(
    auth_client: tuple[AsyncClient, _CapturingTransport], db_session: AsyncSession
) -> None:
    await _seed_user(db_session, "alice@example.com")
    client, emails = auth_client
    for _ in range(4):
        resp = await client.post("/auth/request-magic-link", json={"email": "alice@example.com"})
        assert resp.status_code == 200
    # 3/hr/email ceiling: the fourth request is a silent success, no email.
    assert len(emails.sent) == 3


async def test_logout_deletes_session_and_clears_cookie(
    auth_client: tuple[AsyncClient, _CapturingTransport], db_session: AsyncSession
) -> None:
    await _seed_user(db_session, "alice@example.com")
    client, emails = auth_client
    await client.post("/auth/request-magic-link", json={"email": "alice@example.com"})
    token = _token_from_link(emails.sent[0])
    await client.get("/auth/verify", params={"token": token})
    assert await db_session.scalar(select(func.count()).select_from(Session)) == 1

    resp = await client.post("/auth/logout")

    assert resp.status_code == 204
    assert await db_session.scalar(select(func.count()).select_from(Session)) == 0
