from __future__ import annotations

import base64
from typing import Any

import httpx
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.lib.ids import new_snippet_id
from app.lib.tokens import hash_token
from app.main import app
from app.models.accounts import Session as SessionRow
from app.models.accounts import User
from app.models.reports import Report, ReportReasonCategory
from app.models.snippets import ContentType, ShareMode, Snippet


def _disable_turnstile() -> None:
    """Null the Turnstile secret for the app so a present token bypasses the
    challenge. The test .env may carry a real secret, which would otherwise
    round-trip a bogus token to Cloudflare and fail closed."""
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={"turnstile_secret_key": None}
    )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


async def _sign_in(db: AsyncSession, email: str = "reporter@example.com") -> tuple[User, str]:
    user = User(email=email, auth_credential_hash=b"argon2-placeholder")
    db.add(user)
    await db.flush()
    token = f"test-session-{email}"
    db.add(SessionRow(user_id=user.id, token_hash=hash_token(token), device_label="test"))
    await db.commit()
    return user, token


def _pin_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "share_mode": "pin_share",
        "content_type": "text",
        "ciphertext": _b64(b"the-encrypted-blob"),
        "content_key": _b64(b"\x01" * 32),
        "encrypted_metadata": _b64(b"meta"),
        "ttl_seconds": 3600,
        "max_reads": 5,
    }
    body.update(overrides)
    return body


async def _create_pin_share(client: AsyncClient, db: AsyncSession, **headers: str) -> str:
    """Sign in and create a pin_share via the API; return its snippet id."""
    _, token = await _sign_in(db)
    client.cookies.set("wispr_session", token)
    resp = await client.post("/snippets", json=_pin_body(), headers=headers or None)
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _insert_link(db: AsyncSession) -> str:
    """Insert an anonymous link snippet directly and return its id."""
    snippet = Snippet(
        id=new_snippet_id(),
        share_mode=ShareMode.link,
        content_type=ContentType.text,
        encrypted_metadata=b"meta",
        ciphertext_inline=b"blob",
        size_bytes=4,
        max_reads=1,
    )
    db.add(snippet)
    await db.commit()
    return snippet.id


async def test_report_unknown_snippet_is_rejected(db_client: AsyncClient) -> None:
    resp = await db_client.post(
        "/reports", json={"snippet_id": "nosuchid1234", "reason_category": "spam"}
    )
    assert resp.status_code == 404
    assert resp.json()["reason"] == "unknown_snippet"


async def test_report_rejects_non_pin_share(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Only PIN shares are operator-reviewable; a report against a link 404s."""
    link_id = await _insert_link(db_session)
    resp = await db_client.post(
        "/reports", json={"snippet_id": link_id, "reason_category": "malware"}
    )
    assert resp.status_code == 404
    assert resp.json()["reason"] == "unknown_snippet"


async def test_report_anonymous_creates_row(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    snippet_id = await _create_pin_share(db_client, db_session)
    db_client.cookies.clear()  # report anonymously

    resp = await db_client.post(
        "/reports",
        json={
            "snippet_id": snippet_id,
            "reason_category": "harassment",
            "reason_text": "abusive content",
        },
    )

    assert resp.status_code == 201
    assert resp.json()["ok"] is True

    row = await db_session.scalar(select(Report).where(Report.snippet_id == snippet_id))
    assert row is not None
    assert row.reporter_user_id is None
    assert row.reason_category is ReportReasonCategory.harassment
    assert row.reason_text == "abusive content"
    # The IP is stored hashed (SHA-256 hex), never the raw address.
    assert len(row.reporter_ip) == 64
    assert all(c in "0123456789abcdef" for c in row.reporter_ip)


async def test_report_signed_in_records_reporter(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _sign_in(db_session, email="member@example.com")
    # A pin_share owned by someone else, reported by the signed-in member.
    other_id = await _create_pin_share(db_client, db_session)
    db_client.cookies.set("wispr_session", token)

    resp = await db_client.post(
        "/reports", json={"snippet_id": other_id, "reason_category": "illegal"}
    )

    assert resp.status_code == 201
    row = await db_session.scalar(select(Report).where(Report.snippet_id == other_id))
    assert row is not None
    reporter = await db_session.scalar(select(User).where(User.email == "member@example.com"))
    assert reporter is not None
    assert row.reporter_user_id == reporter.id


async def test_report_turnstile_required_above_three(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    snippet_id = await _create_pin_share(db_client, db_session)
    db_client.cookies.clear()
    body = {"snippet_id": snippet_id, "reason_category": "spam"}
    _disable_turnstile()
    try:
        # First three from this IP file freely.
        for _ in range(3):
            assert (await db_client.post("/reports", json=body)).status_code == 201

        # The fourth now demands a Turnstile token.
        gated = await db_client.post("/reports", json=body)
        assert gated.status_code == 403
        assert gated.json()["reason"] == "turnstile_required"

        # With a token it goes through (secret nulled, so a token bypasses).
        ok = await db_client.post("/reports", json={**body, "turnstile_token": "tok"})
        assert ok.status_code == 201
    finally:
        app.dependency_overrides.pop(get_settings, None)


async def test_report_hard_limited_five_per_hour(
    rate_limit_client: AsyncClient, db_session: AsyncSession
) -> None:
    """5/hr/IP hard ceiling. The sixth report in an hour is a 429 regardless of
    Turnstile (reports past the third carry a token so the challenge passes)."""
    app.state.http_client = httpx.AsyncClient()
    _disable_turnstile()
    ip = {"CF-Connecting-IP": "203.0.113.90"}
    try:
        snippet_id = await _create_pin_share(rate_limit_client, db_session, **ip)
        rate_limit_client.cookies.clear()
        body = {"snippet_id": snippet_id, "reason_category": "spam", "turnstile_token": "tok"}

        for _ in range(5):
            resp = await rate_limit_client.post("/reports", json=body, headers=ip)
            assert resp.status_code == 201, resp.text

        overflow = await rate_limit_client.post("/reports", json=body, headers=ip)
        assert overflow.status_code == 429
        assert "retry-after" in {k.lower() for k in overflow.headers}
    finally:
        app.dependency_overrides.pop(get_settings, None)
        await app.state.http_client.aclose()
