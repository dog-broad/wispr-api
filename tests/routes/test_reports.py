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
from app.models.reports import Report, ReportReasonCategory, ReportResolution
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


# --- admin review + takedown -------------------------------------------------


async def _sign_in_admin(db: AsyncSession, email: str = "admin@example.com") -> tuple[User, str]:
    user = User(email=email, auth_credential_hash=b"argon2-placeholder", is_admin=True)
    db.add(user)
    await db.flush()
    token = f"admin-session-{email}"
    db.add(SessionRow(user_id=user.id, token_hash=hash_token(token), device_label="admin"))
    await db.commit()
    return user, token


async def _insert_report(
    db: AsyncSession,
    snippet_id: str | None,
    *,
    category: ReportReasonCategory = ReportReasonCategory.spam,
    text: str | None = None,
    reporter_user_id: object = None,
) -> Report:
    report = Report(
        snippet_id=snippet_id,
        reporter_ip="a" * 64,
        reporter_user_id=reporter_user_id,
        reason_category=category,
        reason_text=text,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report


async def _create_pin_full(client: AsyncClient, db: AsyncSession) -> tuple[str, str]:
    """Create a pin_share and return (id, pin)."""
    _, token = await _sign_in(db)
    client.cookies.set("wispr_session", token)
    resp = await client.post("/snippets", json=_pin_body())
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return str(body["id"]), str(body["pin"])


async def test_admin_reports_requires_admin(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    assert (await db_client.get("/me/admin/reports")).status_code == 401
    _, token = await _sign_in(db_session, email="plain@example.com")
    db_client.cookies.set("wispr_session", token)
    assert (await db_client.get("/me/admin/reports")).status_code == 403


async def test_admin_lists_pending_reports_oldest_first(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    snippet_id = await _create_pin_share(db_client, db_session)
    first = await _insert_report(db_session, snippet_id, category=ReportReasonCategory.spam)
    await _insert_report(db_session, snippet_id, category=ReportReasonCategory.malware)
    _, admin_token = await _sign_in_admin(db_session)
    db_client.cookies.set("wispr_session", admin_token)

    resp = await db_client.get("/me/admin/reports")

    assert resp.status_code == 200
    reports = resp.json()["reports"]
    assert len(reports) == 2
    assert reports[0]["id"] == str(first.id)  # oldest first
    assert reports[0]["snippet_present"] is True
    assert reports[0]["snippet_content_type"] == "text"
    assert reports[0]["snippet_taken_down"] is False
    assert reports[0]["from_member"] is False


async def test_admin_resolve_takedown_sets_taken_down_and_renders_gone(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    snippet_id, pin = await _create_pin_full(db_client, db_session)
    report = await _insert_report(db_session, snippet_id, category=ReportReasonCategory.illegal)
    _, admin_token = await _sign_in_admin(db_session)
    db_client.cookies.set("wispr_session", admin_token)

    resolve = await db_client.post(
        f"/me/admin/reports/{report.id}/resolve",
        json={"resolution": "taken_down", "notes": "confirmed illegal"},
    )

    assert resolve.status_code == 200
    assert resolve.json()["snippet_taken_down"] is True

    db_session.expunge_all()
    snip = await db_session.scalar(select(Snippet).where(Snippet.id == snippet_id))
    assert snip is not None
    assert snip.taken_down_at is not None
    assert snip.taken_down_reason == "confirmed illegal"
    saved = await db_session.scalar(select(Report).where(Report.id == report.id))
    assert saved is not None
    assert saved.resolved_at is not None
    assert saved.resolution is ReportResolution.taken_down
    assert saved.resolution_notes == "confirmed illegal"

    # Receive now renders outcome #6: by-pin returns 410 gone taken_down.
    db_client.cookies.clear()
    gone = await db_client.post("/snippets/by-pin", json={"pin": pin})
    assert gone.status_code == 410
    assert gone.json()["reason"] == "taken_down"


async def test_admin_resolve_dismiss_leaves_snippet_live(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    snippet_id, pin = await _create_pin_full(db_client, db_session)
    report = await _insert_report(db_session, snippet_id)
    _, admin_token = await _sign_in_admin(db_session)
    db_client.cookies.set("wispr_session", admin_token)

    resolve = await db_client.post(
        f"/me/admin/reports/{report.id}/resolve", json={"resolution": "dismissed"}
    )

    assert resolve.status_code == 200
    assert resolve.json()["snippet_taken_down"] is False

    db_session.expunge_all()
    snip = await db_session.scalar(select(Snippet).where(Snippet.id == snippet_id))
    assert snip is not None and snip.taken_down_at is None

    # The share still resolves normally.
    db_client.cookies.clear()
    ok = await db_client.post("/snippets/by-pin", json={"pin": pin})
    assert ok.status_code == 200 and ok.json()["mode"] == "pin_share"


async def test_admin_resolve_is_single_use(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    snippet_id = await _create_pin_share(db_client, db_session)
    report = await _insert_report(db_session, snippet_id)
    _, admin_token = await _sign_in_admin(db_session)
    db_client.cookies.set("wispr_session", admin_token)

    body = {"resolution": "dismissed"}
    assert (
        await db_client.post(f"/me/admin/reports/{report.id}/resolve", json=body)
    ).status_code == 200
    again = await db_client.post(f"/me/admin/reports/{report.id}/resolve", json=body)
    assert again.status_code == 409


async def test_admin_resolve_unknown_report_404(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    _, admin_token = await _sign_in_admin(db_session)
    db_client.cookies.set("wispr_session", admin_token)
    missing = "00000000-0000-0000-0000-000000000000"
    resp = await db_client.post(
        f"/me/admin/reports/{missing}/resolve", json={"resolution": "dismissed"}
    )
    assert resp.status_code == 404
