from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.lib import backup
from app.lib.credentials import hash_auth_credential
from app.lib.email import EmailMessage, get_email_transport
from app.lib.ids import new_snippet_id
from app.lib.storage import get_object_store
from app.lib.tokens import hash_token
from app.main import app
from app.models.accounts import Session as SessionRow
from app.models.accounts import User
from app.models.admin import AdminAuditLog
from app.models.snippets import ContentType, ShareMode, Snippet


async def _admin(db: AsyncSession, email: str = "boss@example.com") -> str:
    user = User(email=email, auth_credential_hash=b"argon2-placeholder", is_admin=True)
    db.add(user)
    await db.flush()
    token = f"session-{email}"
    db.add(SessionRow(user_id=user.id, token_hash=hash_token(token), device_label="t"))
    await db.commit()
    return token


# --- purge -------------------------------------------------------------------


async def test_purge_action_deletes_expired(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    db_client.cookies.set("wispr_session", await _admin(db_session))
    expired = Snippet(
        id=new_snippet_id(),
        share_mode=ShareMode.link,
        content_type=ContentType.text,
        encrypted_metadata=b"m",
        ciphertext_inline=b"x",
        size_bytes=1,
        max_reads=1,
        expires_at=datetime.now(tz=UTC) - timedelta(hours=1),
    )
    db_session.add(expired)
    await db_session.commit()

    resp = await db_client.post("/me/admin/actions/purge")
    assert resp.status_code == 200
    assert resp.json()["deleted"] >= 1

    db_session.expunge_all()
    assert await db_session.scalar(select(Snippet).where(Snippet.id == expired.id)) is None
    audit = await db_session.scalar(
        select(AdminAuditLog).where(AdminAuditLog.action == "purge.run")
    )
    assert audit is not None


async def test_purge_requires_admin(db_client: AsyncClient) -> None:
    assert (await db_client.post("/me/admin/actions/purge")).status_code == 401


# --- backup ------------------------------------------------------------------


class _FakeStore:
    async def put_object(self, key: str, data: bytes) -> None:
        self.last = (key, data)

    # Unused by the backup path, present to satisfy the store shape.
    def presign_put(self, key: str) -> str:
        return ""

    def presign_get(self, key: str) -> str:
        return ""


async def test_backup_no_store_503(db_client: AsyncClient, db_session: AsyncSession) -> None:
    db_client.cookies.set("wispr_session", await _admin(db_session))
    app.dependency_overrides[get_object_store] = lambda: None
    try:
        resp = await db_client.post("/me/admin/actions/backup")
    finally:
        app.dependency_overrides.pop(get_object_store, None)
    assert resp.status_code == 503


async def test_backup_uploads_and_audits(
    db_client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_client.cookies.set("wispr_session", await _admin(db_session))

    async def _fake_dump(database_url: str) -> bytes:
        return b"DUMP"

    monkeypatch.setattr(backup, "run_pg_dump", _fake_dump)
    app.dependency_overrides[get_object_store] = lambda: _FakeStore()
    try:
        resp = await db_client.post("/me/admin/actions/backup")
    finally:
        app.dependency_overrides.pop(get_object_store, None)

    assert resp.status_code == 200
    body = resp.json()
    assert body["key"].startswith("backups/") and body["size_bytes"] == 4
    audit = await db_session.scalar(
        select(AdminAuditLog).where(AdminAuditLog.action == "backup.run")
    )
    assert audit is not None and audit.target_id == body["key"]


# --- broadcast ---------------------------------------------------------------


class _CaptureTransport:
    def __init__(self) -> None:
        self.sent: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> None:
        self.sent.append(message)


async def test_broadcast_preview_does_not_send(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    db_client.cookies.set("wispr_session", await _admin(db_session))
    db_session.add(User(email="a@example.com", auth_credential_hash=b"x"))
    db_session.add(User(email="b@example.com", auth_credential_hash=b"x"))
    await db_session.commit()

    capture = _CaptureTransport()
    app.dependency_overrides[get_email_transport] = lambda: capture
    try:
        resp = await db_client.post(
            "/me/admin/actions/broadcast-email",
            json={"subject": "hi", "body": "all", "confirm": False},
        )
    finally:
        app.dependency_overrides.pop(get_email_transport, None)

    assert resp.status_code == 200
    data = resp.json()
    # 3 live members (the admin + two seeded), nothing sent on a preview.
    assert data["preview"] is True and data["recipient_count"] == 3 and data["sent"] == 0
    assert capture.sent == []


async def test_broadcast_confirm_sends_to_all(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    pepper = get_settings().server_pepper
    token = b"\x07" * 32
    admin = User(
        email="boss@example.com",
        auth_credential_hash=hash_auth_credential(token, pepper),
        is_admin=True,
    )
    db_session.add(admin)
    await db_session.flush()
    db_session.add(SessionRow(user_id=admin.id, token_hash=hash_token("s"), device_label="t"))
    db_session.add(User(email="a@example.com", auth_credential_hash=b"x"))
    await db_session.commit()
    db_client.cookies.set("wispr_session", "s")

    capture = _CaptureTransport()
    app.dependency_overrides[get_email_transport] = lambda: capture
    try:
        resp = await db_client.post(
            "/me/admin/actions/broadcast-email",
            json={
                "subject": "news",
                "body": "hello everyone",
                "confirm": True,
                "current_auth_token": base64.b64encode(token).decode(),
            },
        )
    finally:
        app.dependency_overrides.pop(get_email_transport, None)

    assert resp.status_code == 200
    assert resp.json()["sent"] == 2  # admin + one member
    assert {m.to for m in capture.sent} == {"boss@example.com", "a@example.com"}
    assert all(m.subject == "news" for m in capture.sent)
    audit = await db_session.scalar(
        select(AdminAuditLog).where(AdminAuditLog.action == "broadcast.sent")
    )
    assert audit is not None and audit.payload["recipient_count"] == 2


async def test_broadcast_wrong_passphrase_401(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    db_client.cookies.set("wispr_session", await _admin(db_session))
    capture = _CaptureTransport()
    app.dependency_overrides[get_email_transport] = lambda: capture
    try:
        resp = await db_client.post(
            "/me/admin/actions/broadcast-email",
            json={
                "subject": "x",
                "body": "y",
                "confirm": True,
                "current_auth_token": base64.b64encode(b"\x00" * 32).decode(),
            },
        )
    finally:
        app.dependency_overrides.pop(get_email_transport, None)
    assert resp.status_code == 401
    assert resp.json()["reason"] == "wrong_passphrase"
    assert capture.sent == []
