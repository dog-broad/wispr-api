from __future__ import annotations

import base64
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.lib.tokens import hash_token
from app.models.accounts import Session as SessionRow
from app.models.accounts import User
from app.models.snippets import ShareMode, Snippet


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


async def _sign_in(db: AsyncSession, email: str = "syncuser@example.com") -> str:
    user = User(email=email, auth_credential_hash=b"argon2-placeholder")
    db.add(user)
    await db.flush()
    token = f"test-session-{email}"
    db.add(SessionRow(user_id=user.id, token_hash=hash_token(token), device_label="test"))
    await db.commit()
    return token


def _sync_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "share_mode": "sync",
        "content_type": "text",
        "ciphertext": _b64(b"encrypted-clip"),
        "wrapped_dek": _b64(b"\x11" * 48),
        "wrapped_dek_iv": _b64(b"\x22" * 12),
        "encrypted_metadata": _b64(b"meta"),
    }
    body.update(overrides)
    return body


async def test_sync_create_requires_auth(db_client: AsyncClient) -> None:
    resp = await db_client.post("/snippets", json=_sync_body())
    assert resp.status_code == 401


async def test_sync_create_stores_wrapped_dek(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    db_client.cookies.set("wispr_session", await _sign_in(db_session))

    resp = await db_client.post("/snippets", json=_sync_body())

    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data and "pin" not in data
    db_session.expunge_all()
    snip = await db_session.scalar(select(Snippet).where(Snippet.id == data["id"]))
    assert snip is not None
    assert snip.share_mode is ShareMode.sync
    assert snip.wrapped_dek == b"\x11" * 48
    assert snip.wrapped_dek_iv == b"\x22" * 12
    assert snip.owner_user_id is not None
    # ZK invariants: no PIN, no key_version, no TTL/max_reads.
    assert snip.pin is None and snip.key_version is None
    assert snip.expires_at is None and snip.max_reads is None
