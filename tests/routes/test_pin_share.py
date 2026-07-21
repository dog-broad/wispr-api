from __future__ import annotations

import base64
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.lib.keyvault import get_key_vault
from app.lib.tokens import hash_token
from app.models.accounts import Session as SessionRow
from app.models.accounts import User
from app.models.snippets import ShareMode, Snippet


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


async def _sign_in(db: AsyncSession, email: str = "member@example.com") -> str:
    """Seed a member + session and return the raw cookie token."""
    user = User(email=email, auth_credential_hash=b"argon2-placeholder")
    db.add(user)
    await db.flush()
    token = "test-session-token"
    db.add(SessionRow(user_id=user.id, token_hash=hash_token(token), device_label="test"))
    await db.commit()
    return token


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


async def test_pin_share_requires_auth(db_client: AsyncClient) -> None:
    resp = await db_client.post("/snippets", json=_pin_body())
    assert resp.status_code == 401


async def test_pin_share_created_and_key_wrapped(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _sign_in(db_session)
    db_client.cookies.set("wispr_session", token)

    resp = await db_client.post("/snippets", json=_pin_body())

    assert resp.status_code == 201
    data = resp.json()
    assert len(data["pin"]) == 4 and data["pin"].isdigit()
    assert "content_key" not in data  # the raw key is never echoed back

    db_session.expunge_all()
    snip = await db_session.scalar(select(Snippet).where(Snippet.id == data["id"]))
    assert snip is not None
    assert snip.share_mode is ShareMode.pin_share
    assert snip.pin == data["pin"]
    assert snip.owner_user_id is not None
    assert snip.max_reads == 5
    assert snip.key_version == 1
    # The stored wrapped key unwraps back to the client's raw content key.
    assert snip.encrypted_content_key is not None and snip.content_key_iv is not None
    unwrapped = get_key_vault().unwrap(
        snip.encrypted_content_key, snip.content_key_iv, snip.key_version
    )
    assert unwrapped == b"\x01" * 32


async def test_pin_share_unlimited_reads_allowed(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _sign_in(db_session)
    db_client.cookies.set("wispr_session", token)
    resp = await db_client.post("/snippets", json=_pin_body(max_reads=None))
    assert resp.status_code == 201
    db_session.expunge_all()
    snip = await db_session.scalar(select(Snippet).where(Snippet.id == resp.json()["id"]))
    assert snip is not None and snip.max_reads is None


async def test_link_create_still_anonymous(db_client: AsyncClient) -> None:
    # No auth cookie — link creation must still work and carry no PIN.
    resp = await db_client.post(
        "/snippets",
        json={
            "share_mode": "link",
            "content_type": "text",
            "ciphertext": _b64(b"blob"),
            "encrypted_metadata": _b64(b"meta"),
            "ttl_seconds": 3600,
        },
    )
    assert resp.status_code == 201
    assert "pin" not in resp.json()
