from __future__ import annotations

import asyncio
import base64
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.lib.sync_bus import SnippetCreatedEvent, SnippetDeletedEvent
from app.lib.sync_bus import bus as sync_bus
from app.lib.tokens import hash_token
from app.models.accounts import Session as SessionRow
from app.models.accounts import User
from app.models.snippets import ShareMode, Snippet


async def _user_id(db: AsyncSession, email: str = "syncuser@example.com") -> str:
    user = await db.scalar(select(User).where(User.email == email))
    assert user is not None
    return str(user.id)


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


async def _create(client: AsyncClient, **overrides: Any) -> str:
    resp = await client.post("/snippets", json=_sync_body(**overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def test_list_requires_auth(db_client: AsyncClient) -> None:
    assert (await db_client.get("/me/snippets")).status_code == 401


async def test_list_returns_own_sync_items_only(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    db_client.cookies.set("wispr_session", await _sign_in(db_session))
    id_a = await _create(db_client)
    id_b = await _create(db_client)
    # An anonymous link must not appear in the Sync feed.
    await db_client.post(
        "/snippets",
        json={
            "share_mode": "link",
            "content_type": "text",
            "ciphertext": _b64(b"x"),
            "encrypted_metadata": _b64(b"m"),
            "ttl_seconds": 600,
        },
    )

    resp = await db_client.get("/me/snippets")
    assert resp.status_code == 200
    body = resp.json()
    ids = {item["id"] for item in body["items"]}
    assert ids == {id_a, id_b}
    assert body["next_before"] is None
    # Each item carries the wrapped DEK for client-side unwrap.
    assert all(item["wrapped_dek"] for item in body["items"])


async def test_list_excludes_other_users(db_client: AsyncClient, db_session: AsyncSession) -> None:
    db_client.cookies.set("wispr_session", await _sign_in(db_session))
    await _create(db_client)
    db_client.cookies.set("wispr_session", await _sign_in(db_session, email="other@example.com"))
    resp = await db_client.get("/me/snippets")
    assert resp.status_code == 200
    assert resp.json()["items"] == []


async def test_burn_removes_from_feed(db_client: AsyncClient, db_session: AsyncSession) -> None:
    db_client.cookies.set("wispr_session", await _sign_in(db_session))
    snippet_id = await _create(db_client)
    burn = await db_client.post(f"/me/snippets/{snippet_id}/burn")
    assert burn.status_code == 204
    resp = await db_client.get("/me/snippets")
    assert resp.json()["items"] == []


async def test_create_publishes_created_event(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    db_client.cookies.set("wispr_session", await _sign_in(db_session))
    uid = await _user_id(db_session)
    queue = await sync_bus.subscribe(uid)
    try:
        snippet_id = await _create(db_client)
        event = await asyncio.wait_for(queue.get(), 2.0)
        assert isinstance(event, SnippetCreatedEvent)
        assert event.item.id == snippet_id
    finally:
        await sync_bus.unsubscribe(uid, queue)


async def test_burn_publishes_deleted_event(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    db_client.cookies.set("wispr_session", await _sign_in(db_session))
    uid = await _user_id(db_session)
    snippet_id = await _create(db_client)
    queue = await sync_bus.subscribe(uid)
    try:
        await db_client.post(f"/me/snippets/{snippet_id}/burn")
        event = await asyncio.wait_for(queue.get(), 2.0)
        assert isinstance(event, SnippetDeletedEvent)
        assert event.snippet_id == snippet_id
    finally:
        await sync_bus.unsubscribe(uid, queue)
