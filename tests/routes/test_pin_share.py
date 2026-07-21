from __future__ import annotations

import base64
import json
from typing import Any

from httpx import AsyncClient
from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.lib.keyvault import get_key_vault
from app.lib.tokens import hash_token
from app.models.accounts import Session as SessionRow
from app.models.accounts import User
from app.models.snippets import ShareMode, Snippet


async def _create_pin(client: AsyncClient, db: AsyncSession, **overrides: Any) -> tuple[str, str]:
    """Sign in (if not already) and create a pin_share; returns (id, pin)."""
    if "wispr_session" not in client.cookies:
        client.cookies.set("wispr_session", await _sign_in(db))
    resp = await client.post("/snippets", json=_pin_body(**overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()["id"], resp.json()["pin"]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


async def _sign_in(db: AsyncSession, email: str = "member@example.com") -> str:
    """Seed a member + session and return the raw cookie token."""
    user = User(email=email, auth_credential_hash=b"argon2-placeholder")
    db.add(user)
    await db.flush()
    token = f"test-session-{email}"  # distinct per user so token_hash stays unique
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


async def test_by_pin_resolves_burns_and_returns_key(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    _id, pin = await _create_pin(db_client, db_session, max_reads=1)

    resp = await db_client.post("/snippets/by-pin", json={"pin": pin})

    assert resp.status_code == 200
    data = resp.json()
    assert data["mode"] == "pin_share"
    assert base64.b64decode(data["content_key"]) == b"\x01" * 32
    assert base64.b64decode(data["ciphertext"]) == b"the-encrypted-blob"
    assert data["read_count"] == 1

    # Burned after the single read.
    again = await db_client.post("/snippets/by-pin", json={"pin": pin})
    assert again.status_code == 410
    assert again.json()["reason"] == "burned"


async def test_by_pin_unknown_returns_404(db_client: AsyncClient) -> None:
    resp = await db_client.post("/snippets/by-pin", json={"pin": "0000"})
    assert resp.status_code == 404
    assert resp.json()["reason"] == "unknown_pin"


async def test_by_pin_password_gate(db_client: AsyncClient, db_session: AsyncSession) -> None:
    pw_hash = base64.b64encode(b"\xaa" * 32).decode()
    pw_salt = base64.b64encode(b"\xbb" * 16).decode()
    _id, pin = await _create_pin(
        db_client, db_session, password_hash=pw_hash, password_salt=pw_salt, max_reads=5
    )

    # No password -> gated with the salt.
    gated = await db_client.post("/snippets/by-pin", json={"pin": pin})
    assert gated.status_code == 401
    assert gated.json()["status"] == "password_required"
    assert base64.b64decode(gated.json()["password_salt"]) == b"\xbb" * 16

    # Wrong password -> password_incorrect.
    wrong = await db_client.post(
        "/snippets/by-pin",
        json={"pin": pin, "password_hash": base64.b64encode(b"\x00" * 32).decode()},
    )
    assert wrong.status_code == 401
    assert wrong.json()["reason"] == "password_incorrect"

    # Correct password -> content.
    ok = await db_client.post("/snippets/by-pin", json={"pin": pin, "password_hash": pw_hash})
    assert ok.status_code == 200
    assert ok.json()["mode"] == "pin_share"


async def test_by_pin_signals_pair_for_live_pairing(
    db_client: AsyncClient, redis_client: Redis
) -> None:
    await redis_client.set(
        "pair:pin:4321",
        json.dumps({"sender_token": "t", "sender_ip": "1.2.3.4", "created_at": 9_999_999_999}),
    )
    resp = await db_client.post("/snippets/by-pin", json={"pin": "4321"})
    assert resp.status_code == 200
    assert resp.json()["mode"] == "pair"


async def test_by_pin_turnstile_required_after_three_failures(
    db_client: AsyncClient,
) -> None:
    for _ in range(3):
        r = await db_client.post("/snippets/by-pin", json={"pin": "0000"})
        assert r.status_code == 404
    # Fourth attempt from this IP now needs a Turnstile token.
    gated = await db_client.post("/snippets/by-pin", json={"pin": "0000"})
    assert gated.status_code == 403
    assert gated.json()["reason"] == "turnstile_required"


async def test_rotate_pin_changes_pin_keeps_content(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    snippet_id, old_pin = await _create_pin(db_client, db_session, max_reads=5)

    resp = await db_client.post(f"/me/snippets/{snippet_id}/rotate-pin")

    assert resp.status_code == 200
    new_pin = resp.json()["pin"]
    assert new_pin != old_pin and len(new_pin) == 4
    # Old PIN stops resolving; the new one returns the same content.
    assert (await db_client.post("/snippets/by-pin", json={"pin": old_pin})).status_code == 404
    ok = await db_client.post("/snippets/by-pin", json={"pin": new_pin})
    assert ok.status_code == 200 and ok.json()["mode"] == "pin_share"


async def test_rotate_pin_requires_auth(db_client: AsyncClient, db_session: AsyncSession) -> None:
    snippet_id, _pin = await _create_pin(db_client, db_session)
    db_client.cookies.clear()
    resp = await db_client.post(f"/me/snippets/{snippet_id}/rotate-pin")
    assert resp.status_code == 401


async def test_rotate_pin_non_owner_is_404(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    snippet_id, _pin = await _create_pin(db_client, db_session)
    db_client.cookies.set("wispr_session", await _sign_in(db_session, email="other@example.com"))
    resp = await db_client.post(f"/me/snippets/{snippet_id}/rotate-pin")
    assert resp.status_code == 404


async def _set_failed_attempts(db: AsyncSession, snippet_id: str, n: int) -> None:
    await db.execute(update(Snippet).where(Snippet.id == snippet_id).values(pin_failed_attempts=n))
    await db.commit()


async def test_by_pin_disabled_at_attempt_cap(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    snippet_id, pin = await _create_pin(db_client, db_session)
    await _set_failed_attempts(db_session, snippet_id, 50)
    resp = await db_client.post("/snippets/by-pin", json={"pin": pin})
    assert resp.status_code == 410
    assert resp.json()["reason"] == "disabled"


async def test_wrong_password_trips_disable_at_cap(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    pw_hash = _b64(b"\xaa" * 32)
    pw_salt = _b64(b"\xbb" * 16)
    snippet_id, pin = await _create_pin(
        db_client, db_session, password_hash=pw_hash, password_salt=pw_salt, max_reads=5
    )
    await _set_failed_attempts(db_session, snippet_id, 49)

    resp = await db_client.post(
        "/snippets/by-pin",
        json={"pin": pin, "password_hash": _b64(b"\x00" * 32)},
    )
    assert resp.status_code == 410
    assert resp.json()["reason"] == "disabled"

    db_session.expunge_all()
    snip = await db_session.scalar(select(Snippet).where(Snippet.id == snippet_id))
    assert snip is not None and snip.pin_failed_attempts == 50
