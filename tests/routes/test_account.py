from __future__ import annotations

import base64
from datetime import UTC, datetime

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.lib.tokens import hash_token
from app.models.accounts import Invite, User
from app.models.accounts import Session as SessionRow
from app.models.snippets import ContentType, ShareMode, Snippet


async def _make_user(db: AsyncSession, email: str, *, is_admin: bool = False) -> User:
    user = User(email=email, auth_credential_hash=b"argon2-placeholder", is_admin=is_admin)
    db.add(user)
    await db.flush()
    return user


async def _add_session(db: AsyncSession, user: User, token: str, label: str) -> None:
    db.add(SessionRow(user_id=user.id, token_hash=hash_token(token), device_label=label))


async def _sign_in(
    db: AsyncSession, email: str = "acct@example.com", *, is_admin: bool = False
) -> tuple[User, str]:
    user = await _make_user(db, email, is_admin=is_admin)
    token = f"cur-{email}"
    await _add_session(db, user, token, "this-device")
    await db.commit()
    return user, token


async def test_list_sessions_requires_auth(db_client: AsyncClient) -> None:
    assert (await db_client.get("/me/sessions")).status_code == 401


async def test_list_sessions_flags_current(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    user, token = await _sign_in(db_session)
    await _add_session(db_session, user, "other-token", "other-device")
    await db_session.commit()
    db_client.cookies.set("wispr_session", token)

    resp = await db_client.get("/me/sessions")

    assert resp.status_code == 200
    sessions = resp.json()["sessions"]
    assert len(sessions) == 2
    current = [s for s in sessions if s["current"]]
    assert len(current) == 1
    assert current[0]["device_label"] == "this-device"


async def test_revoke_session_signs_out_one_device(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    user, token = await _sign_in(db_session)
    await _add_session(db_session, user, "other-token", "other-device")
    await db_session.commit()
    db_client.cookies.set("wispr_session", token)

    other = next(
        s for s in (await db_client.get("/me/sessions")).json()["sessions"] if not s["current"]
    )
    revoke = await db_client.request("DELETE", f"/me/sessions/{other['id']}")
    assert revoke.status_code == 204

    remaining = (await db_client.get("/me/sessions")).json()["sessions"]
    assert len(remaining) == 1
    assert remaining[0]["current"] is True


async def test_revoke_other_users_session_is_404(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _sign_in(db_session)
    victim = await _make_user(db_session, "victim@example.com")
    await _add_session(db_session, victim, "victim-token", "victim-device")
    await db_session.commit()
    victim_session = await db_session.scalar(
        select(SessionRow).where(SessionRow.user_id == victim.id)
    )
    assert victim_session is not None
    db_client.cookies.set("wispr_session", token)

    resp = await db_client.request("DELETE", f"/me/sessions/{victim_session.id}")
    assert resp.status_code == 404
    # The victim's session survives.
    assert (
        await db_session.scalar(select(SessionRow).where(SessionRow.id == victim_session.id))
    ) is not None


async def _add_sync(
    db: AsyncSession, owner_id: object, sid: str, *, stored: bool = False
) -> None:
    db.add(
        Snippet(
            id=sid,
            share_mode=ShareMode.sync,
            content_type=ContentType.text,
            encrypted_metadata=b"meta",
            ciphertext_inline=None if stored else b"ct",
            storage_object_key="files/tok" if stored else None,
            chunk_count=1 if stored else None,
            size_bytes=2,
            wrapped_dek=b"\xaa" * 48,
            wrapped_dek_iv=b"\xbb" * 12,
            owner_user_id=owner_id,
        )
    )
    await db.commit()


async def test_export_requires_auth(db_client: AsyncClient) -> None:
    assert (await db_client.get("/me/export")).status_code == 401


async def test_export_bundles_sync_and_unwrapped_pins(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    user, token = await _sign_in(db_session)
    user.master_key_salt = b"\x07" * 16
    await _add_sync(db_session, user.id, "syncinline01")
    await _add_sync(db_session, user.id, "syncstored02", stored=True)
    db_client.cookies.set("wispr_session", token)

    # A PIN-share created through the real path so its key is vault-wrapped.
    pin = await db_client.post(
        "/snippets",
        json={
            "share_mode": "pin_share",
            "content_type": "text",
            "ciphertext": base64.b64encode(b"pin-ct").decode(),
            "content_key": base64.b64encode(b"\x02" * 32).decode(),
            "encrypted_metadata": base64.b64encode(b"pinmeta").decode(),
            "ttl_seconds": 3600,
            "max_reads": 5,
        },
    )
    assert pin.status_code == 201, pin.text

    resp = await db_client.get("/me/export")

    assert resp.status_code == 200, resp.text
    bundle = resp.json()
    assert bundle["version"] == 1
    assert bundle["master_key_salt"] == base64.b64encode(b"\x07" * 16).decode()

    by_id = {item["id"]: item for item in bundle["sync"]}
    assert by_id["syncinline01"]["ciphertext"] == base64.b64encode(b"ct").decode()
    assert by_id["syncinline01"]["stored"] is False
    assert by_id["syncinline01"]["wrapped_dek"] == base64.b64encode(b"\xaa" * 48).decode()
    # File-backed content ships as metadata only — its bytes aren't embedded.
    assert by_id["syncstored02"]["stored"] is True
    assert by_id["syncstored02"]["ciphertext"] is None

    assert len(bundle["pins"]) == 1
    exported_key = base64.b64decode(bundle["pins"][0]["content_key"])
    assert exported_key == b"\x02" * 32  # server-unwrapped for the owner


async def test_export_omits_taken_down(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    user, token = await _sign_in(db_session)
    await _add_sync(db_session, user.id, "synclivexxx1")
    down = Snippet(
        id="syncdownxxx2",
        share_mode=ShareMode.sync,
        content_type=ContentType.text,
        encrypted_metadata=b"meta",
        ciphertext_inline=b"ct",
        size_bytes=2,
        wrapped_dek=b"\xaa" * 48,
        wrapped_dek_iv=b"\xbb" * 12,
        owner_user_id=user.id,
        taken_down_at=datetime.now(tz=UTC),
    )
    db_session.add(down)
    await db_session.commit()
    db_client.cookies.set("wispr_session", token)

    bundle = (await db_client.get("/me/export")).json()

    ids = {item["id"] for item in bundle["sync"]}
    assert "synclivexxx1" in ids
    assert "syncdownxxx2" not in ids


async def test_create_invite_admin_only(db_client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _sign_in(db_session, email="member@example.com")
    db_client.cookies.set("wispr_session", token)
    assert (await db_client.post("/me/invites")).status_code == 403


async def test_create_invite_mints_code(db_client: AsyncClient, db_session: AsyncSession) -> None:
    admin, token = await _sign_in(db_session, email="boss@example.com", is_admin=True)
    db_client.cookies.set("wispr_session", token)

    resp = await db_client.post("/me/invites")

    assert resp.status_code == 200
    code = resp.json()["code"]
    assert len(code) == 8
    row = await db_session.scalar(select(Invite).where(Invite.code == code))
    assert row is not None
    assert row.created_by == admin.id
    assert row.used_by is None
