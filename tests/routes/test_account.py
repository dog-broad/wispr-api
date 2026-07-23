from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.lib.tokens import hash_token
from app.models.accounts import Invite, User
from app.models.accounts import Session as SessionRow


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
