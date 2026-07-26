from __future__ import annotations

import base64
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.lib.tokens import hash_token
from app.models.accounts import Session as SessionRow
from app.models.accounts import User
from app.models.admin import AdminAuditLog, KillSwitch


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


async def _sign_in(db: AsyncSession, email: str, *, is_admin: bool = False) -> str:
    user = User(email=email, auth_credential_hash=b"argon2-placeholder", is_admin=is_admin)
    db.add(user)
    await db.flush()
    token = f"session-{email}"
    db.add(SessionRow(user_id=user.id, token_hash=hash_token(token), device_label="t"))
    await db.commit()
    return token


def _link_body() -> dict[str, Any]:
    return {
        "share_mode": "link",
        "content_type": "text",
        "ciphertext": _b64(b"blob"),
        "encrypted_metadata": _b64(b"meta"),
        "ttl_seconds": 600,
    }


def _pin_body() -> dict[str, Any]:
    return {
        "share_mode": "pin_share",
        "content_type": "text",
        "ciphertext": _b64(b"blob"),
        "content_key": _b64(b"\x01" * 32),
        "encrypted_metadata": _b64(b"meta"),
        "ttl_seconds": 600,
        "max_reads": 5,
    }


async def test_toggle_requires_admin(db_client: AsyncClient, db_session: AsyncSession) -> None:
    assert (
        await db_client.post("/me/admin/kill-switch/mode2", json={"enabled": True})
    ).status_code == 401
    db_client.cookies.set("wispr_session", await _sign_in(db_session, "plain@example.com"))
    assert (
        await db_client.post("/me/admin/kill-switch/mode2", json={"enabled": True})
    ).status_code == 403


async def test_toggle_unknown_switch_404(db_client: AsyncClient, db_session: AsyncSession) -> None:
    db_client.cookies.set(
        "wispr_session", await _sign_in(db_session, "boss@example.com", is_admin=True)
    )
    resp = await db_client.post("/me/admin/kill-switch/nope", json={"enabled": True})
    assert resp.status_code == 404


async def test_mode2_switch_blocks_pin_create(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    admin_token = await _sign_in(db_session, "boss@example.com", is_admin=True)
    db_client.cookies.set("wispr_session", admin_token)

    # Off: pin create works.
    assert (await db_client.post("/snippets", json=_pin_body())).status_code == 201

    toggled = await db_client.post("/me/admin/kill-switch/mode2", json={"enabled": True})
    assert toggled.status_code == 200 and toggled.json()["enabled"] is True

    # On: pin create is paused.
    blocked = await db_client.post("/snippets", json=_pin_body())
    assert blocked.status_code == 503
    assert blocked.json()["reason"] == "feature_disabled"

    # The toggle is audited, and the row persisted.
    audit = await db_session.scalar(
        select(AdminAuditLog).where(AdminAuditLog.action == "kill_switch.toggled")
    )
    assert audit is not None and audit.target_id == "mode2" and audit.payload["enabled"] is True
    row = await db_session.scalar(select(KillSwitch).where(KillSwitch.name == "mode2"))
    assert row is not None and row.enabled is True

    # Toggling back off re-enables create.
    await db_client.post("/me/admin/kill-switch/mode2", json={"enabled": False})
    assert (await db_client.post("/snippets", json=_pin_body())).status_code == 201


async def test_anon_link_switch_blocks_link_create(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    db_client.cookies.set(
        "wispr_session", await _sign_in(db_session, "boss@example.com", is_admin=True)
    )
    await db_client.post("/me/admin/kill-switch/anon_link", json={"enabled": True})

    # Anonymous link create is paused (clear the admin cookie first).
    db_client.cookies.clear()
    blocked = await db_client.post("/snippets", json=_link_body())
    assert blocked.status_code == 503
    assert blocked.json()["reason"] == "feature_disabled"


async def test_maintenance_state_public(db_client: AsyncClient, db_session: AsyncSession) -> None:
    # Off by default.
    off = await db_client.get("/maintenance")
    assert off.status_code == 200 and off.json() == {"enabled": False, "message": None}

    db_client.cookies.set(
        "wispr_session", await _sign_in(db_session, "boss@example.com", is_admin=True)
    )
    await db_client.post(
        "/me/admin/kill-switch/maintenance_mode",
        json={"enabled": True, "message": "back at 5pm"},
    )

    # Public endpoint reflects it (no auth needed).
    db_client.cookies.clear()
    on = await db_client.get("/maintenance")
    assert on.status_code == 200
    assert on.json() == {"enabled": True, "message": "back at 5pm"}
