from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db import get_session
from app.lib.auth import SESSION_COOKIE_NAME
from app.lib.dashboard import load_dashboard
from app.lib.tokens import hash_token
from app.models.accounts import Session as SessionRow
from app.models.accounts import User
from app.schemas.dashboard import DashboardResponse

router = APIRouter(tags=["admin"])

DbSession = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]

_CLOSE_NORMAL = 1000
_CLOSE_POLICY = 1008
# Push cadence. The dashboard data itself only refreshes every 30 s (the cache
# TTL), so most ticks find no change and send nothing; the tick just checks.
_TICK_SECONDS = 5.0


async def _admin_from_ws(websocket: WebSocket, session: AsyncSession) -> User | None:
    """Resolve an authed admin from the session cookie on the handshake, or
    None (not signed in, deleted, or not an admin)."""
    raw_token = websocket.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        return None
    user = (
        await session.execute(
            select(User)
            .join(SessionRow, SessionRow.user_id == User.id)
            .where(SessionRow.token_hash == hash_token(raw_token))
        )
    ).scalar_one_or_none()
    if user is None or user.deleted_at is not None or not user.is_admin:
        return None
    return user


def _flatten(payload: DashboardResponse) -> dict[str, dict[str, Any]]:
    """All metric rows keyed by their (globally-unique) key, for diffing."""
    flat: dict[str, dict[str, Any]] = {}
    for section in (payload.quotas, payload.health, payload.business, payload.abuse, payload.ops):
        for metric in section:
            flat[metric.key] = metric.model_dump(mode="json")
    return flat


def _diff(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    return {key: value for key, value in current.items() if previous.get(key) != value}


@router.websocket("/ws/admin")
async def admin_feed(websocket: WebSocket, session: DbSession, settings: SettingsDep) -> None:
    """Live operator-console feed. Pushes a full snapshot on connect, then only
    the changed metric rows every 5 s. Admin only."""
    admin = await _admin_from_ws(websocket, session)
    await websocket.accept()
    if admin is None:
        await websocket.close(code=_CLOSE_POLICY, reason="unauthorized")
        return

    pusher = asyncio.create_task(_push_dashboard(websocket, session, settings))
    drainer = asyncio.create_task(_drain_incoming(websocket))
    try:
        done, _pending = await asyncio.wait({pusher, drainer}, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except WebSocketDisconnect:
        pass
    finally:
        pusher.cancel()
        drainer.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await pusher
        with contextlib.suppress(asyncio.CancelledError):
            await drainer
        with contextlib.suppress(RuntimeError):
            await websocket.close(code=_CLOSE_NORMAL, reason="closed")


async def _push_dashboard(websocket: WebSocket, session: AsyncSession, settings: Settings) -> None:
    redis = websocket.app.state.redis
    http_client = websocket.app.state.http_client
    last_flat: dict[str, dict[str, Any]] | None = None
    last_actions: list[dict[str, Any]] | None = None
    while True:
        payload = await load_dashboard(session, redis, http_client, settings)
        # Reads only: drop any transaction snapshot so the long-lived session
        # sees fresh data on the next build.
        await session.rollback()
        flat = _flatten(payload)
        actions = [a.model_dump(mode="json") for a in payload.recent_actions]

        if last_flat is None:
            await _send(websocket, {"op": "snapshot", "dashboard": payload.model_dump(mode="json")})
        else:
            changed = _diff(flat, last_flat)
            message: dict[str, Any] = {"op": "delta", "status": payload.status.value}
            has_change = bool(changed)
            if changed:
                message["metrics"] = changed
            if actions != last_actions:
                message["recent_actions"] = actions
                has_change = True
            if has_change:
                await _send(websocket, message)

        last_flat = flat
        last_actions = actions
        await asyncio.sleep(_TICK_SECONDS)


async def _send(websocket: WebSocket, data: dict[str, Any]) -> None:
    with contextlib.suppress(RuntimeError, WebSocketDisconnect):
        await websocket.send_text(json.dumps(data))


async def _drain_incoming(websocket: WebSocket) -> None:
    while True:
        try:
            await websocket.receive_text()
        except WebSocketDisconnect:
            return
