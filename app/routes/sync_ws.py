from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.lib.auth import SESSION_COOKIE_NAME
from app.lib.sync_bus import SnippetCreatedEvent, SnippetDeletedEvent, SyncEvent
from app.lib.sync_bus import bus as sync_bus
from app.lib.tokens import hash_token
from app.models.accounts import Session as SessionRow
from app.models.accounts import User

router = APIRouter(tags=["me"])

DbSession = Annotated[AsyncSession, Depends(get_session)]

_CLOSE_NORMAL = 1000
_CLOSE_POLICY = 1008


async def _user_id_from_ws(websocket: WebSocket, session: AsyncSession) -> str | None:
    """Resolve the authed user from the session cookie on the WS handshake, or
    None. Mirrors the HTTP current_user lookup."""
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
    if user is None or user.deleted_at is not None:
        return None
    return str(user.id)


@router.websocket("/ws/sync")
async def sync_feed(websocket: WebSocket, session: DbSession) -> None:
    """Live Sync feed for the authed user: pushes snippet.created /
    snippet.deleted as they happen so /me updates without polling."""
    user_id = await _user_id_from_ws(websocket, session)
    await websocket.accept()
    if user_id is None:
        await websocket.close(code=_CLOSE_POLICY, reason="unauthorized")
        return

    forwarder = asyncio.create_task(_forward_events(websocket, user_id))
    drainer = asyncio.create_task(_drain_incoming(websocket))
    try:
        done, _pending = await asyncio.wait(
            {forwarder, drainer}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in done:
            task.result()
    except WebSocketDisconnect:
        pass
    finally:
        forwarder.cancel()
        drainer.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await forwarder
        with contextlib.suppress(asyncio.CancelledError):
            await drainer
        with contextlib.suppress(RuntimeError):
            await websocket.close(code=_CLOSE_NORMAL, reason="closed")


def _payload(event: SyncEvent) -> dict[str, Any]:
    if isinstance(event, SnippetCreatedEvent):
        return {"op": "snippet.created", "item": event.item.model_dump(mode="json")}
    if isinstance(event, SnippetDeletedEvent):
        return {"op": "snippet.deleted", "id": event.snippet_id}
    raise AssertionError(f"unhandled sync event: {event!r}")


async def _forward_events(websocket: WebSocket, user_id: str) -> None:
    async for event in sync_bus.listen(user_id):
        with contextlib.suppress(RuntimeError, WebSocketDisconnect):
            await websocket.send_text(json.dumps(_payload(event)))


async def _drain_incoming(websocket: WebSocket) -> None:
    while True:
        try:
            await websocket.receive_text()
        except WebSocketDisconnect:
            return
