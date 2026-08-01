from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.lib.watch_bus import GoneEvent, ReadEvent, WatchEvent
from app.lib.watch_bus import bus as watch_bus
from app.models.snippets import Snippet
from app.schemas.snippets import GoneReason

router = APIRouter(tags=["snippets"])

DbSession = Annotated[AsyncSession, Depends(get_session)]

# RFC 6455 close codes. 1000 = normal; 1008 = policy violation (we use
# it for "snippet not found" since 1011 is reserved for server error).
_CLOSE_NORMAL = 1000
_CLOSE_POLICY = 1008


@router.websocket("/ws/snippet/{snippet_id}/watch")
async def watch_snippet(
    websocket: WebSocket,
    snippet_id: str,
    session: DbSession,
) -> None:
    """Live read-counter stream for the sender's SentState.

    Anyone with the snippet id can attach (no owner_token gate per
    [D-260526-02]). The watch surface leaks one meta-fact ("this
    share has been read") that anyone with the URL learns anyway from
    a single GET attempt.

    The flow:
      1. Accept the WS.
      2. Load the snippet; close 1008 if it doesn't exist.
      3. Send an initial ``{op: "snapshot"}`` carrying the current
         read_count / max_reads / expires_at / gone reason if any.
      4. If the snippet is already gone, close immediately after the
         snapshot: there's nothing to watch.
      5. Subscribe to the bus and stream events as they arrive. The
         connection holds until the client disconnects, the snippet
         hits a terminal state, or expiry fires.
    """
    await websocket.accept()

    snippet = await _load(session, snippet_id)
    if snippet is None:
        await websocket.close(code=_CLOSE_POLICY, reason="not_found")
        return

    snapshot, gone_reason = _snapshot_payload(snippet)
    await _safe_send(websocket, snapshot)

    if gone_reason is not None:
        # Nothing to watch: surface the terminal state and close.
        await _safe_send(websocket, _gone_payload(gone_reason))
        with contextlib.suppress(RuntimeError):
            await websocket.close(code=_CLOSE_NORMAL, reason=gone_reason)
        return

    # Forward bus events until the WS closes or a terminal event fires.
    forwarder = asyncio.create_task(_forward_events(websocket, snippet_id))
    drainer = asyncio.create_task(_drain_incoming(websocket))
    try:
        done, _pending = await asyncio.wait(
            {forwarder, drainer}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in done:
            # Surface forwarder exceptions; drainer ending just means
            # the client closed.
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
            await websocket.close(code=_CLOSE_NORMAL, reason="watch_closed")


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _load(session: AsyncSession, snippet_id: str) -> Snippet | None:
    result: Snippet | None = await session.get(Snippet, snippet_id)
    return result


def _snapshot_payload(snippet: Snippet) -> tuple[dict[str, Any], GoneReason | None]:
    gone = _gone_reason(snippet)
    payload: dict[str, Any] = {
        "op": "snapshot",
        "read_count": snippet.read_count,
        "max_reads": snippet.max_reads,
        "expires_at": (
            snippet.expires_at.astimezone(UTC).isoformat()
            if snippet.expires_at is not None
            else None
        ),
        "taken_down": snippet.taken_down_at is not None,
    }
    if gone is not None:
        payload["gone_reason"] = gone.value
    return payload, gone


def _gone_reason(snippet: Snippet) -> GoneReason | None:
    if snippet.taken_down_at is not None:
        return GoneReason.taken_down
    now = datetime.now(tz=UTC)
    if snippet.expires_at is not None and snippet.expires_at <= now:
        return GoneReason.expired
    if snippet.max_reads is not None and snippet.read_count >= snippet.max_reads:
        return GoneReason.burned
    return None


def _gone_payload(reason: GoneReason) -> dict[str, Any]:
    return {"op": "gone", "reason": reason.value}


def _event_payload(event: WatchEvent) -> dict[str, Any]:
    if isinstance(event, ReadEvent):
        return {
            "op": "read",
            "read_count": event.read_count,
            "at": datetime.now(tz=UTC).isoformat(),
        }
    if isinstance(event, GoneEvent):
        return {"op": "gone", "reason": event.reason}
    raise AssertionError(f"unhandled event variant: {event!r}")


async def _forward_events(websocket: WebSocket, snippet_id: str) -> None:
    """Drain the bus subscription, ship each event to the client, and
    stop after a gone event: no point streaming further."""
    async for event in watch_bus.listen(snippet_id):
        payload = _event_payload(event)
        await _safe_send(websocket, payload)
        if event.kind == "gone":
            return


async def _drain_incoming(websocket: WebSocket) -> None:
    """The protocol is server-push only; we don't expect client frames.
    We still need to drain inbound data so the WS receive loop notices
    a remote close. Without this, the forwarder happily runs into a
    half-closed socket."""
    while True:
        try:
            await websocket.receive_text()
        except WebSocketDisconnect:
            return


async def _safe_send(websocket: WebSocket, payload: dict[str, Any]) -> None:
    with contextlib.suppress(RuntimeError, WebSocketDisconnect):
        await websocket.send_text(json.dumps(payload))
