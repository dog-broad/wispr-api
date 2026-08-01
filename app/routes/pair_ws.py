from __future__ import annotations

import contextlib
import hmac
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from redis.asyncio import Redis

from app.lib.clientip import bucket_key, extract_client_ip
from app.lib.pair_signaling import (
    MAX_SIGNAL_FRAME_BYTES,
    REDEEM_BURST_PER_HOUR,
    REDEEM_BURST_PER_MINUTE,
    ActivePair,
    AttachOutcome,
    PairFailReason,
    registry,
)
from app.lib.pairings import lookup_pairing
from app.lib.ratelimit import consume_token

router = APIRouter(tags=["pair"])
logger = logging.getLogger(__name__)

# Normal closure code per RFC 6455. WS clients see the reason text.
_CLOSE_NORMAL = 1000
_PEER_DISCONNECTED = "peer_disconnected"

# Allowed envelope ops. The server *forwards* signal payloads opaquely
# without inspecting their content; redeem and cancel are the only
# protocol-meaningful ops.
_OP_REDEEM = "redeem"
_OP_SIGNAL = "signal"
_OP_CANCEL = "cancel"

# Outbound ops the server emits.
_OP_PAIR_FAILED = "pair_failed"
_OP_PAIRED = "paired"
_OP_RECEIVER_CONNECTED = "receiver_connected"


@router.websocket("/ws/pair")
async def ws_pair(ws: WebSocket) -> None:
    """Pair signaling relay. See [D-260525-03] for the protocol shape.

    Sender: opens ``?pin=…&sender_token=…``. Token is validated against
    the stored pair record; on success the sender's socket is parked in
    the registry until a receiver redeems.

    Receiver: opens with no query, sends ``{op: redeem, pin}`` as the
    first frame. On success, server sends ``paired`` to the receiver
    and ``receiver_connected`` to the sender; subsequent ``signal``
    frames are forwarded opaquely until either side closes.
    """
    pin = ws.query_params.get("pin")
    sender_token = ws.query_params.get("sender_token")
    redis_client: Redis = ws.app.state.redis

    await ws.accept()

    if pin is not None and sender_token is not None:
        await _run_sender(ws, pin, sender_token, redis_client)
    else:
        sender_ip = extract_client_ip(ws)
        await _run_receiver(ws, sender_ip, redis_client)


async def _run_sender(ws: WebSocket, pin: str, sender_token: str, redis_client: Redis) -> None:
    pair = await lookup_pairing(redis_client, pin)
    if pair is None or not hmac.compare_digest(pair.sender_token, sender_token):
        await _fail_and_close(ws, PairFailReason.unknown_token)
        return

    registered = await registry.register_sender(
        pin=pair.pin,
        sender_token=pair.sender_token,
        sender_ip=pair.sender_ip,
        ws=ws,
    )
    if not registered:
        await _fail_and_close(ws, PairFailReason.duplicate_sender)
        return

    try:
        await _sender_loop(ws, pair.pin)
    except WebSocketDisconnect:
        # Sender hung up; fall through to cleanup.
        pass
    finally:
        active = await registry.remove(pair.pin)
        if active is not None and active.receiver_ws is not None:
            await _safe_close_peer(active.receiver_ws)


async def _sender_loop(ws: WebSocket, pin: str) -> None:
    while True:
        text = await ws.receive_text()
        if len(text) > MAX_SIGNAL_FRAME_BYTES:
            await _fail_and_close(ws, PairFailReason.oversized_signal)
            return

        envelope = _parse_envelope(text)
        if envelope is None:
            await _fail_and_close(ws, PairFailReason.bad_envelope)
            return

        op = envelope.get("op")
        if op == _OP_CANCEL:
            # Sender-initiated teardown. Cleanup happens in the finally
            # block in ``_run_sender``.
            return
        if op == _OP_SIGNAL:
            active = await registry.get(pin)
            if active is None or active.receiver_ws is None:
                await _fail_and_close(ws, PairFailReason.premature_signal)
                return
            await active.receiver_ws.send_text(text)
            continue
        await _fail_and_close(ws, PairFailReason.bad_op)
        return


async def _run_receiver(ws: WebSocket, sender_ip: str, redis_client: Redis) -> None:
    # First frame must be ``{op: redeem, pin}``. We don't accept the
    # connection state-machine until we know which PIN to attach to.
    try:
        text = await ws.receive_text()
    except WebSocketDisconnect:
        return

    if len(text) > MAX_SIGNAL_FRAME_BYTES:
        await _fail_and_close(ws, PairFailReason.oversized_signal)
        return

    envelope = _parse_envelope(text)
    if envelope is None:
        await _fail_and_close(ws, PairFailReason.bad_envelope)
        return

    op = envelope.get("op")
    pin_value = envelope.get("pin")
    if op != _OP_REDEEM or not isinstance(pin_value, str):
        await _fail_and_close(ws, PairFailReason.bad_op)
        return

    pin = pin_value

    # Rate-limit the redeem attempt. Two layered budgets keep a single
    # rogue IP from drowning the namespace ([§12]).
    rl_key_suffix = bucket_key(sender_ip)
    minute = await consume_token(
        redis_client,
        f"rl:pair-redeem-minute:{rl_key_suffix}",
        capacity=REDEEM_BURST_PER_MINUTE,
        period_seconds=60,
    )
    if not minute.allowed:
        await _fail_and_close(
            ws,
            PairFailReason.rate_limited_minute,
            retry_after=minute.retry_after_seconds,
        )
        return

    hourly = await consume_token(
        redis_client,
        f"rl:pair-redeem-hour:{rl_key_suffix}",
        capacity=REDEEM_BURST_PER_HOUR,
        period_seconds=3600,
    )
    if not hourly.allowed:
        await _fail_and_close(
            ws,
            PairFailReason.rate_limited_hour,
            retry_after=hourly.retry_after_seconds,
        )
        return

    pair_record = await lookup_pairing(redis_client, pin)
    if pair_record is None:
        await _fail_and_close(ws, PairFailReason.unknown_pin)
        return

    active, outcome = await registry.attach_receiver(pin, ws)
    if outcome is AttachOutcome.sender_offline:
        await _fail_and_close(ws, PairFailReason.sender_offline)
        return
    if outcome is AttachOutcome.already_redeemed or active is None:
        await _fail_and_close(ws, PairFailReason.already_redeemed)
        return

    # Pair established. Sender keeps its registry slot; the Redis state
    # is *not* deleted (see [D-260525-03]) so a duplicate redeem on this
    # PIN still resolves and surfaces ``already_redeemed`` instead of a
    # misleading ``unknown_pin``. TTL on the Redis record handles the
    # cleanup 60s after issue.
    await ws.send_text(_envelope({"op": _OP_PAIRED}))
    try:
        await active.sender_ws.send_text(_envelope({"op": _OP_RECEIVER_CONNECTED}))
    except (RuntimeError, WebSocketDisconnect):
        # Sender disconnected between attach_receiver and the notify
        # send. Treat as sender_offline from the receiver's view.
        await _fail_and_close(ws, PairFailReason.sender_offline)
        await registry.remove(pin)
        return

    try:
        await _receiver_loop(ws, active)
    except WebSocketDisconnect:
        pass
    finally:
        removed = await registry.remove(pin)
        if removed is not None:
            await _safe_close_peer(removed.sender_ws)
        # Redis state is left to expire naturally so a late duplicate
        # redeem on the same PIN sees ``already_redeemed`` rather than
        # ``unknown_pin``.


async def _receiver_loop(ws: WebSocket, active: ActivePair) -> None:
    while True:
        text = await ws.receive_text()
        if len(text) > MAX_SIGNAL_FRAME_BYTES:
            await _fail_and_close(ws, PairFailReason.oversized_signal)
            return

        envelope = _parse_envelope(text)
        if envelope is None:
            await _fail_and_close(ws, PairFailReason.bad_envelope)
            return

        op = envelope.get("op")
        if op == _OP_CANCEL:
            return
        if op == _OP_SIGNAL:
            await active.sender_ws.send_text(text)
            continue
        await _fail_and_close(ws, PairFailReason.bad_op)
        return


def _parse_envelope(text: str) -> dict[str, Any] | None:
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(envelope, dict):
        return None
    return envelope


def _envelope(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"))


async def _fail_and_close(
    ws: WebSocket, reason: PairFailReason, *, retry_after: int | None = None
) -> None:
    """Send a ``pair_failed`` envelope and close the socket. Best effort
    on the send; if the client has already dropped, the close attempt
    still runs."""
    payload: dict[str, Any] = {"op": _OP_PAIR_FAILED, "reason": str(reason)}
    if retry_after is not None:
        payload["retry_after_seconds"] = retry_after
    with contextlib.suppress(RuntimeError, WebSocketDisconnect):
        await ws.send_text(_envelope(payload))
    with contextlib.suppress(RuntimeError):
        await ws.close(code=_CLOSE_NORMAL, reason=str(reason))


async def _safe_close_peer(peer: WebSocket) -> None:
    """Close the partner socket with a peer_disconnected reason. Used on
    either side dropping after the pair was established."""
    with contextlib.suppress(RuntimeError):
        await peer.close(code=_CLOSE_NORMAL, reason=_PEER_DISCONNECTED)
