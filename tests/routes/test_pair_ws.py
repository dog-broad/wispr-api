from __future__ import annotations

import json
import time
from typing import Any

import pytest
import redis as sync_redis
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


def _seed_pair(
    ws_redis: sync_redis.Redis,
    *,
    pin: str,
    sender_token: str,
    sender_ip: str,
    ttl: int = 60,
) -> None:
    """Hand-write the redis state that ``POST /pair`` would have left.
    Lets WS tests skip the HTTP round-trip and just exercise the relay.
    """
    payload = json.dumps(
        {
            "sender_token": sender_token,
            "sender_ip": sender_ip,
            "created_at": int(time.time()),
        },
        separators=(",", ":"),
    )
    ws_redis.set(f"pair:pin:{pin}", payload, ex=ttl)
    ws_redis.set(f"pair:sender:{sender_ip}", pin, ex=ttl)


def _recv_json(ws: Any) -> dict[str, Any]:
    raw = ws.receive_text()
    parsed = json.loads(raw)
    assert isinstance(parsed, dict)
    return parsed


# ---------------------------------------------------------------------------
# Happy path: sender attaches, receiver redeems, signals forward both ways
# ---------------------------------------------------------------------------


def test_pair_flow_sender_receiver_handshake_and_relay(
    ws_client: TestClient, ws_redis: sync_redis.Redis
) -> None:
    _seed_pair(ws_redis, pin="1234", sender_token="tok-abc", sender_ip="203.0.113.10")

    with (
        ws_client.websocket_connect("/ws/pair?pin=1234&sender_token=tok-abc") as sender,
        ws_client.websocket_connect("/ws/pair") as receiver,
    ):
        receiver.send_text(json.dumps({"op": "redeem", "pin": "1234"}))

        paired = _recv_json(receiver)
        assert paired == {"op": "paired"}

        notified = _recv_json(sender)
        assert notified == {"op": "receiver_connected"}

        # Sender → receiver opaque forwarding.
        sender.send_text(json.dumps({"op": "signal", "payload": "sdp-offer-data"}))
        relayed_to_receiver = _recv_json(receiver)
        assert relayed_to_receiver == {"op": "signal", "payload": "sdp-offer-data"}

        # Receiver → sender opaque forwarding.
        receiver.send_text(json.dumps({"op": "signal", "payload": "sdp-answer-data"}))
        relayed_to_sender = _recv_json(sender)
        assert relayed_to_sender == {"op": "signal", "payload": "sdp-answer-data"}


# ---------------------------------------------------------------------------
# Sender failure paths
# ---------------------------------------------------------------------------


def test_sender_with_wrong_token_is_rejected(
    ws_client: TestClient, ws_redis: sync_redis.Redis
) -> None:
    _seed_pair(ws_redis, pin="1234", sender_token="tok-correct", sender_ip="203.0.113.20")

    with ws_client.websocket_connect("/ws/pair?pin=1234&sender_token=tok-wrong") as sender:
        msg = _recv_json(sender)
        assert msg == {"op": "pair_failed", "reason": "unknown_token"}
        with pytest.raises(WebSocketDisconnect):
            sender.receive_text()


def test_sender_with_unknown_pin_is_rejected(ws_client: TestClient) -> None:
    with ws_client.websocket_connect("/ws/pair?pin=0000&sender_token=tok-any") as sender:
        msg = _recv_json(sender)
        assert msg == {"op": "pair_failed", "reason": "unknown_token"}


def test_duplicate_sender_for_same_pin_rejected(
    ws_client: TestClient, ws_redis: sync_redis.Redis
) -> None:
    _seed_pair(ws_redis, pin="1234", sender_token="tok-abc", sender_ip="203.0.113.21")

    with (
        ws_client.websocket_connect("/ws/pair?pin=1234&sender_token=tok-abc"),
        # Second sender on the same PIN: registry refuses.
        ws_client.websocket_connect("/ws/pair?pin=1234&sender_token=tok-abc") as second,
    ):
        msg = _recv_json(second)
        assert msg == {"op": "pair_failed", "reason": "duplicate_sender"}


# ---------------------------------------------------------------------------
# Receiver failure paths
# ---------------------------------------------------------------------------


def test_receiver_unknown_pin_yields_unknown_pin(ws_client: TestClient) -> None:
    """PIN never existed in either namespace.

    Redis lookup miss fires before the registry check, so a fully
    unknown PIN is reported as ``unknown_pin``, distinct from the
    ``sender_offline`` case where Redis has the record but no sender WS
    ever attached (see test_receiver_redeem_when_sender_never_attached).
    """
    with ws_client.websocket_connect("/ws/pair") as receiver:
        receiver.send_text(json.dumps({"op": "redeem", "pin": "0000"}))
        msg = _recv_json(receiver)
        assert msg == {"op": "pair_failed", "reason": "unknown_pin"}


def test_receiver_redeem_when_sender_never_attached(
    ws_client: TestClient, ws_redis: sync_redis.Redis
) -> None:
    """Redis has the pair record (issued by POST /pair) but no sender
    WS ever attached → sender_offline."""
    _seed_pair(ws_redis, pin="1234", sender_token="tok-abc", sender_ip="203.0.113.30")
    with ws_client.websocket_connect("/ws/pair") as receiver:
        receiver.send_text(json.dumps({"op": "redeem", "pin": "1234"}))
        msg = _recv_json(receiver)
        assert msg == {"op": "pair_failed", "reason": "sender_offline"}


def test_receiver_second_redeem_on_same_pin_already_redeemed(
    ws_client: TestClient, ws_redis: sync_redis.Redis
) -> None:
    _seed_pair(ws_redis, pin="1234", sender_token="tok-abc", sender_ip="203.0.113.31")

    with (
        ws_client.websocket_connect("/ws/pair?pin=1234&sender_token=tok-abc"),
        ws_client.websocket_connect("/ws/pair") as first_receiver,
    ):
        first_receiver.send_text(json.dumps({"op": "redeem", "pin": "1234"}))
        assert _recv_json(first_receiver) == {"op": "paired"}

        with ws_client.websocket_connect("/ws/pair") as second_receiver:
            second_receiver.send_text(json.dumps({"op": "redeem", "pin": "1234"}))
            msg = _recv_json(second_receiver)
            assert msg == {"op": "pair_failed", "reason": "already_redeemed"}


def test_receiver_bad_first_op_is_rejected(ws_client: TestClient) -> None:
    with ws_client.websocket_connect("/ws/pair") as receiver:
        receiver.send_text(json.dumps({"op": "signal", "payload": "premature"}))
        msg = _recv_json(receiver)
        assert msg == {"op": "pair_failed", "reason": "bad_op"}


def test_receiver_malformed_envelope_is_rejected(ws_client: TestClient) -> None:
    with ws_client.websocket_connect("/ws/pair") as receiver:
        receiver.send_text("this-is-not-json")
        msg = _recv_json(receiver)
        assert msg == {"op": "pair_failed", "reason": "bad_envelope"}


def test_oversized_redeem_frame_is_rejected(ws_client: TestClient) -> None:
    with ws_client.websocket_connect("/ws/pair") as receiver:
        # 17 KiB of payload, over the 16 KiB cap.
        oversized = json.dumps(
            {"op": "redeem", "pin": "1234", "junk": "x" * (17 * 1024)},
            separators=(",", ":"),
        )
        receiver.send_text(oversized)
        msg = _recv_json(receiver)
        assert msg == {"op": "pair_failed", "reason": "oversized_signal"}


# ---------------------------------------------------------------------------
# Rate limiting on receiver redeems
# ---------------------------------------------------------------------------


def test_receiver_redeem_rate_limited_per_minute(
    ws_client: TestClient, ws_redis: sync_redis.Redis
) -> None:
    """Five wrong-PIN redeems from the same IP fit the burst; the sixth
    comes back rate_limited_minute."""
    headers = {"cf-connecting-ip": "203.0.113.40"}
    for _ in range(5):
        with ws_client.websocket_connect("/ws/pair", headers=headers) as ws:
            ws.send_text(json.dumps({"op": "redeem", "pin": "0000"}))
            msg = _recv_json(ws)
            assert msg["op"] == "pair_failed"

    with ws_client.websocket_connect("/ws/pair", headers=headers) as ws:
        ws.send_text(json.dumps({"op": "redeem", "pin": "0000"}))
        msg = _recv_json(ws)
        assert msg["op"] == "pair_failed"
        assert msg["reason"] == "rate_limited_minute"
        assert msg["retry_after_seconds"] >= 1


# ---------------------------------------------------------------------------
# Peer disconnect propagation
# ---------------------------------------------------------------------------


def test_sender_disconnect_closes_receiver(
    ws_client: TestClient, ws_redis: sync_redis.Redis
) -> None:
    """When the sender drops after pairing, the receiver's WS closes
    with the peer_disconnected reason."""
    _seed_pair(ws_redis, pin="1234", sender_token="tok-abc", sender_ip="203.0.113.50")

    with (
        ws_client.websocket_connect("/ws/pair?pin=1234&sender_token=tok-abc") as sender,
        ws_client.websocket_connect("/ws/pair") as receiver,
    ):
        receiver.send_text(json.dumps({"op": "redeem", "pin": "1234"}))
        assert _recv_json(receiver) == {"op": "paired"}
        _ = _recv_json(sender)  # drain receiver_connected

        sender.close()

        with pytest.raises(WebSocketDisconnect):
            receiver.receive_text()
