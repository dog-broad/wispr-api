from __future__ import annotations

from typing import cast
from unittest.mock import MagicMock

import pytest
from fastapi import WebSocket

from app.lib.pair_signaling import (
    AttachOutcome,
    PairSignalingRegistry,
)


def _ws() -> WebSocket:
    """A bare stand-in WebSocket for registry tests; the registry never
    calls any method on it."""
    return cast(WebSocket, MagicMock(spec=WebSocket))


@pytest.fixture
def reg() -> PairSignalingRegistry:
    return PairSignalingRegistry()


async def test_register_sender_claims_pin_slot(reg: PairSignalingRegistry) -> None:
    sender = _ws()
    ok = await reg.register_sender(
        pin="1234", sender_token="tok", sender_ip="203.0.113.10", ws=sender
    )
    assert ok is True

    active = await reg.get("1234")
    assert active is not None
    assert active.sender_ws is sender
    assert active.receiver_ws is None
    assert active.sender_ip == "203.0.113.10"
    assert active.sender_token == "tok"


async def test_register_sender_rejects_duplicate(reg: PairSignalingRegistry) -> None:
    first = _ws()
    second = _ws()
    assert await reg.register_sender("1234", "tok", "203.0.113.11", first) is True
    assert await reg.register_sender("1234", "tok", "203.0.113.11", second) is False
    # The original sender keeps the slot.
    active = await reg.get("1234")
    assert active is not None
    assert active.sender_ws is first


async def test_attach_receiver_pairs_with_sender(reg: PairSignalingRegistry) -> None:
    sender = _ws()
    receiver = _ws()
    await reg.register_sender("1234", "tok", "203.0.113.12", sender)

    active, outcome = await reg.attach_receiver("1234", receiver)
    assert outcome is AttachOutcome.ok
    assert active is not None
    assert active.sender_ws is sender
    assert active.receiver_ws is receiver


async def test_attach_receiver_reports_sender_offline_when_unknown_pin(
    reg: PairSignalingRegistry,
) -> None:
    active, outcome = await reg.attach_receiver("9999", _ws())
    assert active is None
    assert outcome is AttachOutcome.sender_offline


async def test_attach_receiver_rejects_second_redeem(
    reg: PairSignalingRegistry,
) -> None:
    await reg.register_sender("1234", "tok", "203.0.113.13", _ws())
    first_active, first_outcome = await reg.attach_receiver("1234", _ws())
    assert first_outcome is AttachOutcome.ok
    assert first_active is not None

    second_active, second_outcome = await reg.attach_receiver("1234", _ws())
    assert second_outcome is AttachOutcome.already_redeemed
    assert second_active is None

    # The first receiver is still the canonical one in the registry.
    still_active = await reg.get("1234")
    assert still_active is not None
    assert still_active.receiver_ws is first_active.receiver_ws


async def test_remove_clears_slot(reg: PairSignalingRegistry) -> None:
    sender = _ws()
    await reg.register_sender("1234", "tok", "203.0.113.14", sender)

    removed = await reg.remove("1234")
    assert removed is not None
    assert removed.sender_ws is sender
    assert await reg.get("1234") is None


async def test_remove_unknown_pin_is_noop(reg: PairSignalingRegistry) -> None:
    assert await reg.remove("9999") is None
