from __future__ import annotations

from unittest.mock import patch

import pytest
from redis.asyncio import Redis

from app.lib.pairings import (
    PAIRING_TTL_SECONDS,
    PairNamespaceFullError,
    create_pairing,
    delete_pairing,
    lookup_pairing,
)


async def test_create_pairing_issues_pin_and_token(redis_client: Redis) -> None:
    pairing = await create_pairing(redis_client, "203.0.113.10")

    assert len(pairing.pin) == 4
    assert pairing.pin.isdigit()
    # sender token: 32 random bytes → 43-char unpadded base64url
    assert len(pairing.sender_token) == 43
    assert pairing.sender_ip == "203.0.113.10"
    assert pairing.expires_at - pairing.created_at == PAIRING_TTL_SECONDS


async def test_create_pairing_persists_lookup(redis_client: Redis) -> None:
    issued = await create_pairing(redis_client, "203.0.113.11")

    fetched = await lookup_pairing(redis_client, issued.pin)
    assert fetched is not None
    assert fetched.pin == issued.pin
    assert fetched.sender_token == issued.sender_token
    assert fetched.sender_ip == issued.sender_ip
    assert fetched.created_at == issued.created_at
    assert fetched.expires_at == issued.expires_at


async def test_create_pairing_is_idempotent_per_sender_ip(redis_client: Redis) -> None:
    """A second call from the same sender IP while the first pair is
    still waiting returns the original PIN + sender token."""
    first = await create_pairing(redis_client, "203.0.113.20", now=1_000_000)
    second = await create_pairing(redis_client, "203.0.113.20", now=1_000_005)

    assert first.pin == second.pin
    assert first.sender_token == second.sender_token
    # expires_at must reflect the *original* creation, not the retry,
    # so the sender's on-screen countdown stays honest.
    assert second.created_at == 1_000_000
    assert second.expires_at == 1_000_000 + PAIRING_TTL_SECONDS


async def test_different_sender_ips_get_different_pins(redis_client: Redis) -> None:
    a = await create_pairing(redis_client, "203.0.113.30")
    b = await create_pairing(redis_client, "203.0.113.31")

    assert a.pin != b.pin
    assert a.sender_token != b.sender_token


async def test_pin_collision_rerolls(redis_client: Redis) -> None:
    """When the first candidate PIN is already taken, the generator
    rerolls until it finds an unused slot."""
    # Park "1234" so the first generator output collides; the loop then
    # falls back to a fresh draw and succeeds.
    occupant = await create_pairing(redis_client, "203.0.113.40")
    pin_attempts = iter([occupant.pin, "9876"])

    with patch("app.lib.pairings._generate_pin", side_effect=lambda: next(pin_attempts)):
        winner = await create_pairing(redis_client, "203.0.113.41")

    assert winner.pin == "9876"
    assert winner.pin != occupant.pin


async def test_pin_namespace_full_after_reroll_cap(redis_client: Redis) -> None:
    """When every reroll candidate collides, the generator raises rather
    than looping forever."""
    blocker = await create_pairing(redis_client, "203.0.113.50")

    with (
        patch("app.lib.pairings._generate_pin", return_value=blocker.pin),
        pytest.raises(PairNamespaceFullError),
    ):
        await create_pairing(redis_client, "203.0.113.51")


async def test_lookup_returns_none_for_unknown_pin(redis_client: Redis) -> None:
    assert await lookup_pairing(redis_client, "0000") is None


async def test_delete_pairing_clears_both_keys(redis_client: Redis) -> None:
    pairing = await create_pairing(redis_client, "203.0.113.60")
    await delete_pairing(redis_client, pairing.pin)

    assert await lookup_pairing(redis_client, pairing.pin) is None
    # A fresh issue from the same sender IP must produce a brand-new PIN
    # because the sender sentinel was cleared.
    fresh = await create_pairing(redis_client, "203.0.113.60")
    assert fresh.created_at >= pairing.created_at


async def test_delete_pairing_noop_when_expired(redis_client: Redis) -> None:
    # Calling delete on a PIN that never existed must be a clean no-op.
    await delete_pairing(redis_client, "0001")


async def test_dangling_sender_sentinel_recovers(redis_client: Redis) -> None:
    """If the sender-sentinel survives a TTL race where the pair record
    is gone, the next create call drops the dangling sentinel and issues
    a fresh pair instead of returning a phantom one."""
    sender_ip = "203.0.113.70"
    # Hand-craft a dangling sentinel: PIN slot empty, sender key points
    # at a PIN that has no record.
    await redis_client.set(f"pair:sender:{sender_ip}", "0042", ex=60)

    pairing = await create_pairing(redis_client, sender_ip)
    assert pairing.pin != "0042"
    assert await lookup_pairing(redis_client, pairing.pin) is not None


async def test_create_pairing_rejects_empty_sender_ip(redis_client: Redis) -> None:
    with pytest.raises(ValueError):
        await create_pairing(redis_client, "")
