from __future__ import annotations

import asyncio

import pytest
from redis.asyncio import Redis

from app.lib.ratelimit import consume_token


@pytest.mark.parametrize("capacity", [5])
async def test_consume_token_returns_remaining(redis_client: Redis, capacity: int) -> None:
    key = "rl:test:returns_remaining"

    first = await consume_token(redis_client, key, capacity=capacity, period_seconds=60)
    assert first.allowed is True
    assert first.remaining == capacity - 1

    second = await consume_token(redis_client, key, capacity=capacity, period_seconds=60)
    assert second.allowed is True
    assert second.remaining == capacity - 2


async def test_consume_token_blocks_when_bucket_empty(redis_client: Redis) -> None:
    key = "rl:test:blocks_when_empty"

    # Exhaust a small bucket with a long refill window so the next call
    # cannot recover by sneaking under a refill tick.
    for _ in range(3):
        ok = await consume_token(redis_client, key, capacity=3, period_seconds=3600)
        assert ok.allowed is True

    blocked = await consume_token(redis_client, key, capacity=3, period_seconds=3600)
    assert blocked.allowed is False
    assert blocked.retry_after_seconds >= 1


async def test_consume_token_refills_after_window(redis_client: Redis) -> None:
    """With capacity 1 and period 1s the bucket refills a token every
    second; sleeping a touch over a second should unblock a new call."""
    key = "rl:test:refills_after_window"

    first = await consume_token(redis_client, key, capacity=1, period_seconds=1)
    assert first.allowed is True

    blocked = await consume_token(redis_client, key, capacity=1, period_seconds=1)
    assert blocked.allowed is False

    await asyncio.sleep(1.2)
    refilled = await consume_token(redis_client, key, capacity=1, period_seconds=1)
    assert refilled.allowed is True


async def test_consume_token_validates_inputs(redis_client: Redis) -> None:
    with pytest.raises(ValueError):
        await consume_token(redis_client, "rl:test:bad", capacity=0, period_seconds=10)
    with pytest.raises(ValueError):
        await consume_token(redis_client, "rl:test:bad", capacity=10, period_seconds=0)


# ---------------------------------------------------------------------------
# End-to-end: the snippets routes return 429 once the per-IP budget is gone
# ---------------------------------------------------------------------------


import base64  # noqa: E402


def _link_body() -> dict[str, object]:
    return {
        "share_mode": "link",
        "content_type": "text",
        "ciphertext": base64.b64encode(b"\xde\xad\xbe\xef").decode(),
        "encrypted_metadata": base64.b64encode(b"meta").decode(),
        "ttl_seconds": 300,
        "max_reads": 1,
    }


async def test_create_endpoint_429s_when_budget_exhausted(
    rate_limit_client: object,  # AsyncClient — typed loose to avoid an import cycle
) -> None:
    """POST /snippets is capped at 20/hr/IP. Hammer it past 20 and the
    21st request must come back 429 with a Retry-After header."""
    from httpx import AsyncClient  # local to keep top-of-file imports tidy

    client: AsyncClient = rate_limit_client  # type: ignore[assignment]
    ip = "203.0.113.99"

    # Burn the budget. Some of these may legitimately fail under heavy
    # contention, but with a single client and a fresh bucket all should
    # land 201.
    successes = 0
    for _ in range(20):
        resp = await client.post(
            "/snippets",
            json=_link_body(),
            headers={"CF-Connecting-IP": ip},
        )
        if resp.status_code == 201:
            successes += 1
        else:
            break
    assert successes == 20

    overflow = await client.post(
        "/snippets",
        json=_link_body(),
        headers={"CF-Connecting-IP": ip},
    )
    assert overflow.status_code == 429
    assert "retry-after" in {k.lower() for k in overflow.headers}


async def test_buckets_are_per_ip(rate_limit_client: object) -> None:
    """A different CF-Connecting-IP gets its own bucket and is unaffected
    by another IP's exhaustion."""
    from httpx import AsyncClient

    client: AsyncClient = rate_limit_client  # type: ignore[assignment]

    # First IP: burn through the budget.
    busy_ip = "203.0.113.50"
    for _ in range(20):
        resp = await client.post(
            "/snippets", json=_link_body(), headers={"CF-Connecting-IP": busy_ip}
        )
        assert resp.status_code in (201, 429)
    blocked = await client.post(
        "/snippets", json=_link_body(), headers={"CF-Connecting-IP": busy_ip}
    )
    assert blocked.status_code == 429

    # Different IP: should still be allowed.
    quiet_ip = "203.0.113.51"
    free = await client.post(
        "/snippets", json=_link_body(), headers={"CF-Connecting-IP": quiet_ip}
    )
    assert free.status_code == 201
