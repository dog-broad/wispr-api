from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from httpx import AsyncClient


async def test_post_pair_returns_pin_and_token(redis_only_client: AsyncClient) -> None:
    response = await redis_only_client.post(
        "/pair",
        headers={"CF-Connecting-IP": "203.0.113.110"},
    )
    assert response.status_code == 200
    body = response.json()

    assert isinstance(body["pin"], str)
    assert len(body["pin"]) == 4
    assert body["pin"].isdigit()
    assert isinstance(body["sender_token"], str)
    assert len(body["sender_token"]) == 43

    expires_at = datetime.fromisoformat(body["expires_at"])
    delta = expires_at - datetime.now(tz=UTC)
    # 60s waiting window; allow generous clock-skew slack for the test.
    assert timedelta(seconds=50) <= delta <= timedelta(seconds=70)


async def test_post_pair_is_idempotent_per_sender_ip(
    redis_only_client: AsyncClient,
) -> None:
    """Repeat POST /pair from the same sender IP returns the same PIN
    and the same expires_at (the original, not refreshed)."""
    ip = "203.0.113.120"
    first = await redis_only_client.post("/pair", headers={"CF-Connecting-IP": ip})
    second = await redis_only_client.post("/pair", headers={"CF-Connecting-IP": ip})

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["pin"] == second.json()["pin"]
    assert first.json()["sender_token"] == second.json()["sender_token"]
    assert first.json()["expires_at"] == second.json()["expires_at"]


async def test_post_pair_different_ips_get_different_pins(
    redis_only_client: AsyncClient,
) -> None:
    a = await redis_only_client.post("/pair", headers={"CF-Connecting-IP": "203.0.113.130"})
    b = await redis_only_client.post("/pair", headers={"CF-Connecting-IP": "203.0.113.131"})
    assert a.json()["pin"] != b.json()["pin"]


async def test_post_pair_429s_when_budget_exhausted(
    redis_only_rate_limit_client: AsyncClient,
) -> None:
    """30/hr/IP rate limit. The 31st request from the same IP
    inside the bucket window must come back 429 with Retry-After."""
    client = redis_only_rate_limit_client
    ip = "203.0.113.140"

    successes = 0
    for _ in range(30):
        resp = await client.post("/pair", headers={"CF-Connecting-IP": ip})
        if resp.status_code == 200:
            successes += 1
        else:
            break
    assert successes == 30

    overflow = await client.post("/pair", headers={"CF-Connecting-IP": ip})
    assert overflow.status_code == 429
    assert "retry-after" in {k.lower() for k in overflow.headers}


async def test_post_pair_400_when_sender_ip_missing(redis_only_client: AsyncClient) -> None:
    """When extract_client_ip yields the empty string (no header set and
    no peer address — unlikely in production but possible behind a
    misconfigured proxy), the route refuses to write a dangling
    pair:sender: key and returns 400 instead."""
    with patch("app.routes.pair.extract_client_ip", return_value=""):
        response = await redis_only_client.post("/pair")
    assert response.status_code == 400
