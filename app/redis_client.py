from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Request
from redis.asyncio import Redis, from_url

from app.config import get_settings


async def open_redis() -> Redis:
    """Build the redis client used by the api. Called once on app startup
    and the connection is shared across requests; redis-py's connection
    pool handles concurrency."""
    settings = get_settings()
    return from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=False,
    )


async def close_redis(client: Redis) -> None:
    await client.aclose()


async def get_redis(request: Request) -> AsyncIterator[Redis]:
    """FastAPI dependency that hands handlers the app-wide client."""
    yield request.app.state.redis
