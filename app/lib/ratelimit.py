from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, cast

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis

from app.lib.clientip import bucket_key, extract_client_ip
from app.redis_client import get_redis

# Atomic token-bucket check-and-decrement.
#
# KEYS[1] - the bucket hash key
# ARGV[1] - capacity (max tokens the bucket holds)
# ARGV[2] - refill rate, tokens per second (float)
# ARGV[3] - `now` in seconds (float)
# ARGV[4] - cost (tokens this request wants to consume; usually 1)
#
# Returns {allowed:int, remaining_tokens:int, retry_after_seconds:int}.
# A fresh bucket is born full; subsequent calls refill at `rate * elapsed`
# tokens since the previous call. EXPIRE bounds the worst-case key
# lifetime to the time required to refill a full bucket plus a minute of
# slack, so abandoned buckets do not leak.
_LUA_BUCKET_SCRIPT = """
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local data = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then
  tokens = capacity
  ts = now
end

local elapsed = math.max(0, now - ts)
tokens = math.min(capacity, tokens + elapsed * rate)

local allowed = 0
local retry_after = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  local deficit = cost - tokens
  retry_after = math.ceil(deficit / rate)
end

redis.call('HMSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', KEYS[1], math.ceil(capacity / rate) + 60)

return {allowed, math.floor(tokens), retry_after}
"""


@dataclass(frozen=True, slots=True)
class TokenBucketResult:
    allowed: bool
    remaining: int
    retry_after_seconds: int


async def consume_token(
    redis_client: Redis,
    key: str,
    capacity: int,
    period_seconds: int,
) -> TokenBucketResult:
    """Run the bucket script for one request worth of tokens.

    ``capacity`` is the burst ceiling; ``period_seconds`` is how long it
    takes for the bucket to refill from empty to full. The refill rate is
    derived as ``capacity / period_seconds`` tokens per second.
    """
    if capacity <= 0 or period_seconds <= 0:
        raise ValueError("capacity and period_seconds must be positive")
    rate = capacity / period_seconds
    # redis-py's async stubs declare .eval()'s return type as
    # `Awaitable[str] | str`, which is wrong for Lua scripts that return
    # a list. Cast the awaitable through Any so mypy stops fighting it.
    eval_call: object = redis_client.eval(
        _LUA_BUCKET_SCRIPT,
        1,
        key,
        capacity,
        rate,
        time.time(),
        1,
    )
    raw = cast(list[int], await cast(Awaitable[object], eval_call))
    allowed, remaining, retry_after = (int(raw[0]), int(raw[1]), int(raw[2]))
    return TokenBucketResult(
        allowed=allowed == 1,
        remaining=remaining,
        retry_after_seconds=retry_after,
    )


_RedisDep = Annotated[Redis, Depends(get_redis)]

RateLimitDependency = Callable[..., Awaitable[None]]


def rate_limit(capacity: int, period_seconds: int, scope: str) -> RateLimitDependency:
    """Build a FastAPI dependency that enforces a per-IP token-bucket limit.

    ``scope`` is the namespace inside the redis keyspace; pick something
    that describes the rate-limited *action* (e.g. ``"snippets-create"``)
    so multiple routes can share or split limits cleanly.

    On exhaustion the dependency raises 429 with ``Retry-After`` set to the
    number of seconds until at least one token will be available again.
    """

    async def _enforce(request: Request, redis_client: _RedisDep) -> None:
        ip = extract_client_ip(request)
        key = f"rl:{scope}:{bucket_key(ip)}"
        result = await consume_token(redis_client, key, capacity, period_seconds)
        if not result.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="rate limit exceeded",
                headers={"Retry-After": str(max(1, result.retry_after_seconds))},
            )

    _enforce.__name__ = f"rate_limit_{scope}"
    return _enforce


def burst_per_period(burst: int, period: str) -> tuple[int, int]:
    """Convenience for naming a limit the way the spec phrases them:
    ``burst_per_period(20, "hour")`` reads cleanly at the route
    declaration site."""
    seconds = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}[period]
    return burst, seconds


# Limit ceilings come from PROJECT.md §6 and §12. The rate_limit factory
# returns a fresh function per call, so we build them once at import time
# and let routes import the resulting dep — that gives tests a stable
# function object to plug into `app.dependency_overrides` if they want
# to bypass rate limiting (most do).
_SNIPPETS_CREATE_BURST, _SNIPPETS_CREATE_WINDOW = burst_per_period(20, "hour")
_SNIPPETS_GET_BURST, _SNIPPETS_GET_WINDOW = burst_per_period(30, "minute")
_PAIR_CREATE_BURST, _PAIR_CREATE_WINDOW = burst_per_period(30, "hour")

snippets_create_anon_limit = rate_limit(
    _SNIPPETS_CREATE_BURST, _SNIPPETS_CREATE_WINDOW, "snippets-create-anon"
)
snippets_get_limit = rate_limit(_SNIPPETS_GET_BURST, _SNIPPETS_GET_WINDOW, "snippets-get")
pair_create_limit = rate_limit(_PAIR_CREATE_BURST, _PAIR_CREATE_WINDOW, "pair-create")
