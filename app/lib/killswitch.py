from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.lib.audit import record_action
from app.models.admin import KillSwitch

# A missing row means the switch is off, so the read path is cheap: one Redis
# GET, and a DB lookup only on a 30 s cache miss. Values change rarely (an
# operator toggling a switch), so the short TTL keeps the hot create paths fast
# without letting a toggle take long to propagate.
_CACHE_TTL_SECONDS = 30
_KEY_PREFIX = "ks:"

ACTION_KILL_SWITCH_TOGGLED = "kill_switch.toggled"


def _cache_key(name: str) -> str:
    return f"{_KEY_PREFIX}{name}"


async def get_switch(redis: Redis, session: AsyncSession, name: str) -> tuple[bool, str | None]:
    """Return ``(enabled, message)`` for a switch, cache-first. A switch with no
    row is off with no message."""
    cached = await redis.get(_cache_key(name))
    if cached is not None:
        data = json.loads(cached)
        return bool(data["enabled"]), data.get("message")

    row = await session.scalar(select(KillSwitch).where(KillSwitch.name == name))
    state: tuple[bool, str | None] = (
        (row.enabled, row.message) if row is not None else (False, None)
    )
    await redis.set(
        _cache_key(name),
        json.dumps({"enabled": state[0], "message": state[1]}),
        ex=_CACHE_TTL_SECONDS,
    )
    return state


async def is_enabled(redis: Redis, session: AsyncSession, name: str) -> bool:
    enabled, _ = await get_switch(redis, session, name)
    return enabled


async def set_switch(
    session: AsyncSession,
    redis: Redis,
    *,
    name: str,
    enabled: bool,
    message: str | None,
    actor_id: uuid.UUID,
) -> tuple[bool, str | None]:
    """Upsert a switch, audit the toggle, and bust its cache. Commits."""
    row = await session.scalar(select(KillSwitch).where(KillSwitch.name == name))
    if row is None:
        row = KillSwitch(name=name)
        session.add(row)
    row.enabled = enabled
    row.message = message
    row.toggled_at = datetime.now(tz=UTC)
    row.toggled_by_user_id = actor_id
    await record_action(
        session,
        actor_id=actor_id,
        action=ACTION_KILL_SWITCH_TOGGLED,
        target_type="kill_switch",
        target_id=name,
        metadata={"enabled": enabled},
    )
    await session.commit()
    # Drop the cached value so the next read reflects the toggle immediately.
    await redis.delete(_cache_key(name))
    return enabled, message
