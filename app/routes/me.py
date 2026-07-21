from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.lib.auth import CurrentUser
from app.lib.pairings import lookup_pairing
from app.models.snippets import ShareMode, Snippet
from app.redis_client import get_redis
from app.schemas.snippets import RotatePinResponse

router = APIRouter(prefix="/me", tags=["me"])

DbSession = Annotated[AsyncSession, Depends(get_session)]
RedisDep = Annotated[Redis, Depends(get_redis)]

_PIN_RETRIES = 8


async def _owned_pin_share(session: AsyncSession, snippet_id: str, user_id: object) -> Snippet:
    """Load a PIN share owned by the caller, or 404. Ownership failures return
    404 (not 403) so the endpoint doesn't confirm a snippet exists to a
    non-owner."""
    snippet = await session.scalar(select(Snippet).where(Snippet.id == snippet_id))
    if (
        snippet is None
        or snippet.share_mode is not ShareMode.pin_share
        or snippet.owner_user_id != user_id
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if snippet.taken_down_at is not None:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="taken down")
    return snippet


@router.post("/snippets/{snippet_id}/rotate-pin", response_model=RotatePinResponse)
async def rotate_pin(
    snippet_id: str,
    user: CurrentUser,
    session: DbSession,
    redis_client: RedisDep,
) -> RotatePinResponse:
    """Issue a fresh PIN for an owned Mode 2 share; the old PIN stops resolving,
    the content stays. Resets the failed-attempt counter. The new PIN must be
    unique across live Mode 2 shares and live Mode 3 pairings."""
    await _owned_pin_share(session, snippet_id, user.id)

    for _ in range(_PIN_RETRIES):
        pin = f"{secrets.randbelow(10000):04d}"
        if await lookup_pairing(redis_client, pin) is not None:
            continue
        try:
            await session.execute(
                update(Snippet)
                .where(Snippet.id == snippet_id)
                .values(pin=pin, pin_failed_attempts=0)
            )
            await session.commit()
        except IntegrityError:
            await session.rollback()
            continue
        return RotatePinResponse(pin=pin)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="could not allocate a PIN; try again",
    )
