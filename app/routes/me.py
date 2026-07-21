from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from redis.asyncio import Redis
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.lib.auth import CurrentUser
from app.lib.pairings import lookup_pairing
from app.models.snippets import ShareMode, Snippet
from app.redis_client import get_redis
from app.schemas.snippets import RotatePinResponse, SyncItem, SyncListResponse

router = APIRouter(prefix="/me", tags=["me"])

DbSession = Annotated[AsyncSession, Depends(get_session)]
RedisDep = Annotated[Redis, Depends(get_redis)]

_PIN_RETRIES = 8
_SYNC_PAGE_SIZE = 50


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


@router.get("/snippets", response_model=SyncListResponse)
async def list_sync_snippets(
    user: CurrentUser,
    session: DbSession,
    before: datetime | None = None,
) -> SyncListResponse:
    """The caller's Sync feed, newest first, 50/page. Keyset paginate by
    passing the previous page's ``next_before`` as ``?before=``."""
    stmt = select(Snippet).where(
        Snippet.owner_user_id == user.id, Snippet.share_mode == ShareMode.sync
    )
    if before is not None:
        stmt = stmt.where(Snippet.created_at < before)
    stmt = stmt.order_by(Snippet.created_at.desc()).limit(_SYNC_PAGE_SIZE + 1)
    rows = list(await session.scalars(stmt))

    has_more = len(rows) > _SYNC_PAGE_SIZE
    items = rows[:_SYNC_PAGE_SIZE]
    return SyncListResponse(
        items=[
            SyncItem(
                id=s.id,
                content_type=s.content_type,
                ciphertext=s.ciphertext_inline or b"",
                wrapped_dek=s.wrapped_dek or b"",
                wrapped_dek_iv=s.wrapped_dek_iv or b"",
                encrypted_metadata=s.encrypted_metadata,
                size_bytes=s.size_bytes,
                created_at=s.created_at,
            )
            for s in items
        ],
        next_before=items[-1].created_at if (has_more and items) else None,
    )


async def _delete_owned(session: AsyncSession, snippet_id: str, user_id: uuid.UUID) -> None:
    """Hard-delete a snippet the caller owns, or 404 (also masks existence
    from non-owners). Idempotent: a second call after deletion is a 404."""
    snippet = await session.scalar(select(Snippet).where(Snippet.id == snippet_id))
    if snippet is None or snippet.owner_user_id != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await session.execute(delete(Snippet).where(Snippet.id == snippet_id))
    await session.commit()


@router.delete("/snippets/{snippet_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_snippet(snippet_id: str, user: CurrentUser, session: DbSession) -> Response:
    """Hard-delete an owned snippet (Sync delete / PIN delete-now)."""
    await _delete_owned(session, snippet_id, user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/snippets/{snippet_id}/burn", status_code=status.HTTP_204_NO_CONTENT)
async def burn_snippet(snippet_id: str, user: CurrentUser, session: DbSession) -> Response:
    """Alias of delete as a POST action — hard-delete an owned snippet now."""
    await _delete_owned(session, snippet_id, user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
