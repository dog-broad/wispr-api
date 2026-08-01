from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.asyncio import Redis

from app.lib.clientip import extract_client_ip
from app.lib.pairings import PairNamespaceFullError, create_pairing
from app.lib.ratelimit import pair_create_limit
from app.redis_client import get_redis
from app.schemas.pair import CreatePairResponse

router = APIRouter(prefix="/pair", tags=["pair"])

_RedisDep = Annotated[Redis, Depends(get_redis)]


@router.post(
    "",
    status_code=status.HTTP_200_OK,
    response_model=CreatePairResponse,
    dependencies=[Depends(pair_create_limit)],
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "Sender IP unavailable"},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "PIN namespace full"},
    },
)
async def create_pair(request: Request, redis_client: _RedisDep) -> CreatePairResponse:
    """Open a Mode 3 (Pair) waiting slot.

    Issues a 4-digit PIN + opaque sender token. A repeat call from the
    same sender IP while a previous pair is still in its 60-second
    waiting window returns that same pair unchanged (one active waiting
    pair per sender IP), so the on-screen countdown stays
    honest instead of silently resetting.
    """
    sender_ip = extract_client_ip(request)
    if not sender_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="sender ip unavailable",
        )

    try:
        pairing = await create_pairing(redis_client, sender_ip)
    except PairNamespaceFullError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="pair namespace full",
        ) from exc

    return CreatePairResponse(
        pin=pairing.pin,
        sender_token=pairing.sender_token,
        expires_at=datetime.fromtimestamp(pairing.expires_at, tz=UTC),
    )
