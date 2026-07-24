from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.lib.killswitch import get_switch
from app.models.admin import KillSwitchName
from app.redis_client import get_redis
from app.schemas.admin import MaintenanceState

router = APIRouter()


class HealthResponse(BaseModel):
    status: str


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/maintenance", response_model=MaintenanceState)
async def maintenance(
    session: Annotated[AsyncSession, Depends(get_session)],
    redis_client: Annotated[Redis, Depends(get_redis)],
) -> MaintenanceState:
    """Public: whether the operator has put the site in maintenance mode, plus
    the banner text. The web polls this to show a site-wide banner. Cached 30 s."""
    enabled, message = await get_switch(
        redis_client, session, KillSwitchName.maintenance_mode.value
    )
    return MaintenanceState(enabled=enabled, message=message)
