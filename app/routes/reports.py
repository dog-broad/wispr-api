from __future__ import annotations

import hashlib
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db import get_session
from app.lib.auth import OptionalUser
from app.lib.clientip import bucket_key, extract_client_ip
from app.lib.ratelimit import reports_limit
from app.lib.turnstile import verify_turnstile
from app.models.reports import Report
from app.models.snippets import ShareMode, Snippet
from app.redis_client import get_redis
from app.schemas.reports import CreateReportRequest, ReportAcceptedResponse

router = APIRouter(prefix="/reports", tags=["reports"])

DbSession = Annotated[AsyncSession, Depends(get_session)]
RedisDep = Annotated[Redis, Depends(get_redis)]
SettingsDep = Annotated[Settings, Depends(get_settings)]

# A Turnstile challenge becomes mandatory once an IP has filed this many reports
# within the counter's window. The hard 5/hr bucket (reports_limit) then stops
# the sixth.
_REPORT_TURNSTILE_AFTER = 3
_REPORT_COUNT_TTL_SECONDS = 3600


def _http_client(request: Request) -> httpx.AsyncClient:
    client: httpx.AsyncClient = request.app.state.http_client
    return client


HttpClient = Annotated[httpx.AsyncClient, Depends(_http_client)]


def _report_count_key(ip: str) -> str:
    # Keyed by the same /64-bucketed identity the hard limiter uses, so IPv6
    # address rotation within a prefix can't reset the challenge threshold.
    return f"reports:count:{bucket_key(ip)}"


async def _report_count(redis_client: Redis, ip: str) -> int:
    raw = await redis_client.get(_report_count_key(ip))
    return int(raw) if raw is not None else 0


async def _record_report(redis_client: Redis, ip: str) -> None:
    key = _report_count_key(ip)
    await redis_client.incr(key)
    await redis_client.expire(key, _REPORT_COUNT_TTL_SECONDS)


def _hash_reporter_ip(ip: str, pepper: str | None) -> str:
    """SHA-256 of the peppered IP. Stored only to rate-limit and de-duplicate
    reporters — never reversed. Reuses the deployment pepper (empty in dev)."""
    return hashlib.sha256(f"{pepper or ''}:{ip}".encode()).hexdigest()


@router.post("", status_code=status.HTTP_201_CREATED, response_model=None)
async def create_report(
    body: CreateReportRequest,
    request: Request,
    session: DbSession,
    user: OptionalUser,
    redis_client: RedisDep,
    settings: SettingsDep,
    http_client: HttpClient,
    _: Annotated[None, Depends(reports_limit)],
) -> ReportAcceptedResponse | JSONResponse:
    """File a takedown report against a PIN-share. Public — an anonymous
    receiver or a signed-in one may report. Above the per-IP hourly threshold a
    Turnstile token is required; the report must reference a live PIN-share."""
    ip = extract_client_ip(request)

    if await _report_count(redis_client, ip) >= _REPORT_TURNSTILE_AFTER:
        if not body.turnstile_token:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"reason": "turnstile_required"},
            )
        if not await verify_turnstile(
            token=body.turnstile_token,
            remote_ip=ip,
            secret=settings.turnstile_secret_key,
            client=http_client,
        ):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"reason": "turnstile_failed"},
            )

    # Only PIN shares are operator-reviewable, so a report always points at one.
    # A missing / non-Mode-2 id is rejected rather than stored as an
    # un-actionable row; the reporter already holds this id from resolving the
    # PIN, so a 404 leaks nothing.
    snippet_id = await session.scalar(
        select(Snippet.id).where(
            Snippet.id == body.snippet_id, Snippet.share_mode == ShareMode.pin_share
        )
    )
    if snippet_id is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"reason": "unknown_snippet"},
        )

    session.add(
        Report(
            snippet_id=snippet_id,
            reporter_ip=_hash_reporter_ip(ip, settings.server_pepper),
            reporter_user_id=user.id if user is not None else None,
            reason_category=body.reason_category,
            reason_text=body.reason_text,
        )
    )
    await session.commit()
    await _record_report(redis_client, ip)
    return ReportAcceptedResponse()
