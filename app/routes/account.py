from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import CursorResult, delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.lib.auth import SESSION_COOKIE_NAME, CurrentUser
from app.lib.invites import generate_invite_code
from app.lib.tokens import hash_token
from app.models.accounts import Invite, Session
from app.schemas.account import InviteResponse, SessionInfo, SessionListResponse

router = APIRouter(prefix="/me", tags=["me"])

DbSession = Annotated[AsyncSession, Depends(get_session)]

_INVITE_RETRIES = 8


@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    user: CurrentUser, session: DbSession, request: Request
) -> SessionListResponse:
    """The caller's active devices, most-recently-seen first. The device the
    request's own cookie belongs to is flagged ``current``."""
    raw_token = request.cookies.get(SESSION_COOKIE_NAME) or ""
    current_hash = hash_token(raw_token)
    rows = list(
        await session.scalars(
            select(Session).where(Session.user_id == user.id).order_by(Session.last_seen_at.desc())
        )
    )
    return SessionListResponse(
        sessions=[
            SessionInfo(
                id=row.id,
                device_label=row.device_label,
                created_at=row.created_at,
                last_seen_at=row.last_seen_at,
                current=row.token_hash == current_hash,
            )
            for row in rows
        ]
    )


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(session_id: uuid.UUID, user: CurrentUser, session: DbSession) -> Response:
    """Sign out one device. Scoped to the caller's own sessions — a 404 both
    covers not-found and masks another user's session ids. Revoking the current
    device is allowed (the next request simply finds no session)."""
    result = await session.execute(
        delete(Session).where(Session.id == session_id, Session.user_id == user.id)
    )
    await session.commit()
    if isinstance(result, CursorResult) and result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/invites", response_model=InviteResponse)
async def create_invite(user: CurrentUser, session: DbSession) -> InviteResponse:
    """Mint a single-use invite code. Admin only — signup stays invite-gated."""
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin only")
    for _ in range(_INVITE_RETRIES):
        code = generate_invite_code()
        session.add(Invite(code=code, created_by=user.id))
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            continue
        return InviteResponse(code=code)
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="could not allocate an invite code; try again",
    )
