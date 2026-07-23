from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import CursorResult, delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db import get_session
from app.lib.auth import SESSION_COOKIE_NAME, CurrentUser
from app.lib.clientip import extract_client_ip
from app.lib.email import EmailMessage, EmailTransport, get_email_transport
from app.lib.invites import generate_invite_code
from app.lib.reauth import reauth
from app.lib.tokens import generate_opaque_token, hash_token
from app.models.accounts import (
    EmailChangeRequest,
    Invite,
    MagicLinkPurpose,
    MagicLinkToken,
    Session,
    User,
)
from app.schemas.account import InviteResponse, OkResponse, SessionInfo, SessionListResponse
from app.schemas.auth import ChangeEmailRequest

router = APIRouter(prefix="/me", tags=["me"])

DbSession = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
EmailDep = Annotated[EmailTransport, Depends(get_email_transport)]

_INVITE_RETRIES = 8
_EMAIL_CHANGE_TTL = timedelta(minutes=15)


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


@router.post("/change-email", response_model=None)
async def change_email(
    body: ChangeEmailRequest,
    request: Request,
    user: CurrentUser,
    session: DbSession,
    settings: SettingsDep,
    background: BackgroundTasks,
    email_transport: EmailDep,
) -> OkResponse | JSONResponse:
    """Start an email change: re-auth with the current passphrase, then mail a
    confirmation link to the new address and an alert to the old one. The change
    only takes effect when the link is clicked (GET /auth/verify). The new
    address must be free."""
    if user.auth_credential_hash is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="set a passphrase before changing your email",
        )
    now = datetime.now(tz=UTC)
    outcome = await reauth(session, user, body.current_auth_token, settings.server_pepper, now)
    if not outcome.ok:
        await session.commit()  # persist the failed-attempt / lockout counters
        if outcome.send_email:
            background.add_task(
                _send_lockout_alert, email_transport, user.email, settings.app_base_url
            )
        reason = "locked" if outcome.locked else "wrong_passphrase"
        code = status.HTTP_423_LOCKED if outcome.locked else status.HTTP_401_UNAUTHORIZED
        return JSONResponse(status_code=code, content={"reason": reason}, background=background)

    if body.new_email == user.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="that is already your email"
        )
    taken = await session.scalar(
        select(User.id).where(User.email == body.new_email, User.deleted_at.is_(None))
    )
    if taken is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="that email is already in use"
        )

    old_email = user.email
    raw_token = generate_opaque_token()
    token = MagicLinkToken(
        user_id=user.id,
        email=body.new_email,
        purpose=MagicLinkPurpose.change_email,
        new_email=body.new_email,
        token_hash=hash_token(raw_token),
        expires_at=now + _EMAIL_CHANGE_TTL,
        request_ip=extract_client_ip(request),
    )
    session.add(token)
    await session.flush()
    session.add(
        EmailChangeRequest(
            user_id=user.id,
            old_email=old_email,
            new_email=body.new_email,
            magic_link_token_id=token.id,
        )
    )
    await session.commit()

    link = f"{settings.app_base_url}/auth/verify?token={raw_token}"
    background.add_task(_send_change_confirm, email_transport, body.new_email, link)
    background.add_task(
        _send_change_alert, email_transport, old_email, body.new_email, settings.app_base_url
    )
    return OkResponse()


async def _send_change_confirm(transport: EmailTransport, to: str, link: str) -> None:
    await transport.send(
        EmailMessage(
            to=to,
            subject="Confirm your new Wispr email",
            text_body=(
                f"Click to confirm this address as your new Wispr email:\n\n{link}\n\n"
                "This link works once and expires in 15 minutes. If you didn't "
                "request it, you can ignore this email."
            ),
        )
    )


async def _send_change_alert(
    transport: EmailTransport, to: str, new_email: str, app_base_url: str
) -> None:
    await transport.send(
        EmailMessage(
            to=to,
            subject="A Wispr email change was requested",
            text_body=(
                f"Someone requested changing your Wispr email to {new_email}.\n\n"
                "The change only happens if the link sent to that address is "
                "clicked. If this wasn't you, sign in and review your devices: "
                f"{app_base_url}/me/settings"
            ),
        )
    )


async def _send_lockout_alert(transport: EmailTransport, to: str, app_base_url: str) -> None:
    await transport.send(
        EmailMessage(
            to=to,
            subject="Your Wispr account was locked",
            text_body=(
                "Your Wispr account was locked for one hour after 10 failed "
                "passphrase attempts.\n\nIf this wasn't you, sign in and review "
                f"your devices: {app_base_url}/me/settings"
            ),
        )
    )


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
