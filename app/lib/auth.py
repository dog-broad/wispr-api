from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db import get_session
from app.lib.tokens import generate_opaque_token, hash_token
from app.models.accounts import Session, User

SESSION_COOKIE_NAME = "wispr_session"
# 30 days, rolling.
SESSION_MAX_AGE_SECONDS = 2_592_000

_DEVICE_LABEL_MAX = 256


def set_session_cookie(response: Response, raw_token: str, settings: Settings) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        raw_token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        domain=settings.session_cookie_domain,
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        domain=settings.session_cookie_domain,
        path="/",
    )


def device_label_from_request(request: Request) -> str:
    """A human-readable device label for the session list. The raw User-Agent
    is the best signal we have without fingerprinting; truncate to the column
    width."""
    ua = request.headers.get("user-agent", "unknown device")
    return ua[:_DEVICE_LABEL_MAX]


async def create_session(
    db: AsyncSession, user_id: uuid.UUID, device_label: str
) -> str:
    """Create a session row and return the raw cookie token. Only the token's
    SHA-256 is stored server-side; the raw value lives only in the cookie."""
    raw_token = generate_opaque_token()
    db.add(
        Session(
            user_id=user_id,
            token_hash=hash_token(raw_token),
            device_label=device_label,
        )
    )
    await db.commit()
    return raw_token


DbSession = Annotated[AsyncSession, Depends(get_session)]


async def current_user(request: Request, db: DbSession) -> User:
    """Resolve the authenticated user from the session cookie, or 401.

    Rejects sessions whose user has been soft-deleted. Bumps ``last_seen_at``
    so the device list reflects recent activity.
    """
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    row = (
        await db.execute(
            select(Session, User)
            .join(User, Session.user_id == User.id)
            .where(Session.token_hash == hash_token(raw_token))
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    session_row: Session = row[0]
    user: User = row[1]
    if user.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    session_row.last_seen_at = datetime.now(tz=UTC)
    await db.commit()
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def is_allowed_origin(origin: str, settings: Settings) -> bool:
    if origin in settings.cors_allowed_origins:
        return True
    pattern = settings.cors_allowed_origin_regex
    return bool(pattern and re.match(pattern, origin))


def enforce_origin(request: Request) -> None:
    """CSRF defense-in-depth on state-changing routes: reject a cross-origin
    ``Origin``. Requests without an Origin header (same-origin navigations,
    server-to-server) are allowed — SameSite=Lax already blocks the cross-site
    cookie-bearing case this backstops."""
    origin = request.headers.get("origin")
    if origin is None:
        return
    if not is_allowed_origin(origin, get_settings()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="cross-origin request rejected"
        )
