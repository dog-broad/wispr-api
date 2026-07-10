from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db import get_session
from app.lib.auth import (
    SESSION_COOKIE_NAME,
    clear_session_cookie,
    create_session,
    device_label_from_request,
    enforce_origin,
    set_session_cookie,
)
from app.lib.clientip import extract_client_ip
from app.lib.email import EmailMessage, EmailTransport, get_email_transport
from app.lib.ratelimit import consume_magic_link_email, magic_link_ip_limit
from app.lib.tokens import generate_opaque_token, hash_token
from app.lib.turnstile import verify_turnstile
from app.models.accounts import Invite, MagicLinkPurpose, MagicLinkToken, Session, User
from app.redis_client import get_redis
from app.schemas.auth import (
    MagicLinkResponse,
    RequestMagicLinkRequest,
    VerifyResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])

DbSession = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
RedisDep = Annotated[Redis, Depends(get_redis)]
EmailDep = Annotated[EmailTransport, Depends(get_email_transport)]

MAGIC_LINK_TTL = timedelta(minutes=15)


def _http_client(request: Request) -> httpx.AsyncClient:
    client: httpx.AsyncClient = request.app.state.http_client
    return client


HttpClient = Annotated[httpx.AsyncClient, Depends(_http_client)]


@router.post(
    "/request-magic-link",
    response_model=MagicLinkResponse,
    dependencies=[Depends(magic_link_ip_limit)],
)
async def request_magic_link(
    body: RequestMagicLinkRequest,
    request: Request,
    db: DbSession,
    settings: SettingsDep,
    http_client: HttpClient,
    email_transport: EmailDep,
    redis_client: RedisDep,
) -> MagicLinkResponse | JSONResponse:
    """Request a magic link. Always returns ``{ok: true}`` regardless of
    whether the email maps to an account or the invite is valid — the only
    observable difference is whether an email actually arrives. Existing
    accounts get a sign-in link; a valid unused invite for a new email gets a
    sign-up link; anything else is a silent no-op."""
    enforce_origin(request)

    ip = extract_client_ip(request)
    if not await verify_turnstile(
        token=body.turnstile_token,
        remote_ip=ip,
        secret=settings.turnstile_secret_key,
        client=http_client,
    ):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "human verification failed"},
        )

    # Per-email throttle. On exhaustion stay silent (still 200) so a 429 can't
    # be used to probe which addresses are being targeted.
    email_budget = await consume_magic_link_email(redis_client, body.email)
    if not email_budget.allowed:
        return MagicLinkResponse()

    token_row = await _build_token(db, body.email, body.invite_code, ip)
    if token_row is None:
        # Unknown email with no valid invite: nothing to sign into and no
        # invitation to accept. Silent success.
        return MagicLinkResponse()

    raw_token = generate_opaque_token()
    token_row.token_hash = hash_token(raw_token)
    token_row.expires_at = datetime.now(tz=UTC) + MAGIC_LINK_TTL
    db.add(token_row)
    await db.commit()

    link = f"{settings.app_base_url}/auth/verify?token={raw_token}"
    await email_transport.send(
        EmailMessage(
            to=body.email,
            subject="Your Wispr sign-in link",
            text_body=(
                f"Click to continue signing in to Wispr:\n\n{link}\n\n"
                "This link works once and expires in 15 minutes. "
                "If you didn't request it, you can ignore this email."
            ),
        )
    )
    return MagicLinkResponse()


async def _build_token(
    db: AsyncSession, email: str, invite_code: str | None, ip: str
) -> MagicLinkToken | None:
    """Decide which kind of link (if any) this request earns. A live account
    gets a sign-in link; otherwise a valid unused invite gets a sign-up link;
    otherwise nothing."""
    user = await db.scalar(select(User).where(User.email == email, User.deleted_at.is_(None)))
    if user is not None:
        return MagicLinkToken(
            user_id=user.id,
            email=email,
            purpose=MagicLinkPurpose.sign_in,
            request_ip=ip,
        )
    if invite_code is not None:
        invite = await db.scalar(
            select(Invite).where(Invite.code == invite_code, Invite.used_by.is_(None))
        )
        if invite is not None:
            return MagicLinkToken(
                email=email,
                purpose=MagicLinkPurpose.sign_up,
                invite_id=invite.id,
                request_ip=ip,
            )
    return None


def _invalid_link() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"reason": "invalid_or_expired"},
    )


@router.get(
    "/verify",
    response_model=VerifyResponse,
    responses={status.HTTP_400_BAD_REQUEST: {"description": "Link invalid or expired"}},
)
async def verify(
    token: str,
    request: Request,
    db: DbSession,
    settings: SettingsDep,
) -> Response:
    """Consume a magic link: create the account on first sign-up, start a
    session, and set the cookie. Single-use and time-limited; a spent or
    expired token returns 400 so the client can show the expired-link state."""
    token_row = await db.scalar(
        select(MagicLinkToken).where(
            MagicLinkToken.token_hash == hash_token(token),
            MagicLinkToken.consumed_at.is_(None),
        )
    )
    if token_row is None or token_row.expires_at <= datetime.now(tz=UTC):
        return _invalid_link()

    token_row.consumed_at = datetime.now(tz=UTC)

    if token_row.purpose is MagicLinkPurpose.sign_in:
        user = await _resolve_signin(db, token_row)
    elif token_row.purpose is MagicLinkPurpose.sign_up:
        user = await _redeem_signup(db, token_row)
    else:
        raise NotImplementedError("change_email verification ships with the change-email flow")

    if user is None:
        return _invalid_link()

    await db.commit()

    raw_session = await create_session(
        db, user_id=user.id, device_label=device_label_from_request(request)
    )
    response: Response = JSONResponse(
        content=VerifyResponse(
            email=user.email,
            needs_passphrase_setup=user.auth_credential_hash is None,
        ).model_dump()
    )
    set_session_cookie(response, raw_session, settings)
    return response


async def _resolve_signin(db: AsyncSession, token_row: MagicLinkToken) -> User | None:
    if token_row.user_id is None:
        return None
    user: User | None = await db.scalar(
        select(User).where(User.id == token_row.user_id, User.deleted_at.is_(None))
    )
    return user


async def _redeem_signup(db: AsyncSession, token_row: MagicLinkToken) -> User | None:
    """Create the account for a sign-up link and consume its invite. Returns
    None if the invite is missing or already used (race), or if the email was
    claimed by another signup in the meantime."""
    if token_row.invite_id is None:
        return None
    invite = await db.scalar(
        select(Invite).where(Invite.id == token_row.invite_id, Invite.used_by.is_(None))
    )
    if invite is None:
        return None
    user = User(email=token_row.email, invited_by=invite.created_by)
    db.add(user)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return None
    invite.used_by = user.id
    invite.used_at = datetime.now(tz=UTC)
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    db: DbSession,
    settings: SettingsDep,
) -> Response:
    """Invalidate the current session and clear the cookie. Idempotent — a
    missing or unknown cookie still returns 204."""
    enforce_origin(request)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_token:
        await db.execute(delete(Session).where(Session.token_hash == hash_token(raw_token)))
        await db.commit()
    clear_session_cookie(response, settings)
    return response
