from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.config import Settings, get_settings
from app.db import get_session
from app.lib.auth import (
    SESSION_COOKIE_NAME,
    CurrentUser,
    clear_session_cookie,
    create_session,
    device_label_from_request,
    enforce_origin,
    set_session_cookie,
)
from app.lib.clientip import extract_client_ip
from app.lib.credentials import hash_auth_credential, verify_auth_credential
from app.lib.email import EmailMessage, EmailTransport, get_email_transport
from app.lib.lockout import clear as clear_lockout
from app.lib.lockout import is_locked, register_failure
from app.lib.ratelimit import consume_magic_link_email, magic_link_ip_limit
from app.lib.tokens import generate_opaque_token, hash_token
from app.lib.turnstile import verify_turnstile
from app.models.accounts import Invite, MagicLinkPurpose, MagicLinkToken, Session, User
from app.models.snippets import ShareMode, Snippet
from app.redis_client import get_redis
from app.schemas.auth import (
    ChangePassphraseRequest,
    MagicLinkResponse,
    RequestMagicLinkRequest,
    SessionResponse,
    SetupPassphraseRequest,
    UnlockRequest,
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
    background: BackgroundTasks,
    email_transport: EmailDep,
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

    is_signin = token_row.purpose is MagicLinkPurpose.sign_in
    if is_signin:
        user = await _resolve_signin(db, token_row)
    elif token_row.purpose is MagicLinkPurpose.sign_up:
        user = await _redeem_signup(db, token_row)
    else:
        raise NotImplementedError("change_email verification ships with the change-email flow")

    if user is None:
        return _invalid_link()

    await db.commit()

    device_label = device_label_from_request(request)
    raw_session = await create_session(db, user_id=user.id, device_label=device_label)

    # Audit every sign-in (not the initial sign-up, which the invitee just
    # performed themselves). Sent in the background so email latency never
    # blocks the sign-in response.
    if is_signin:
        background.add_task(
            _send_signin_audit,
            email_transport,
            user.email,
            device_label,
            settings.app_base_url,
        )

    response: Response = JSONResponse(
        content=VerifyResponse(
            email=user.email,
            needs_passphrase_setup=user.auth_credential_hash is None,
        ).model_dump(),
        background=background,
    )
    set_session_cookie(response, raw_session, settings)
    return response


async def _send_signin_audit(
    email_transport: EmailTransport,
    to: str,
    device_label: str,
    app_base_url: str,
) -> None:
    # Coarse "who/when/what device" audit. Country enrichment is deferred until
    # a GeoIP source is wired; the device label (User-Agent) is the signal we
    # have without it. The timestamp is stamped at send time inside the task.
    when = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    await email_transport.send(
        EmailMessage(
            to=to,
            subject="New sign-in to Wispr",
            text_body=(
                f"You just signed in to Wispr at {when}.\n\n"
                f"Device: {device_label}\n\n"
                "If this wasn't you, sign in and remove the device from your "
                f"settings: {app_base_url}/me/settings"
            ),
        )
    )


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


@router.get("/session", response_model=SessionResponse)
async def session(user: CurrentUser) -> SessionResponse:
    """Current auth state plus the client PBKDF2 salts, so a returning tab can
    re-derive its keys. Salts are non-secret and returned only to the owner."""
    return SessionResponse(
        email=user.email,
        is_admin=user.is_admin,
        needs_passphrase_setup=user.auth_credential_hash is None,
        master_key_version=user.master_key_version,
        auth_credential_salt=user.auth_credential_salt,
        master_key_salt=user.master_key_salt,
    )


@router.post("/unlock")
async def unlock(
    body: UnlockRequest,
    user: CurrentUser,
    db: DbSession,
    settings: SettingsDep,
    background: BackgroundTasks,
    email_transport: EmailDep,
) -> Response:
    """Verify the passphrase for a returning session by checking the client
    auth token against the stored argon2id credential (204). Ten wrong attempts
    in 15 min lock the account for an hour (423) and fire a throttled alert;
    the master key is derived in the browser, the server only confirms."""
    if user.auth_credential_hash is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="passphrase not set")

    now = datetime.now(tz=UTC)
    if await is_locked(db, user.id, now):
        return JSONResponse(status_code=status.HTTP_423_LOCKED, content={"reason": "locked"})

    ok = await run_in_threadpool(
        verify_auth_credential,
        user.auth_credential_hash,
        body.auth_token,
        settings.server_pepper,
    )
    if ok:
        await clear_lockout(db, user.id, now)
        await db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    result = await register_failure(db, user.id, now)
    await db.commit()
    if result.send_email:
        background.add_task(_send_lockout_audit, email_transport, user.email, settings.app_base_url)
    reason = "locked" if result.locked else "wrong_passphrase"
    code = status.HTTP_423_LOCKED if result.locked else status.HTTP_401_UNAUTHORIZED
    return JSONResponse(status_code=code, content={"reason": reason}, background=background)


async def _send_lockout_audit(email_transport: EmailTransport, to: str, app_base_url: str) -> None:
    await email_transport.send(
        EmailMessage(
            to=to,
            subject="Your Wispr account was locked",
            text_body=(
                "Your Wispr account was locked for one hour after 10 failed "
                "passphrase attempts.\n\n"
                "If this was you, just wait and try again. If it wasn't, sign in "
                f"and review your devices: {app_base_url}/me/settings"
            ),
        )
    )


@router.post("/setup-passphrase", status_code=status.HTTP_204_NO_CONTENT)
async def setup_passphrase(
    body: SetupPassphraseRequest,
    user: CurrentUser,
    db: DbSession,
    settings: SettingsDep,
) -> Response:
    """First-time passphrase setup. Stores the two client PBKDF2 salts and
    argon2id(auth_token, pepper); the passphrase and master key never reach the
    server. Rejects if a passphrase is already set (409)."""
    if user.auth_credential_hash is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="passphrase already set")
    user.auth_credential_salt = body.auth_credential_salt
    user.master_key_salt = body.master_key_salt
    user.auth_credential_hash = await run_in_threadpool(
        hash_auth_credential, body.auth_token, settings.server_pepper
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/change-passphrase", status_code=status.HTTP_204_NO_CONTENT)
async def change_passphrase(
    body: ChangePassphraseRequest,
    user: CurrentUser,
    db: DbSession,
    settings: SettingsDep,
    background: BackgroundTasks,
    email_transport: EmailDep,
) -> Response:
    """Change the passphrase in one atomic transaction: re-auth with the
    current auth token, then swap both PBKDF2 salts + the argon2id credential,
    bump ``master_key_version``, and replace every owned Sync item's
    ``wrapped_dek`` with the client's re-wrapped value.

    Changing ``master_key_salt`` makes the old KEK unrecoverable, so the rewrap
    set must cover the caller's exact current Sync items (409 if it drifted) —
    otherwise a missed item would be stranded undecryptable. Wrong current
    passphrase counts toward the same lockout as unlock so this can't be used to
    brute-force."""
    if user.auth_credential_hash is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="passphrase not set")

    now = datetime.now(tz=UTC)
    if await is_locked(db, user.id, now):
        return JSONResponse(status_code=status.HTTP_423_LOCKED, content={"reason": "locked"})

    ok = await run_in_threadpool(
        verify_auth_credential,
        user.auth_credential_hash,
        body.current_auth_token,
        settings.server_pepper,
    )
    if not ok:
        result = await register_failure(db, user.id, now)
        await db.commit()
        if result.send_email:
            background.add_task(
                _send_lockout_audit, email_transport, user.email, settings.app_base_url
            )
        reason = "locked" if result.locked else "wrong_passphrase"
        code = status.HTTP_423_LOCKED if result.locked else status.HTTP_401_UNAUTHORIZED
        return JSONResponse(status_code=code, content={"reason": reason}, background=background)

    # The rewrap must be complete: after the salt swap the old KEK is gone, so
    # any owned Sync item not re-wrapped here becomes permanently undecryptable.
    owned_ids = set(
        await db.scalars(
            select(Snippet.id).where(
                Snippet.owner_user_id == user.id, Snippet.share_mode == ShareMode.sync
            )
        )
    )
    provided_ids = {item.id for item in body.rewrapped}
    if provided_ids != owned_ids:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="rewrap set does not match current sync items; refetch and retry",
        )

    for item in body.rewrapped:
        await db.execute(
            update(Snippet)
            .where(
                Snippet.id == item.id,
                Snippet.owner_user_id == user.id,
                Snippet.share_mode == ShareMode.sync,
            )
            .values(wrapped_dek=item.wrapped_dek, wrapped_dek_iv=item.wrapped_dek_iv)
        )

    user.auth_credential_salt = body.new_auth_credential_salt
    user.master_key_salt = body.new_master_key_salt
    user.auth_credential_hash = await run_in_threadpool(
        hash_auth_credential, body.new_auth_token, settings.server_pepper
    )
    user.master_key_version += 1
    await clear_lockout(db, user.id, now)
    # Single commit: credential swap + version bump + all rewraps land together
    # or not at all.
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


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
