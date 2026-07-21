from __future__ import annotations

import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.lib.auth import OptionalUser
from app.lib.ids import new_snippet_id
from app.lib.keyvault import KeyVault, get_key_vault
from app.lib.pairings import lookup_pairing
from app.lib.ratelimit import (
    snippets_create_anon_limit,
    snippets_get_limit,
    verify_password_limit,
)
from app.lib.watch_bus import GoneEvent, ReadEvent
from app.lib.watch_bus import bus as watch_bus
from app.models.accounts import User
from app.models.snippets import ShareMode, Snippet
from app.redis_client import get_redis
from app.schemas.snippets import (
    CreateLinkSnippetRequest,
    CreatePinShareResponse,
    CreatePinShareSnippetRequest,
    CreateSnippetRequest,
    CreateSnippetResponse,
    GetSnippetResponse,
    GoneReason,
    GoneResponse,
    PasswordRequiredResponse,
    VerifyPasswordRequest,
)

RedisDep = Annotated[Redis, Depends(get_redis)]
KeyVaultDep = Annotated[KeyVault, Depends(get_key_vault)]

_PIN_RETRIES = 8

router = APIRouter(prefix="/snippets", tags=["snippets"])

DbSession = Annotated[AsyncSession, Depends(get_session)]

# How many times to retry on a primary-key collision. 62^12 ≈ 3.2e21 IDs;
# even one collision is unlikely, but a tight retry budget keeps us honest
# about the bound if the alphabet ever shrinks.
_ID_RETRIES = 5


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=None,
    dependencies=[Depends(snippets_create_anon_limit)],
)
async def create_snippet(
    body: CreateSnippetRequest,
    session: DbSession,
    user: OptionalUser,
    redis_client: RedisDep,
    key_vault: KeyVaultDep,
) -> CreateSnippetResponse | CreatePinShareResponse:
    """Create a snippet. Link shares are anonymous; PIN shares are members-only
    (the discriminated body routes here either way)."""
    if isinstance(body, CreatePinShareSnippetRequest):
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="sign in to share by PIN"
            )
        return await _create_pin_share(session, redis_client, key_vault, user, body)
    return await _create_link(session, body)


async def _create_link(
    session: AsyncSession, body: CreateLinkSnippetRequest
) -> CreateSnippetResponse:
    expires_at = datetime.now(tz=UTC) + timedelta(seconds=body.ttl_seconds)

    last_error: IntegrityError | None = None
    for _ in range(_ID_RETRIES):
        snippet_id = new_snippet_id()
        snippet = Snippet(
            id=snippet_id,
            share_mode=ShareMode.link,
            content_type=body.content_type,
            encrypted_metadata=body.encrypted_metadata,
            ciphertext_inline=body.ciphertext,
            size_bytes=len(body.ciphertext),
            expires_at=expires_at,
            max_reads=body.max_reads,
            password_hash=body.password_hash,
            password_salt=body.password_salt,
        )
        session.add(snippet)
        try:
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            last_error = exc
            continue
        return CreateSnippetResponse(id=snippet_id, expires_at=expires_at)

    # Exhausted retry budget — surface the underlying error as 500 so the
    # operator notices an actual ID-space anomaly instead of seeing a
    # silent 5xx with no breadcrumbs.
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"could not generate a unique snippet id: {last_error}",
    )


async def _create_pin_share(
    session: AsyncSession,
    redis_client: Redis,
    key_vault: KeyVault,
    user: User,
    body: CreatePinShareSnippetRequest,
) -> CreatePinShareResponse:
    """Create a member PIN share. The client's raw content key is wrapped with
    the key-vault master before storage (Mode 2 is encryption-at-rest, not ZK).
    The 4-digit PIN must be unique across live Mode 2 shares (DB unique index)
    and live Mode 3 pairings (Redis)."""
    expires_at = datetime.now(tz=UTC) + timedelta(seconds=body.ttl_seconds)
    wrapped, iv, key_version = key_vault.wrap(body.content_key)

    for _ in range(_PIN_RETRIES):
        pin = f"{secrets.randbelow(10000):04d}"
        # Cross-mode collision: never mint a PIN that's a live pair handshake.
        if await lookup_pairing(redis_client, pin) is not None:
            continue
        snippet = Snippet(
            id=new_snippet_id(),
            share_mode=ShareMode.pin_share,
            content_type=body.content_type,
            encrypted_metadata=body.encrypted_metadata,
            ciphertext_inline=body.ciphertext,
            size_bytes=len(body.ciphertext),
            pin=pin,
            encrypted_content_key=wrapped,
            content_key_iv=iv,
            key_version=key_version,
            owner_user_id=user.id,
            expires_at=expires_at,
            max_reads=body.max_reads,
            password_hash=body.password_hash,
            password_salt=body.password_salt,
        )
        session.add(snippet)
        try:
            await session.commit()
        except IntegrityError:
            # PIN or id collided against a live row — reroll both.
            await session.rollback()
            continue
        return CreatePinShareResponse(id=snippet.id, pin=pin, expires_at=expires_at)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="could not allocate a PIN; try again",
    )


@router.get(
    "/{snippet_id}",
    response_model=GetSnippetResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": PasswordRequiredResponse,
            "description": "Snippet is password-protected — call verify-password with the hash",
        },
        status.HTTP_404_NOT_FOUND: {"description": "Snippet ID does not exist"},
        status.HTTP_410_GONE: {
            "model": GoneResponse,
            "description": "Snippet existed but is expired, burned, or taken down",
        },
    },
    dependencies=[Depends(snippets_get_limit)],
)
async def get_snippet(
    snippet_id: str,
    session: DbSession,
) -> GetSnippetResponse | JSONResponse:
    """Fetch a snippet's ciphertext, burning one read.

    Password-protected snippets short-circuit to 401 before the read-
    count CAS so wrong passwords don't burn the snippet (see
    [D-260526-01]); the burn happens inside ``verify_password`` instead.
    """
    snippet = await _load_snippet(session, snippet_id)
    if snippet is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    # Terminal states bypass the password gate — the snippet is gone
    # regardless of whether the caller knows the password.
    gone_reason = _gone_reason_or_none(snippet)
    if gone_reason is not None:
        return JSONResponse(
            status_code=status.HTTP_410_GONE,
            content=GoneResponse(reason=gone_reason).model_dump(mode="json"),
        )

    if snippet.password_hash is not None and snippet.password_salt is not None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=PasswordRequiredResponse(
                password_salt=snippet.password_salt,
            ).model_dump(mode="json"),
        )

    return await _burn_and_render(session, snippet_id)


@router.post(
    "/{snippet_id}/verify-password",
    response_model=GetSnippetResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "Snippet is not password-protected"},
        status.HTTP_401_UNAUTHORIZED: {"description": "Password did not match"},
        status.HTTP_404_NOT_FOUND: {"description": "Snippet ID does not exist"},
        status.HTTP_410_GONE: {
            "model": GoneResponse,
            "description": "Snippet existed but is expired, burned, or taken down",
        },
    },
    dependencies=[Depends(verify_password_limit)],
)
async def verify_password(
    snippet_id: str,
    body: VerifyPasswordRequest,
    session: DbSession,
) -> GetSnippetResponse | JSONResponse:
    """Validate a password attempt for a gated snippet.

    On match, atomically bumps ``read_count`` and returns the ciphertext
    — same shape as the unprotected ``GET /snippets/{id}``. Wrong
    attempts don't touch ``read_count`` so the rate-limited brute-forcer
    is the only thing that burns through their attempt budget.
    """
    snippet = await _load_snippet(session, snippet_id)
    if snippet is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    gone_reason = _gone_reason_or_none(snippet)
    if gone_reason is not None:
        return JSONResponse(
            status_code=status.HTTP_410_GONE,
            content=GoneResponse(reason=gone_reason).model_dump(mode="json"),
        )

    if snippet.password_hash is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="this snippet is not password-protected",
        )

    if not hmac.compare_digest(snippet.password_hash, body.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    return await _burn_and_render(session, snippet_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _load_snippet(session: AsyncSession, snippet_id: str) -> Snippet | None:
    result: Snippet | None = await session.scalar(select(Snippet).where(Snippet.id == snippet_id))
    return result


def _gone_reason_or_none(snippet: Snippet) -> GoneReason | None:
    """Same predicate as the CAS uses, but for a pre-fetched row. Order
    matters: take-down by the operator outranks natural expiry which
    outranks burn-out — the reasons are mutually exclusive in practice
    but the order is the priority we surface."""
    if snippet.taken_down_at is not None:
        return GoneReason.taken_down
    now = datetime.now(tz=UTC)
    if snippet.expires_at is not None and snippet.expires_at <= now:
        return GoneReason.expired
    if snippet.max_reads is not None and snippet.read_count >= snippet.max_reads:
        return GoneReason.burned
    return None


async def _burn_and_render(
    session: AsyncSession, snippet_id: str
) -> GetSnippetResponse | JSONResponse:
    """Atomic CAS: increment read_count only if the row is still
    readable. Used by both the unprotected GET and the verify-password
    success path so the burn semantics stay identical regardless of
    which entry point landed the request."""
    update_stmt = text(
        """
        UPDATE snippets
        SET read_count = read_count + 1
        WHERE id = :id
          AND taken_down_at IS NULL
          AND (expires_at IS NULL OR expires_at > now())
          AND (max_reads IS NULL OR read_count < max_reads)
        RETURNING id
        """
    )
    result = await session.execute(update_stmt, {"id": snippet_id})
    updated_id = result.scalar_one_or_none()

    # The raw SQL UPDATE just bypassed the ORM identity map. The session
    # is configured with ``expire_on_commit=False``, so any Snippet
    # instance the request already loaded (e.g. the password check at
    # the top of the GET handler) would survive the commit below with
    # its pre-bump ``read_count``. A later ``SELECT`` would then return
    # that stale instance instead of re-hydrating from the post-update
    # row, and the watch-bus ReadEvent + burn check downstream would
    # both fire with stale numbers. Expire now so any re-load reflects
    # the DB.
    session.expire_all()

    if updated_id is None:
        # CAS failed between the load and the burn — race with another
        # reader or with the purge job. Re-load to pick the most
        # specific gone-reason.
        existing = await _load_snippet(session, snippet_id)
        if existing is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        reason = _gone_reason_or_none(existing) or GoneReason.burned
        return JSONResponse(
            status_code=status.HTTP_410_GONE,
            content=GoneResponse(reason=reason).model_dump(mode="json"),
        )

    await session.commit()
    fresh = await _load_snippet(session, snippet_id)
    if fresh is None:
        # Vanishingly rare — the purge ran between commit and re-read.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    # Notify any /ws/snippet/{id}/watch subscribers. Publish the read
    # event first so live counters tick, then a gone event if this read
    # also burned the snippet — watchers receive both in order.
    await watch_bus.publish(
        ReadEvent(kind="read", snippet_id=fresh.id, read_count=fresh.read_count)
    )
    if fresh.max_reads is not None and fresh.read_count >= fresh.max_reads:
        await watch_bus.publish(GoneEvent(kind="gone", snippet_id=fresh.id, reason="burned"))

    return GetSnippetResponse(
        id=fresh.id,
        share_mode=fresh.share_mode,
        content_type=fresh.content_type,
        ciphertext=fresh.ciphertext_inline or b"",
        encrypted_metadata=fresh.encrypted_metadata,
        size_bytes=fresh.size_bytes,
        created_at=fresh.created_at,
        expires_at=fresh.expires_at,
        max_reads=fresh.max_reads,
        read_count=fresh.read_count,
    )
