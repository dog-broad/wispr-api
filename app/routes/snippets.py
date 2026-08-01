from __future__ import annotations

import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db import get_session
from app.lib.auth import OptionalUser
from app.lib.clientip import extract_client_ip
from app.lib.ids import new_snippet_id
from app.lib.keyvault import KeyVault, get_key_vault
from app.lib.killswitch import is_enabled
from app.lib.pairings import lookup_pairing
from app.lib.ratelimit import (
    by_pin_hour_limit,
    by_pin_minute_limit,
    snippets_create_anon_limit,
    snippets_get_limit,
    verify_password_limit,
)
from app.lib.storage import ObjectStore, ObjectStoreDep
from app.lib.sync_bus import SnippetCreatedEvent
from app.lib.sync_bus import bus as sync_bus
from app.lib.turnstile import verify_turnstile
from app.lib.watch_bus import GoneEvent, ReadEvent
from app.lib.watch_bus import bus as watch_bus
from app.models.accounts import User
from app.models.snippets import ShareMode, Snippet
from app.redis_client import get_redis
from app.schemas.snippets import (
    ByPinRequest,
    CreateLinkSnippetRequest,
    CreatePinShareResponse,
    CreatePinShareSnippetRequest,
    CreateSnippetRequest,
    CreateSnippetResponse,
    CreateSyncResponse,
    CreateSyncSnippetRequest,
    GetSnippetResponse,
    GoneReason,
    GoneResponse,
    PairSignalResponse,
    PasswordRequiredResponse,
    PinResolveResponse,
    SyncItem,
    VerifyPasswordRequest,
)

RedisDep = Annotated[Redis, Depends(get_redis)]
KeyVaultDep = Annotated[KeyVault, Depends(get_key_vault)]
SettingsDep = Annotated[Settings, Depends(get_settings)]

_PIN_RETRIES = 8

# Turnstile kicks in after this many failed PIN attempts from one IP (§7.6.7 #15).
_BY_PIN_TURNSTILE_AFTER = 3
_BY_PIN_FAIL_TTL_SECONDS = 3600

# A Mode 2 share auto-invalidates after this many wrong password attempts,
# counted on the row across all IPs (§7.6.7 #7).
_MAX_PIN_FAILED_ATTEMPTS = 50


def _http_client(request: Request) -> httpx.AsyncClient:
    client: httpx.AsyncClient = request.app.state.http_client
    return client


HttpClient = Annotated[httpx.AsyncClient, Depends(_http_client)]


def _by_pin_fail_key(ip: str) -> str:
    return f"bypin:fails:{ip}"


async def _bypin_failures(redis_client: Redis, ip: str) -> int:
    raw = await redis_client.get(_by_pin_fail_key(ip))
    return int(raw) if raw is not None else 0


async def _record_bypin_failure(redis_client: Redis, ip: str) -> None:
    key = _by_pin_fail_key(ip)
    await redis_client.incr(key)
    await redis_client.expire(key, _BY_PIN_FAIL_TTL_SECONDS)


async def _reset_bypin_failures(redis_client: Redis, ip: str) -> None:
    await redis_client.delete(_by_pin_fail_key(ip))


def _pin_disabled() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_410_GONE,
        content=GoneResponse(reason=GoneReason.disabled).model_dump(mode="json"),
    )


async def _increment_pin_failures(session: AsyncSession, snippet_id: str) -> int:
    """Atomically bump the row's cross-IP wrong-attempt counter and return the
    new value, so a concurrent brute-force can't undercount toward the cap."""
    result = await session.execute(
        text(
            "UPDATE snippets SET pin_failed_attempts = pin_failed_attempts + 1 "
            "WHERE id = :id RETURNING pin_failed_attempts"
        ),
        {"id": snippet_id},
    )
    count = int(result.scalar_one())
    session.expire_all()  # raw UPDATE bypassed the ORM identity map
    await session.commit()
    return count


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
    store: ObjectStoreDep,
) -> CreateSnippetResponse | CreatePinShareResponse | CreateSyncResponse | JSONResponse:
    """Create a snippet. Link shares are anonymous; PIN and Sync are
    members-only (the discriminated body routes here either way)."""
    if isinstance(body, CreatePinShareSnippetRequest):
        if await is_enabled(redis_client, session, "mode2"):
            return _feature_disabled()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="sign in to share by PIN"
            )
        return await _create_pin_share(session, redis_client, key_vault, store, user, body)
    if isinstance(body, CreateSyncSnippetRequest):
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="sign in to save clips"
            )
        return await _create_sync(session, store, user, body)
    if await is_enabled(redis_client, session, "anon_link"):
        return _feature_disabled()
    return await _create_link(session, store, body)


def _feature_disabled() -> JSONResponse:
    """503 for a create paused by a kill switch. The client surfaces a plain
    'temporarily unavailable' message; existing shares are unaffected."""
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"reason": "feature_disabled"},
    )


class _ResolvedContent:
    """Where a snippet's bytes live: inline in the row, or as R2 chunk objects.
    Exactly one of ``inline`` / ``storage_object_key`` is set."""

    __slots__ = ("chunk_count", "inline", "size_bytes", "storage_object_key")

    def __init__(
        self,
        inline: bytes | None,
        storage_object_key: str | None,
        chunk_count: int | None,
        size_bytes: int,
    ) -> None:
        self.inline = inline
        self.storage_object_key = storage_object_key
        self.chunk_count = chunk_count
        self.size_bytes = size_bytes


async def _resolve_content(
    store: ObjectStore | None,
    *,
    ciphertext: bytes,
    storage_object_key: str | None,
    chunk_count: int | None,
) -> _ResolvedContent:
    """For a file upload, confirm every chunk object landed in R2 and total the
    stored size; for inline content, size is just the ciphertext length. The
    schema guarantees exactly one source is set."""
    if storage_object_key is None:
        return _ResolvedContent(ciphertext, None, None, len(ciphertext))
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="file uploads are not configured",
        )
    if chunk_count is None:  # guaranteed by the request schema; narrow for typing
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="chunk_count required")
    total = 0
    for index in range(chunk_count):
        size = await store.head_size(f"{storage_object_key}/{index}")
        if size is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"upload incomplete: chunk {index} not found",
            )
        total += size
    return _ResolvedContent(None, storage_object_key, chunk_count, total)


async def _create_link(
    session: AsyncSession, store: ObjectStore | None, body: CreateLinkSnippetRequest
) -> CreateSnippetResponse:
    expires_at = datetime.now(tz=UTC) + timedelta(seconds=body.ttl_seconds)
    content = await _resolve_content(
        store,
        ciphertext=body.ciphertext,
        storage_object_key=body.storage_object_key,
        chunk_count=body.chunk_count,
    )

    last_error: IntegrityError | None = None
    for _ in range(_ID_RETRIES):
        snippet_id = new_snippet_id()
        snippet = Snippet(
            id=snippet_id,
            share_mode=ShareMode.link,
            content_type=body.content_type,
            encrypted_metadata=body.encrypted_metadata,
            ciphertext_inline=content.inline,
            storage_object_key=content.storage_object_key,
            chunk_count=content.chunk_count,
            size_bytes=content.size_bytes,
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

    # Exhausted retry budget: surface the underlying error as 500 so the
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
    store: ObjectStore | None,
    user: User,
    body: CreatePinShareSnippetRequest,
) -> CreatePinShareResponse:
    """Create a member PIN share. The client's raw content key is wrapped with
    the key-vault master before storage (Mode 2 is encryption-at-rest, not ZK).
    The 4-digit PIN must be unique across live Mode 2 shares (DB unique index)
    and live Mode 3 pairings (Redis)."""
    expires_at = datetime.now(tz=UTC) + timedelta(seconds=body.ttl_seconds)
    wrapped, iv, key_version = key_vault.wrap(body.content_key)
    content = await _resolve_content(
        store,
        ciphertext=body.ciphertext,
        storage_object_key=body.storage_object_key,
        chunk_count=body.chunk_count,
    )

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
            ciphertext_inline=content.inline,
            storage_object_key=content.storage_object_key,
            chunk_count=content.chunk_count,
            size_bytes=content.size_bytes,
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
            # PIN or id collided against a live row: reroll both.
            await session.rollback()
            continue
        return CreatePinShareResponse(id=snippet.id, pin=pin, expires_at=expires_at)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="could not allocate a PIN; try again",
    )


async def _create_sync(
    session: AsyncSession,
    store: ObjectStore | None,
    user: User,
    body: CreateSyncSnippetRequest,
) -> CreateSyncResponse:
    """Create a Sync (Mode 4) item. Zero-knowledge: the server stores the
    wrapped DEK the client produced with its master KEK and never sees the DEK
    or the KEK. No TTL / max_reads: these are the owner's own clips."""
    content = await _resolve_content(
        store,
        ciphertext=body.ciphertext,
        storage_object_key=body.storage_object_key,
        chunk_count=body.chunk_count,
    )
    for _ in range(_ID_RETRIES):
        snippet = Snippet(
            id=new_snippet_id(),
            share_mode=ShareMode.sync,
            content_type=body.content_type,
            encrypted_metadata=body.encrypted_metadata,
            ciphertext_inline=content.inline,
            storage_object_key=content.storage_object_key,
            chunk_count=content.chunk_count,
            size_bytes=content.size_bytes,
            wrapped_dek=body.wrapped_dek,
            wrapped_dek_iv=body.wrapped_dek_iv,
            owner_user_id=user.id,
        )
        session.add(snippet)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            continue
        # Refresh to load the server-defaulted created_at before publishing.
        await session.refresh(snippet)
        await sync_bus.publish(
            SnippetCreatedEvent(
                kind="snippet.created",
                user_id=str(user.id),
                item=SyncItem(
                    id=snippet.id,
                    content_type=snippet.content_type,
                    ciphertext=snippet.ciphertext_inline or b"",
                    wrapped_dek=snippet.wrapped_dek or b"",
                    wrapped_dek_iv=snippet.wrapped_dek_iv or b"",
                    encrypted_metadata=snippet.encrypted_metadata,
                    size_bytes=snippet.size_bytes,
                    created_at=snippet.created_at,
                    chunk_count=snippet.chunk_count,
                ),
            )
        )
        return CreateSyncResponse(id=snippet.id)

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="could not generate a unique snippet id",
    )


@router.post(
    "/by-pin",
    response_model=None,
    dependencies=[Depends(by_pin_minute_limit), Depends(by_pin_hour_limit)],
)
async def resolve_by_pin(
    body: ByPinRequest,
    request: Request,
    session: DbSession,
    redis_client: RedisDep,
    key_vault: KeyVaultDep,
    settings: SettingsDep,
    http_client: HttpClient,
    store: ObjectStoreDep,
) -> PinResolveResponse | PairSignalResponse | JSONResponse:
    """Resolve a 4-digit PIN. A live Mode 3 pairing returns a pair signal; a
    Mode 2 share returns its ciphertext + server-unwrapped content key (burning
    a read). After 3 failed attempts from an IP a Turnstile token is required."""
    ip = extract_client_ip(request)

    if await _bypin_failures(redis_client, ip) >= _BY_PIN_TURNSTILE_AFTER:
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

    # A live pairing takes the PIN namespace for its 60s window: signal pair.
    if await lookup_pairing(redis_client, body.pin) is not None:
        return PairSignalResponse()

    snippet = await session.scalar(
        select(Snippet).where(Snippet.pin == body.pin, Snippet.share_mode == ShareMode.pin_share)
    )
    if snippet is None:
        await _record_bypin_failure(redis_client, ip)
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND, content={"reason": "unknown_pin"}
        )

    gone_reason = _gone_reason_or_none(snippet)
    if gone_reason is not None:
        return JSONResponse(
            status_code=status.HTTP_410_GONE,
            content=GoneResponse(reason=gone_reason).model_dump(mode="json"),
        )

    # Auto-invalidated after too many wrong password attempts (cross-IP).
    if snippet.pin_failed_attempts >= _MAX_PIN_FAILED_ATTEMPTS:
        return _pin_disabled()

    if snippet.password_hash is not None and snippet.password_salt is not None:
        if body.password_hash is None:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=PasswordRequiredResponse(password_salt=snippet.password_salt).model_dump(
                    mode="json"
                ),
            )
        if not hmac.compare_digest(snippet.password_hash, body.password_hash):
            await _record_bypin_failure(redis_client, ip)
            attempts = await _increment_pin_failures(session, snippet.id)
            if attempts >= _MAX_PIN_FAILED_ATTEMPTS:
                return _pin_disabled()
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"reason": "password_incorrect"},
            )

    await _reset_bypin_failures(redis_client, ip)
    return await _burn_and_render_pin(session, snippet.id, key_vault, store)


@router.get(
    "/{snippet_id}",
    response_model=GetSnippetResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": PasswordRequiredResponse,
            "description": "Snippet is password-protected; call verify-password with the hash",
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
    store: ObjectStoreDep,
) -> GetSnippetResponse | JSONResponse:
    """Fetch a snippet's ciphertext, burning one read.

    Password-protected snippets short-circuit to 401 before the read-
    count CAS so wrong passwords don't burn the snippet (see
    [D-260526-01]); the burn happens inside ``verify_password`` instead.
    """
    snippet = await _load_snippet(session, snippet_id)
    if snippet is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    # Terminal states bypass the password gate: the snippet is gone
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

    return await _burn_and_render(session, snippet_id, store)


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
    store: ObjectStoreDep,
) -> GetSnippetResponse | JSONResponse:
    """Validate a password attempt for a gated snippet.

    On match, atomically bumps ``read_count`` and returns the ciphertext,
    the same shape as the unprotected ``GET /snippets/{id}``. Wrong
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

    return await _burn_and_render(session, snippet_id, store)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _load_snippet(session: AsyncSession, snippet_id: str) -> Snippet | None:
    result: Snippet | None = await session.scalar(select(Snippet).where(Snippet.id == snippet_id))
    return result


def _gone_reason_or_none(snippet: Snippet) -> GoneReason | None:
    """Same predicate as the CAS uses, but for a pre-fetched row. Order
    matters: take-down by the operator outranks natural expiry which
    outranks burn-out. The reasons are mutually exclusive in practice
    but the order is the priority we surface."""
    if snippet.taken_down_at is not None:
        return GoneReason.taken_down
    now = datetime.now(tz=UTC)
    if snippet.expires_at is not None and snippet.expires_at <= now:
        return GoneReason.expired
    if snippet.max_reads is not None and snippet.read_count >= snippet.max_reads:
        return GoneReason.burned
    return None


async def _burn_cas(session: AsyncSession, snippet_id: str) -> Snippet | JSONResponse:
    """Atomic CAS: increment read_count only if the row is still readable, then
    return the freshly-loaded row (or a 410 gone response). Shared by the link
    GET, verify-password, and by-pin paths so burn semantics stay identical."""
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

    # The raw SQL UPDATE just bypassed the ORM identity map. The session is
    # configured with ``expire_on_commit=False``, so any Snippet instance the
    # request already loaded would survive the commit below with its pre-bump
    # ``read_count``. Expire now so any re-load reflects the DB.
    session.expire_all()

    if updated_id is None:
        # CAS failed between load and burn: race with another reader or the
        # purge job. Re-load to pick the most specific gone-reason.
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
        # Vanishingly rare: the purge ran between commit and re-read.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    # Notify any /ws/snippet/{id}/watch subscribers: read first (so live
    # counters tick), then gone if this read also burned the snippet.
    await watch_bus.publish(
        ReadEvent(kind="read", snippet_id=fresh.id, read_count=fresh.read_count)
    )
    if fresh.max_reads is not None and fresh.read_count >= fresh.max_reads:
        await watch_bus.publish(GoneEvent(kind="gone", snippet_id=fresh.id, reason="burned"))

    return fresh


def _download_urls(store: ObjectStore | None, snippet: Snippet) -> list[str] | None:
    """Presigned GET URL per chunk for a file-backed snippet, or None for
    inline content. Raises 503 if the content is in R2 but R2 isn't wired."""
    if snippet.storage_object_key is None:
        return None
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="file storage is not configured",
        )
    return [
        store.presign_get(f"{snippet.storage_object_key}/{i}")
        for i in range(snippet.chunk_count or 0)
    ]


async def _burn_and_render(
    session: AsyncSession, snippet_id: str, store: ObjectStore | None
) -> GetSnippetResponse | JSONResponse:
    outcome = await _burn_cas(session, snippet_id)
    if isinstance(outcome, JSONResponse):
        return outcome
    fresh = outcome
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
        chunk_count=fresh.chunk_count,
        download_urls=_download_urls(store, fresh),
    )


async def _burn_and_render_pin(
    session: AsyncSession, snippet_id: str, key_vault: KeyVault, store: ObjectStore | None
) -> PinResolveResponse | JSONResponse:
    outcome = await _burn_cas(session, snippet_id)
    if isinstance(outcome, JSONResponse):
        return outcome
    fresh = outcome
    if (
        fresh.encrypted_content_key is None
        or fresh.content_key_iv is None
        or fresh.key_version is None
    ):
        # A pin_share row is guaranteed these by CHECK constraint; treat a
        # violation as a server fault rather than leaking a broken response.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="pin share is missing its wrapped key",
        )
    content_key = key_vault.unwrap(
        fresh.encrypted_content_key, fresh.content_key_iv, fresh.key_version
    )
    return PinResolveResponse(
        id=fresh.id,
        content_type=fresh.content_type,
        content_key=content_key,
        ciphertext=fresh.ciphertext_inline or b"",
        encrypted_metadata=fresh.encrypted_metadata,
        size_bytes=fresh.size_bytes,
        created_at=fresh.created_at,
        expires_at=fresh.expires_at,
        max_reads=fresh.max_reads,
        read_count=fresh.read_count,
        chunk_count=fresh.chunk_count,
        download_urls=_download_urls(store, fresh),
    )
