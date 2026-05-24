from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.lib.ids import new_snippet_id
from app.models.snippets import ShareMode, Snippet
from app.schemas.snippets import (
    CreateLinkSnippetRequest,
    CreateSnippetResponse,
    GetSnippetResponse,
    GoneReason,
    GoneResponse,
)

router = APIRouter(prefix="/snippets", tags=["snippets"])

DbSession = Annotated[AsyncSession, Depends(get_session)]

# How many times to retry on a primary-key collision. 62^12 ≈ 3.2e21 IDs;
# even one collision is unlikely, but a tight retry budget keeps us honest
# about the bound if the alphabet ever shrinks.
_ID_RETRIES = 5


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=CreateSnippetResponse,
)
async def create_snippet(
    body: CreateLinkSnippetRequest,
    session: DbSession,
) -> CreateSnippetResponse:
    """Create an anonymous Link snippet.

    Only the link shape is accepted. PIN-share and sync shapes are rejected
    at the schema layer (Pydantic discriminator on share_mode), so the
    handler only sees well-formed link requests.
    """
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


@router.get(
    "/{snippet_id}",
    response_model=GetSnippetResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Snippet ID does not exist"},
        status.HTTP_410_GONE: {
            "model": GoneResponse,
            "description": "Snippet existed but is expired, burned, or taken down",
        },
    },
)
async def get_snippet(
    snippet_id: str,
    session: DbSession,
) -> GetSnippetResponse | JSONResponse:
    """Fetch a snippet's ciphertext, burning one read.

    The update is atomic: the row's read_count is incremented only if every
    "still readable" predicate holds. This avoids the classic read-then-
    write race that would otherwise let two concurrent receivers both
    consume a single-read link.
    """
    # Atomic CAS: increment read_count only if the row is still readable.
    # RETURNING gives us the post-update row in one round-trip.
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

    if updated_id is None:
        # The CAS failed: either the snippet doesn't exist, or it does but
        # one of the gating predicates returned false. Disambiguate with a
        # follow-up SELECT so the client can render the right "this is
        # gone" page (per PROJECT.md §7.6 — gone is not 404).
        existing = await session.execute(
            select(Snippet).where(Snippet.id == snippet_id)
        )
        snippet = existing.scalar_one_or_none()
        if snippet is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        reason = _gone_reason(snippet)
        return JSONResponse(
            status_code=status.HTTP_410_GONE,
            content=GoneResponse(reason=reason).model_dump(mode="json"),
        )

    # CAS succeeded — the row now has read_count bumped. Fetch the fresh
    # state to return.
    await session.commit()
    fresh = await session.execute(select(Snippet).where(Snippet.id == snippet_id))
    snippet = fresh.scalar_one()
    return GetSnippetResponse(
        id=snippet.id,
        share_mode=snippet.share_mode,
        content_type=snippet.content_type,
        ciphertext=snippet.ciphertext_inline or b"",
        encrypted_metadata=snippet.encrypted_metadata,
        size_bytes=snippet.size_bytes,
        created_at=snippet.created_at,
        expires_at=snippet.expires_at,
        max_reads=snippet.max_reads,
        read_count=snippet.read_count,
    )


def _gone_reason(snippet: Snippet) -> GoneReason:
    """Pick the most specific "why gone" reason for a row that failed the
    readability CAS. Order matters: take-down by the operator outranks
    natural expiry which outranks burn-out — the reasons are mutually
    exclusive in practice but the order is the priority we surface."""
    if snippet.taken_down_at is not None:
        return GoneReason.taken_down
    now = datetime.now(tz=UTC)
    if snippet.expires_at is not None and snippet.expires_at <= now:
        return GoneReason.expired
    return GoneReason.burned
