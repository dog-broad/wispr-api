from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, status

from app.lib.ratelimit import files_presign_limit
from app.lib.storage import ObjectStoreDep
from app.schemas.snippets import PresignedChunk, PresignRequest, PresignResponse

router = APIRouter(prefix="/snippets/files", tags=["files"])

# Opaque, unguessable prefix per upload. The chunk objects are stored under it
# as ``{key}/{index}``; the client can't derive another upload's keys.
_KEY_BYTES = 12


@router.post("/presign", dependencies=[Depends(files_presign_limit)])
async def presign(body: PresignRequest, store: ObjectStoreDep) -> PresignResponse:
    """Reserve a storage key and hand back one presigned PUT URL per 1 MiB
    ciphertext chunk. The client uploads ciphertext straight to R2, then
    finalizes via POST /snippets with the returned storage_object_key."""
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="file uploads are not configured",
        )
    key = f"files/{secrets.token_urlsafe(_KEY_BYTES)}"
    chunks = [
        PresignedChunk(index=i, url=store.presign_put(f"{key}/{i}"))
        for i in range(body.chunk_count)
    ]
    return PresignResponse(storage_object_key=key, chunk_count=body.chunk_count, chunks=chunks)
