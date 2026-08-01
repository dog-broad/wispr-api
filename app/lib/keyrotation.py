from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.lib.keyvault import KeyVault
from app.models.snippets import ShareMode, Snippet

_BATCH = 500


@dataclass(frozen=True, slots=True)
class RotationOutcome:
    rewrapped: int
    failed: int
    current_version: int


async def rotate_master_key(
    session_factory: async_sessionmaker[AsyncSession],
    vault: KeyVault,
    batch_size: int = _BATCH,
) -> RotationOutcome:
    """Re-wrap every Mode 2 content key that isn't already at the vault's current
    version: unwrap with the row's recorded ``key_version``, re-wrap under the
    current key, write both columns back.

    Resumable: a keyset cursor (``id > last_id``) plus the ``key_version !=
    current`` filter means a re-wrapped row leaves the working set, so a restart
    mid-job just re-scans and continues from the remaining old-version rows.
    Batches commit independently. A row whose recorded version's key isn't
    loaded (old key retired too early) is skipped and counted, never crashing
    the job.
    """
    current = vault.current_version
    rewrapped = 0
    failed = 0
    last_id = ""

    while True:
        async with session_factory() as session:
            rows = list(
                await session.scalars(
                    select(Snippet)
                    .where(
                        Snippet.share_mode == ShareMode.pin_share,
                        Snippet.key_version.is_not(None),
                        Snippet.key_version != current,
                        Snippet.id > last_id,
                    )
                    .order_by(Snippet.id)
                    .limit(batch_size)
                )
            )
            if not rows:
                break
            for row in rows:
                last_id = row.id  # advance past this row whether or not it rewraps
                if (
                    row.encrypted_content_key is None
                    or row.content_key_iv is None
                    or row.key_version is None
                ):
                    failed += 1
                    continue
                try:
                    content_key = vault.unwrap(
                        row.encrypted_content_key, row.content_key_iv, row.key_version
                    )
                    wrapped, iv, version = vault.wrap(content_key)
                except (KeyError, InvalidTag, ValueError):
                    failed += 1
                    continue
                row.encrypted_content_key = wrapped
                row.content_key_iv = iv
                row.key_version = version
                rewrapped += 1
            await session.commit()

    return RotationOutcome(rewrapped=rewrapped, failed=failed, current_version=current)
