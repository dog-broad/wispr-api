from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import CursorResult, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.lib.storage import ObjectStore
from app.models.snippets import Snippet

logger = logging.getLogger(__name__)

# A file's chunk objects only become orphans if no snippet ever finalized
# against their prefix; give an in-flight upload this long to call finalize
# before the sweeper reclaims its chunks.
_ORPHAN_MAX_AGE_SECONDS = 30 * 60


async def purge_expired(
    session_factory: async_sessionmaker[AsyncSession],
    store: ObjectStore | None = None,
) -> int:
    """Hard-delete every snippet whose ``expires_at`` is in the past, and free
    the R2 chunk objects of any expired file-backed snippets.

    Returns the number of rows deleted. Rows with a null ``expires_at`` are
    left alone — link mode always sets one, but sync keeps snippets until the
    owner removes them, and the purge job should never touch those.
    """
    async with session_factory() as session:
        # Grab the R2 keys of expiring file snippets before the rows go, so we
        # know what to delete from object storage afterwards.
        expiring_stored = (
            await session.execute(
                select(Snippet.storage_object_key, Snippet.chunk_count).where(
                    Snippet.expires_at.is_not(None),
                    Snippet.expires_at < func.now(),
                    Snippet.storage_object_key.is_not(None),
                )
            )
        ).all()
        result = await session.execute(
            delete(Snippet).where(
                Snippet.expires_at.is_not(None),
                Snippet.expires_at < func.now(),
            )
        )
        await session.commit()

    # Best-effort R2 cleanup after the rows are gone (DB is source of truth):
    # if this fails, the objects become orphans the sweeper reclaims later.
    if store is not None and expiring_stored:
        keys = [
            f"{sok}/{i}"
            for sok, chunk_count in expiring_stored
            if sok is not None
            for i in range(chunk_count or 0)
        ]
        if keys:
            try:
                await store.delete_keys(keys)
            except Exception:
                logger.exception("purge: R2 delete failed for %d object(s)", len(keys))

    if not isinstance(result, CursorResult):
        return 0
    return int(result.rowcount or 0)


async def sweep_orphans(
    session_factory: async_sessionmaker[AsyncSession],
    store: ObjectStore | None,
    max_age_seconds: int = _ORPHAN_MAX_AGE_SECONDS,
) -> int:
    """Delete R2 chunk objects whose ``files/<token>`` prefix has no finalized
    snippet and whose newest object is older than ``max_age_seconds`` (so an
    in-flight upload isn't reclaimed mid-flight). Returns the prefix count swept.
    """
    if store is None:
        return 0
    objects = await store.list_objects("files/")
    if not objects:
        return 0

    # Group chunk objects (files/<token>/<i>) by their storage_object_key
    # prefix, tracking the newest last-modified in each.
    newest: dict[str, datetime] = {}
    for key, last_modified in objects:
        parts = key.split("/")
        if len(parts) < 3:
            continue
        prefix = f"{parts[0]}/{parts[1]}"
        current = newest.get(prefix)
        if current is None or last_modified > current:
            newest[prefix] = last_modified

    async with session_factory() as session:
        finalized = set(
            (
                await session.scalars(
                    select(Snippet.storage_object_key).where(
                        Snippet.storage_object_key.in_(list(newest))
                    )
                )
            ).all()
        )

    cutoff = datetime.now(tz=UTC) - timedelta(seconds=max_age_seconds)
    orphan_prefixes = {
        prefix
        for prefix, last_modified in newest.items()
        if prefix not in finalized and last_modified < cutoff
    }
    if not orphan_prefixes:
        return 0

    orphan_keys = [key for key, _ in objects if key.rsplit("/", 1)[0] in orphan_prefixes]
    await store.delete_keys(orphan_keys)
    return len(orphan_prefixes)


async def run_purge_loop(
    session_factory: async_sessionmaker[AsyncSession],
    interval_seconds: int,
    stop_event: asyncio.Event,
    store: ObjectStore | None = None,
) -> None:
    """Drive ``purge_expired`` (and the orphan sweep) forever.

    Runs an initial pass immediately so a freshly-booted api catches rows that
    expired while it was down, then sleeps ``interval_seconds`` between runs.
    Exits cleanly when ``stop_event`` is set. Per-iteration errors are logged
    and swallowed so a transient outage does not kill the loop.

    ``interval_seconds == 0`` short-circuits and never runs — useful for tests
    that drive ``purge_expired`` directly.
    """
    if interval_seconds <= 0:
        logger.info("purge: disabled (interval=%d)", interval_seconds)
        await stop_event.wait()
        return

    while not stop_event.is_set():
        await _run_one(session_factory, store)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except TimeoutError:
            continue


async def _run_one(
    session_factory: async_sessionmaker[AsyncSession], store: ObjectStore | None
) -> None:
    started = time.perf_counter()
    try:
        deleted = await purge_expired(session_factory, store)
    except Exception:
        # Don't crash the loop on a transient DB outage; the next tick retries.
        logger.exception("purge: run failed")
        return
    elapsed_ms = (time.perf_counter() - started) * 1000
    logger.info("purge: deleted %d expired snippet(s) in %.1f ms", deleted, elapsed_ms)

    try:
        swept = await sweep_orphans(session_factory, store)
    except Exception:
        logger.exception("purge: orphan sweep failed")
        return
    if swept:
        logger.info("purge: swept %d orphaned upload(s)", swept)
