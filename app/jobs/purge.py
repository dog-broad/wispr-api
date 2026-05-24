from __future__ import annotations

import asyncio
import logging
import time

from sqlalchemy import CursorResult, delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.snippets import Snippet

logger = logging.getLogger(__name__)


async def purge_expired(session_factory: async_sessionmaker[AsyncSession]) -> int:
    """Hard-delete every snippet whose ``expires_at`` is in the past.

    Returns the number of rows deleted. Rows with a null ``expires_at`` are
    left alone — link mode always sets one, but later modes (sync) keep
    snippets indefinitely until the owner removes them, and the purge job
    should never touch those.

    The job runs inside its own session so it can commit independently of
    any request-scoped session and yields a fresh transaction each call.
    """
    async with session_factory() as session:
        stmt = delete(Snippet).where(
            Snippet.expires_at.is_not(None),
            Snippet.expires_at < _now_sql(),
        )
        result = await session.execute(stmt)
        await session.commit()
        # DELETE returns a CursorResult at runtime; the base Result type
        # isn't narrow enough to expose rowcount on its own.
        if not isinstance(result, CursorResult):
            return 0
        return int(result.rowcount or 0)


def _now_sql() -> object:
    """Inline ``now()`` so the comparison happens server-side — keeps the
    job correct under clock skew between the api host and the database."""
    from sqlalchemy import func

    return func.now()


async def run_purge_loop(
    session_factory: async_sessionmaker[AsyncSession],
    interval_seconds: int,
    stop_event: asyncio.Event,
) -> None:
    """Drive ``purge_expired`` forever.

    Runs an initial purge immediately so a freshly-booted api catches rows
    that expired while it was down, then sleeps ``interval_seconds`` between
    runs. Exits cleanly when ``stop_event`` is set. Per-iteration errors are
    logged and swallowed so a transient DB outage does not kill the loop.

    ``interval_seconds == 0`` short-circuits and never runs — useful for
    tests that drive ``purge_expired`` directly.
    """
    if interval_seconds <= 0:
        logger.info("purge: disabled (interval=%d)", interval_seconds)
        await stop_event.wait()
        return

    while not stop_event.is_set():
        await _run_one(session_factory)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except TimeoutError:
            continue


async def _run_one(session_factory: async_sessionmaker[AsyncSession]) -> None:
    started = time.perf_counter()
    try:
        deleted = await purge_expired(session_factory)
    except Exception:
        # Don't crash the loop on a transient DB outage; the next tick will
        # try again. Exception detail goes to the logger.
        logger.exception("purge: run failed")
        return
    elapsed_ms = (time.perf_counter() - started) * 1000
    logger.info("purge: deleted %d expired snippet(s) in %.1f ms", deleted, elapsed_ms)
