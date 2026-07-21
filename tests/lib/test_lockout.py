from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.lib.lockout import LOCK_THRESHOLD, clear, is_locked, register_failure
from app.models.accounts import User

_T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


async def _make_user(db: AsyncSession) -> uuid.UUID:
    user = User(email="lock@example.com")
    db.add(user)
    await db.flush()
    return user.id


async def _fail_n(db: AsyncSession, uid: uuid.UUID, n: int, now: datetime) -> None:
    for _ in range(n):
        await register_failure(db, uid, now)


async def test_locks_after_threshold(db_session: AsyncSession) -> None:
    uid = await _make_user(db_session)
    for _ in range(LOCK_THRESHOLD - 1):
        r = await register_failure(db_session, uid, _T0)
        assert not r.locked
    tripped = await register_failure(db_session, uid, _T0)
    assert tripped.locked
    assert tripped.send_email
    assert await is_locked(db_session, uid, _T0)


async def test_window_resets_after_15_min(db_session: AsyncSession) -> None:
    uid = await _make_user(db_session)
    await _fail_n(db_session, uid, LOCK_THRESHOLD - 1, _T0)
    # One more, but 16 minutes later — the window resets, so this is attempt #1.
    r = await register_failure(db_session, uid, _T0 + timedelta(minutes=16))
    assert not r.locked


async def test_lockout_email_throttled_to_one_per_24h(db_session: AsyncSession) -> None:
    uid = await _make_user(db_session)
    first = None
    for _ in range(LOCK_THRESHOLD):
        first = await register_failure(db_session, uid, _T0)
    assert first is not None and first.locked and first.send_email

    # Second lockout 2h later (lock expired, still within the 24h email window).
    second = None
    for _ in range(LOCK_THRESHOLD):
        second = await register_failure(db_session, uid, _T0 + timedelta(hours=2))
    assert second is not None and second.locked and not second.send_email

    # Past 24h since the first email — a new alert is allowed.
    third = None
    for _ in range(LOCK_THRESHOLD):
        third = await register_failure(db_session, uid, _T0 + timedelta(hours=25))
    assert third is not None and third.locked and third.send_email


async def test_clear_unlocks(db_session: AsyncSession) -> None:
    uid = await _make_user(db_session)
    await _fail_n(db_session, uid, LOCK_THRESHOLD, _T0)
    assert await is_locked(db_session, uid, _T0)
    await clear(db_session, uid, _T0 + timedelta(hours=2))
    assert not await is_locked(db_session, uid, _T0 + timedelta(hours=2))
