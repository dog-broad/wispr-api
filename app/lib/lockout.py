from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.accounts import PassphraseLockout

# Passphrase brute-force protection (PROJECT.md §3, [D-0024-12]): 10 wrong
# attempts in a rolling 15-minute window lock the account for an hour, and the
# alert email is throttled to at most one per 24h regardless of how many
# lockout events fire.
LOCK_THRESHOLD = 10
LOCK_WINDOW = timedelta(minutes=15)
LOCK_DURATION = timedelta(hours=1)
EMAIL_THROTTLE = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class FailureResult:
    locked: bool  # the account is now locked
    send_email: bool  # the caller should send the (throttled) alert email


async def is_locked(db: AsyncSession, user_id: uuid.UUID, now: datetime) -> bool:
    row = await db.get(PassphraseLockout, user_id)
    return row is not None and row.locked_until is not None and row.locked_until > now


async def clear(db: AsyncSession, user_id: uuid.UUID, now: datetime) -> None:
    """Reset the counter after a correct passphrase. Keeps ``last_email_sent_at``
    so the 24h email throttle spans lock episodes."""
    row = await db.get(PassphraseLockout, user_id)
    if row is not None:
        row.failed_attempts = 0
        row.window_started_at = now
        row.locked_until = None


async def register_failure(db: AsyncSession, user_id: uuid.UUID, now: datetime) -> FailureResult:
    """Record a wrong attempt; lock and (throttled) flag an email once the
    threshold is hit within the rolling window."""
    row = await db.get(PassphraseLockout, user_id)
    if row is None:
        row = PassphraseLockout(user_id=user_id, failed_attempts=1, window_started_at=now)
        db.add(row)
    elif now - row.window_started_at > LOCK_WINDOW:
        # Window elapsed — start a fresh count.
        row.window_started_at = now
        row.failed_attempts = 1
    else:
        row.failed_attempts += 1

    if row.failed_attempts < LOCK_THRESHOLD:
        return FailureResult(locked=False, send_email=False)

    row.locked_until = now + LOCK_DURATION
    send_email = row.last_email_sent_at is None or (now - row.last_email_sent_at) > EMAIL_THROTTLE
    if send_email:
        row.last_email_sent_at = now
    return FailureResult(locked=True, send_email=send_email)
