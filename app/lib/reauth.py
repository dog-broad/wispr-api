from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.lib.credentials import verify_auth_credential
from app.lib.lockout import clear as clear_lockout
from app.lib.lockout import is_locked, register_failure
from app.models.accounts import User


@dataclass(frozen=True, slots=True)
class ReauthOutcome:
    ok: bool
    locked: bool  # attempt blocked / just crossed the lockout threshold
    send_email: bool  # caller should fire the throttled lockout alert


async def reauth(
    db: AsyncSession, user: User, auth_token: bytes, pepper: str | None, now: datetime
) -> ReauthOutcome:
    """Verify a fresh auth-token proof for a sensitive action (change email,
    delete account). Shares the unlock lockout: a wrong token counts toward the
    10-in-15-min lock so these endpoints can't be used to brute-force the
    passphrase. Callers must have already checked ``user.auth_credential_hash``
    is set."""
    stored_hash = user.auth_credential_hash
    if stored_hash is None:
        raise ValueError("reauth requires a passphrase to be set")
    if await is_locked(db, user.id, now):
        return ReauthOutcome(ok=False, locked=True, send_email=False)
    ok = await run_in_threadpool(verify_auth_credential, stored_hash, auth_token, pepper)
    if ok:
        await clear_lockout(db, user.id, now)
        return ReauthOutcome(ok=True, locked=False, send_email=False)
    result = await register_failure(db, user.id, now)
    return ReauthOutcome(ok=False, locked=result.locked, send_email=result.send_email)
