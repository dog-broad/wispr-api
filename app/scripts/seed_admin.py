"""Bootstrap the first admin account and issue invite code(s).

Accounts are invite-only, and invites are issued by admins, so a fresh
database has no way in. Run this once per deployment to create the founding
admin and mint the first invite(s):

    python -m app.scripts.seed_admin --email admin@example.com --invites 1

Idempotent for the admin: an existing account with that email is promoted to
admin rather than duplicated. The admin signs in through the normal magic-link
flow (in dev the link is written to the app log).
"""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import async_session_maker
from app.lib.invites import generate_invite_code
from app.models.accounts import Invite, User


async def _ensure_admin(db: AsyncSession, email: str) -> User:
    normalized = email.strip().lower()
    admin = await db.scalar(select(User).where(User.email == normalized, User.deleted_at.is_(None)))
    if admin is None:
        admin = User(email=normalized, is_admin=True)
        db.add(admin)
        await db.flush()
        print(f"created admin {normalized} ({admin.id})")
        return admin
    if not admin.is_admin:
        admin.is_admin = True
        print(f"promoted existing user {normalized} to admin ({admin.id})")
    else:
        print(f"admin {normalized} already exists ({admin.id})")
    return admin


async def _issue_invites(db: AsyncSession, admin: User, count: int) -> list[str]:
    # Dedup within the batch; a collision against an existing invite is
    # astronomically unlikely (31^8) and would surface as a commit error the
    # operator can just re-run through.
    codes: list[str] = []
    seen: set[str] = set()
    while len(codes) < count:
        code = generate_invite_code()
        if code in seen:
            continue
        seen.add(code)
        db.add(Invite(code=code, created_by=admin.id))
        codes.append(code)
    return codes


async def seed(email: str, invites: int) -> list[str]:
    async with async_session_maker() as db:
        admin = await _ensure_admin(db, email)
        codes = await _issue_invites(db, admin, invites)
        await db.commit()
    for code in codes:
        print(f"invite code: {code}")
    return codes


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the first admin + invites.")
    parser.add_argument("--email", default="admin@wispr.rushyendra.dev")
    parser.add_argument("--invites", type=int, default=1)
    args = parser.parse_args()
    asyncio.run(seed(args.email, args.invites))


if __name__ == "__main__":
    main()
