from __future__ import annotations

import os

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.lib.ids import new_snippet_id
from app.lib.keyrotation import rotate_master_key
from app.lib.keyvault import KeyVault
from app.models.accounts import User
from app.models.snippets import ContentType, ShareMode, Snippet

_DB_URL = os.environ.get(
    "TEST_DATABASE_URL",
    os.environ.get("DATABASE_URL", "postgresql+asyncpg://wispr:wispr@localhost:5432/wispr"),
)

_K1 = os.urandom(32)
_K2 = os.urandom(32)
_V1_VAULT = KeyVault({1: _K1}, current_version=1)
_V2_VAULT = KeyVault({1: _K1, 2: _K2}, current_version=2)  # dual-key window
_V2_ONLY = KeyVault({2: _K2}, current_version=2)  # v1 retired


@pytest.fixture
def factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(_DB_URL, pool_pre_ping=True)
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def _seed_pin_share(db: AsyncSession, vault: KeyVault, content_key: bytes, pin: str) -> str:
    owner = await db.scalar(select(User).where(User.email == "owner@example.com"))
    if owner is None:
        owner = User(email="owner@example.com", auth_credential_hash=b"x")
        db.add(owner)
        await db.flush()
    wrapped, iv, version = vault.wrap(content_key)
    snippet = Snippet(
        id=new_snippet_id(),
        share_mode=ShareMode.pin_share,
        content_type=ContentType.text,
        encrypted_metadata=b"m",
        ciphertext_inline=b"ct",
        size_bytes=2,
        pin=pin,
        encrypted_content_key=wrapped,
        content_key_iv=iv,
        key_version=version,
        owner_user_id=owner.id,
    )
    db.add(snippet)
    await db.commit()
    return snippet.id


async def test_rotate_rewraps_and_preserves_content_key(
    factory: async_sessionmaker[AsyncSession], db_session: AsyncSession
) -> None:
    ck = os.urandom(32)
    sid = await _seed_pin_share(db_session, _V1_VAULT, ck, pin="1111")

    outcome = await rotate_master_key(factory, _V2_VAULT, batch_size=100)

    assert outcome.rewrapped == 1 and outcome.failed == 0 and outcome.current_version == 2
    db_session.expunge_all()
    row = await db_session.scalar(select(Snippet).where(Snippet.id == sid))
    assert row is not None and row.key_version == 2
    # The content key is unchanged — unwrapping under v2 yields the original.
    assert row.encrypted_content_key is not None and row.content_key_iv is not None
    assert _V2_VAULT.unwrap(row.encrypted_content_key, row.content_key_iv, 2) == ck


async def test_rotate_is_idempotent(
    factory: async_sessionmaker[AsyncSession], db_session: AsyncSession
) -> None:
    await _seed_pin_share(db_session, _V1_VAULT, os.urandom(32), pin="2222")

    first = await rotate_master_key(factory, _V2_VAULT)
    second = await rotate_master_key(factory, _V2_VAULT)  # everything already at v2

    assert first.rewrapped == 1
    assert second.rewrapped == 0 and second.failed == 0


async def test_rotate_skips_rows_whose_old_key_is_gone(
    factory: async_sessionmaker[AsyncSession], db_session: AsyncSession
) -> None:
    ck = os.urandom(32)
    sid = await _seed_pin_share(db_session, _V1_VAULT, ck, pin="3333")

    # v1 was retired: the vault can't unwrap the v1 row → it's skipped, not corrupted.
    outcome = await rotate_master_key(factory, _V2_ONLY)

    assert outcome.rewrapped == 0 and outcome.failed == 1
    db_session.expunge_all()
    row = await db_session.scalar(select(Snippet).where(Snippet.id == sid))
    assert row is not None and row.key_version == 1  # untouched
    assert _V1_VAULT.unwrap(row.encrypted_content_key or b"", row.content_key_iv or b"", 1) == ck
