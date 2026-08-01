from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.jobs.purge import purge_expired, sweep_orphans
from app.models.snippets import ContentType, ShareMode, Snippet

_TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    os.environ.get("DATABASE_URL", "postgresql+asyncpg://wispr:wispr@localhost:5432/wispr"),
)


@pytest.fixture
def factory() -> async_sessionmaker[AsyncSession]:
    """Test-scope session factory. We pass this into `purge_expired` so it
    owns its own session and commit, independent of the `db_session`
    fixture used for setup/teardown."""
    engine = create_async_engine(_TEST_DATABASE_URL, pool_pre_ping=True)
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def _snippet(
    snippet_id: str,
    expires_at: datetime | None,
    read_count: int = 0,
    max_reads: int | None = 1,
) -> Snippet:
    return Snippet(
        id=snippet_id,
        share_mode=ShareMode.link,
        content_type=ContentType.text,
        encrypted_metadata=b"meta",
        ciphertext_inline=b"ciphertext",
        size_bytes=10,
        max_reads=max_reads,
        read_count=read_count,
        expires_at=expires_at,
    )


async def test_purge_deletes_expired_rows(
    db_session: AsyncSession, factory: async_sessionmaker[AsyncSession]
) -> None:
    now = datetime.now(tz=UTC)
    db_session.add(_snippet("expiredaaaaa", expires_at=now - timedelta(hours=1)))
    db_session.add(_snippet("expiredbbbbb", expires_at=now - timedelta(minutes=1)))
    db_session.add(_snippet("freshcccccc1", expires_at=now + timedelta(hours=1)))
    await db_session.commit()

    deleted = await purge_expired(factory)
    assert deleted == 2

    remaining = await db_session.execute(select(Snippet.id))
    assert {row[0] for row in remaining.all()} == {"freshcccccc1"}


async def test_purge_leaves_unexpired_rows(
    db_session: AsyncSession, factory: async_sessionmaker[AsyncSession]
) -> None:
    now = datetime.now(tz=UTC)
    db_session.add(_snippet("freshaaaaaaa", expires_at=now + timedelta(hours=1)))
    db_session.add(_snippet("freshbbbbbbb", expires_at=now + timedelta(days=1)))
    await db_session.commit()

    deleted = await purge_expired(factory)
    assert deleted == 0

    remaining = await db_session.execute(select(Snippet.id))
    assert {row[0] for row in remaining.all()} == {"freshaaaaaaa", "freshbbbbbbb"}


async def test_purge_leaves_null_expiry_rows(
    db_session: AsyncSession, factory: async_sessionmaker[AsyncSession]
) -> None:
    """Rows without a TTL are never auto-purged. Link mode always sets
    one; this is defense-in-depth for sync mode which keeps rows
    indefinitely."""
    # Direct SQL: link mode would normally require an expires_at, but the
    # null-purge guarantee must hold regardless of which mode wrote the row.
    await db_session.execute(
        sa_text(
            "INSERT INTO snippets "
            "(id, share_mode, content_type, encrypted_metadata, ciphertext_inline, "
            " size_bytes, max_reads) "
            "VALUES (:id, 'link', 'text', :m, :c, 10, 1)"
        ),
        {"id": "nullexpaaaaa", "m": b"meta", "c": b"ciphertext"},
    )
    await db_session.commit()

    deleted = await purge_expired(factory)
    assert deleted == 0


async def test_purge_keeps_burned_but_unexpired(
    db_session: AsyncSession, factory: async_sessionmaker[AsyncSession]
) -> None:
    """A read-once link that has been consumed but whose TTL has not yet
    passed must stay in the table: the GET handler needs it to return
    410 burned (per the UX spec, "this is gone" not "404")."""
    now = datetime.now(tz=UTC)
    db_session.add(
        _snippet(
            "burnedaaaaaa",
            expires_at=now + timedelta(hours=1),
            read_count=1,
            max_reads=1,
        )
    )
    await db_session.commit()

    deleted = await purge_expired(factory)
    assert deleted == 0

    remaining = await db_session.execute(select(Snippet.id))
    assert {row[0] for row in remaining.all()} == {"burnedaaaaaa"}


async def test_purge_idempotent_on_empty_table(
    db_session: AsyncSession, factory: async_sessionmaker[AsyncSession]
) -> None:
    _ = db_session  # ensures the table has been truncated by the fixture
    first = await purge_expired(factory)
    second = await purge_expired(factory)
    assert first == 0
    assert second == 0


class FakeStore:
    """Object store double for the janitor: seed objects with last-modified
    times and record what gets deleted."""

    def __init__(self, objects: dict[str, datetime] | None = None) -> None:
        self.objects = dict(objects or {})
        self.deleted: list[str] = []

    def presign_put(self, key: str) -> str:
        return key

    def presign_get(self, key: str) -> str:
        return key

    async def head_size(self, key: str) -> int | None:
        return 1 if key in self.objects else None

    async def delete_keys(self, keys: list[str]) -> None:
        for key in keys:
            self.deleted.append(key)
            self.objects.pop(key, None)

    async def list_objects(self, prefix: str) -> list[tuple[str, datetime]]:
        return [(k, ts) for k, ts in self.objects.items() if k.startswith(prefix)]


def _file_snippet(snippet_id: str, key: str, chunk_count: int, expires_at: datetime) -> Snippet:
    return Snippet(
        id=snippet_id,
        share_mode=ShareMode.link,
        content_type=ContentType.file,
        encrypted_metadata=b"meta",
        ciphertext_inline=None,
        storage_object_key=key,
        chunk_count=chunk_count,
        size_bytes=chunk_count * 1024,
        max_reads=1,
        expires_at=expires_at,
    )


async def test_purge_deletes_r2_chunks_for_expired_file_snippet(
    db_session: AsyncSession, factory: async_sessionmaker[AsyncSession]
) -> None:
    now = datetime.now(tz=UTC)
    db_session.add(_file_snippet("filexpired01", "files/tok1", 2, now - timedelta(hours=1)))
    await db_session.commit()
    store = FakeStore()

    deleted = await purge_expired(factory, store)

    assert deleted == 1
    assert set(store.deleted) == {"files/tok1/0", "files/tok1/1"}


async def test_sweep_reclaims_only_old_unfinalized_prefixes(
    db_session: AsyncSession, factory: async_sessionmaker[AsyncSession]
) -> None:
    now = datetime.now(tz=UTC)
    old = now - timedelta(hours=1)
    fresh = now - timedelta(minutes=5)
    # "files/kept" is referenced by a finalized snippet; the other two are not.
    db_session.add(_file_snippet("keptsnippet1", "files/kept", 1, now + timedelta(hours=1)))
    await db_session.commit()
    store = FakeStore(
        {
            "files/kept/0": old,
            "files/orphanold/0": old,
            "files/orphanold/1": old,
            "files/orphanfresh/0": fresh,
        }
    )

    swept = await sweep_orphans(factory, store, max_age_seconds=30 * 60)

    assert swept == 1  # only files/orphanold
    assert set(store.deleted) == {"files/orphanold/0", "files/orphanold/1"}
    # Finalized prefix and the still-fresh (maybe in-flight) upload are kept.
    assert "files/kept/0" in store.objects
    assert "files/orphanfresh/0" in store.objects


async def test_sweep_noop_without_store(
    db_session: AsyncSession, factory: async_sessionmaker[AsyncSession]
) -> None:
    _ = db_session
    assert await sweep_orphans(factory, None) == 0
