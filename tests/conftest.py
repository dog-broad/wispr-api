from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis, from_url
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.lib.ratelimit import snippets_create_anon_limit, snippets_get_limit
from app.main import app

_TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    os.environ.get("DATABASE_URL", "postgresql+asyncpg://wispr:wispr@localhost:5432/wispr"),
)
_TEST_REDIS_URL = os.environ.get(
    "TEST_REDIS_URL",
    os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
)
_REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """ASGI client with no database or redis wiring. Use this for endpoints
    that do not call `Depends(get_session)` or rate-limit deps."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _run_alembic_upgrade() -> None:
    """Run `alembic upgrade head` against the test database. Done in a
    subprocess so alembic's internal asyncio loop does not collide with
    pytest-asyncio's running loop."""
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        check=True,
        cwd=_REPO_ROOT,
        env={**os.environ, "DATABASE_URL": _TEST_DATABASE_URL},
    )


@pytest.fixture(scope="session")
def _migrated_database() -> None:
    _run_alembic_upgrade()


@pytest.fixture
async def db_session(_migrated_database: None) -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(_TEST_DATABASE_URL, pool_pre_ping=True)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    try:
        async with maker() as session:
            yield session
    finally:
        async with maker() as cleanup:
            await cleanup.execute(sa_text("TRUNCATE TABLE snippets CASCADE"))
            await cleanup.commit()
        await engine.dispose()


@pytest.fixture
async def redis_client() -> AsyncIterator[Redis]:
    """Connected redis client backed by the docker-compose service. Flushes
    the configured DB on entry so cases don't see each other's bucket state.

    Most tests should depend on this transitively through `db_client`
    (which mounts the client on `app.state.redis` and bypasses rate
    limiting). Tests that exercise the limiter itself depend on this
    directly and skip the override."""
    client: Redis = from_url(_TEST_REDIS_URL, encoding="utf-8", decode_responses=False)
    try:
        await client.flushdb()
        yield client
    finally:
        await client.aclose()


async def _noop_rate_limit() -> None:
    return None


@pytest.fixture
async def db_client(
    db_session: AsyncSession, redis_client: Redis
) -> AsyncIterator[AsyncClient]:
    """ASGI client backed by the test database. Rate-limit dependencies are
    overridden to no-ops so endpoint tests stay focused on their own
    behaviour; tests that exercise the limiter use `rate_limit_client`."""
    _ = db_session  # establish the dependency chain
    app.state.redis = redis_client
    app.dependency_overrides[snippets_create_anon_limit] = _noop_rate_limit
    app.dependency_overrides[snippets_get_limit] = _noop_rate_limit
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.pop(snippets_create_anon_limit, None)
        app.dependency_overrides.pop(snippets_get_limit, None)


@pytest.fixture
async def rate_limit_client(
    db_session: AsyncSession, redis_client: Redis
) -> AsyncIterator[AsyncClient]:
    """ASGI client with the real rate-limit dependencies attached so a test
    can observe 429s. Tests that need a particular IP set the
    ``CF-Connecting-IP`` header on each request."""
    _ = db_session
    app.state.redis = redis_client
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
