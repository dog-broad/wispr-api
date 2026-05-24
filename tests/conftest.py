from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.main import app

# Tests that touch the database expect a real postgres at TEST_DATABASE_URL
# (or DATABASE_URL as a fallback) — typically the docker-compose service
# brought up via `docker compose up -d db`. Pure-HTTP tests (e.g. /health)
# use the lightweight `client` fixture and never need a database.
_TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    os.environ.get("DATABASE_URL", "postgresql+asyncpg://wispr:wispr@localhost:5432/wispr"),
)
_REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """ASGI client with no database wiring. Use this for endpoints that do
    not call `Depends(get_session)`."""
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
    """Ensure the test database is at head before the first DB-backed test
    runs. Session-scoped so we pay the migration cost once."""
    _run_alembic_upgrade()


@pytest.fixture
async def db_session(_migrated_database: None) -> AsyncIterator[AsyncSession]:
    """Per-test database session for direct assertions. Truncates the
    snippets table after each test so cases don't see each other's rows.

    NOTE: this is *not* the session the handlers receive — they go through
    the real `get_session` dependency and get their own. Sharing one session
    across concurrent requests would deadlock (sessions are not concurrent-
    safe). Use this fixture for setup/teardown or direct row inspection."""
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
async def db_client(db_session: AsyncSession) -> AsyncIterator[AsyncClient]:
    """ASGI client backed by the same test database as `db_session`.

    Depending on this fixture also depends on `db_session`, which means
    the after-test snippets TRUNCATE runs whenever a test uses `db_client`.
    Handlers create their own sessions via the real `get_session` dep —
    no override — so concurrent requests get independent sessions."""
    _ = db_session  # establish the dependency chain
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
