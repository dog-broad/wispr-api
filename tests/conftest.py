from __future__ import annotations

import contextlib
import os
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest
import redis as sync_redis
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis, from_url
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.lib.pair_signaling import registry as pair_signaling_registry
from app.lib.ratelimit import (
    by_pin_hour_limit,
    by_pin_minute_limit,
    files_presign_limit,
    pair_create_limit,
    reports_limit,
    snippets_create_anon_limit,
    snippets_get_limit,
    verify_password_limit,
)
from app.main import app

# Rate-limit deps stubbed out by the DB/redis-only clients so endpoint tests
# focus on behaviour, not limits. Tests that exercise a limiter use the
# rate_limit_client instead.
_STUBBED_LIMITS = (
    snippets_create_anon_limit,
    snippets_get_limit,
    pair_create_limit,
    verify_password_limit,
    by_pin_minute_limit,
    by_pin_hour_limit,
    files_presign_limit,
    reports_limit,
)

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


async def _truncate_all(maker: async_sessionmaker[AsyncSession]) -> None:
    # TRUNCATE ... CASCADE on users clears every account-scoped table
    # (sessions, magic_link_tokens, invites, passphrase_lockouts,
    # email_change_requests, and owned snippets) via their ON DELETE CASCADE
    # FKs; snippets is named explicitly to also clear anonymous rows with no
    # owner.
    async with maker() as cleanup:
        await cleanup.execute(sa_text("TRUNCATE TABLE users, snippets CASCADE"))
        await cleanup.commit()


@pytest.fixture
async def db_session(_migrated_database: None) -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(_TEST_DATABASE_URL, pool_pre_ping=True)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    try:
        # Truncate on the way IN as well as out, so a test starts clean even if
        # local dev activity (a manual seed, an ad-hoc curl) left rows behind
        # in the shared database. Teardown truncation keeps the DB tidy after.
        await _truncate_all(maker)
        async with maker() as session:
            yield session
    finally:
        await _truncate_all(maker)
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
async def db_client(db_session: AsyncSession, redis_client: Redis) -> AsyncIterator[AsyncClient]:
    """ASGI client backed by the test database. Rate-limit dependencies are
    overridden to no-ops so endpoint tests stay focused on their own
    behaviour; tests that exercise the limiter use `rate_limit_client`."""
    _ = db_session  # establish the dependency chain
    app.state.redis = redis_client
    # The real lifespan (which sets this) doesn't run under ASGITransport, so
    # provide the shared HTTP client that routes use for outbound calls.
    app.state.http_client = httpx.AsyncClient()
    for _limit in _STUBBED_LIMITS:
        app.dependency_overrides[_limit] = _noop_rate_limit
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        await app.state.http_client.aclose()
        for _limit in _STUBBED_LIMITS:
            app.dependency_overrides.pop(_limit, None)


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


@pytest.fixture
async def redis_only_client(redis_client: Redis) -> AsyncIterator[AsyncClient]:
    """ASGI client backed by redis but not the database. Use for routes
    that never touch Postgres (e.g. /pair) so the test doesn't need the
    DB container running. Rate-limit deps are overridden to no-ops."""
    app.state.redis = redis_client
    for _limit in _STUBBED_LIMITS:
        app.dependency_overrides[_limit] = _noop_rate_limit
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        for _limit in _STUBBED_LIMITS:
            app.dependency_overrides.pop(_limit, None)


@pytest.fixture
async def redis_only_rate_limit_client(redis_client: Redis) -> AsyncIterator[AsyncClient]:
    """ASGI client backed by redis with the real rate-limit deps attached.
    DB-free counterpart to ``rate_limit_client`` for /pair tests."""
    app.state.redis = redis_client
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def ws_redis() -> Iterator[sync_redis.Redis]:
    """Sync Redis client for seeding state outside the WS handler.

    The async Redis client lazily binds its connection pool to whichever
    asyncio loop first awaits it. WebSocket tests use Starlette's
    ``TestClient`` which runs the ASGI app on its own anyio portal loop,
    distinct from pytest-asyncio's session loop — so the route's async
    Redis calls must happen on the portal loop, not the pytest one.

    Test setup therefore seeds redis through the sync client (no loop
    binding) and lets the route's app-mounted async Redis bind itself
    cleanly inside the portal. ``flushdb`` clears state per case.
    """
    client: sync_redis.Redis = sync_redis.Redis.from_url(_TEST_REDIS_URL, decode_responses=False)
    client.flushdb()
    try:
        yield client
    finally:
        client.close()


@contextlib.asynccontextmanager
async def _redis_only_lifespan(app_: object) -> AsyncIterator[None]:
    """Lifespan for WS tests — opens redis on the portal loop, skips
    the snippets-purge task.

    Two reasons this exists:

    1. The async redis client must bind to whichever loop will await it.
       Creating it in pytest's main thread (no loop running) and then
       awaiting it on Starlette's TestClient portal loop has produced
       flaky ``sender_offline`` failures on full-PIN-pair flows where
       the route's redis lookup silently fails.
    2. The real lifespan also spawns ``run_purge_loop``, which connects
       to Postgres on its first iteration. With no DB container running
       that connect noisily fails, and a lingering purge task per
       TestClient instance accumulates across the suite.

    Opening redis here, on the portal loop, fixes both: every fixture
    enters a fresh lifespan, redis is loop-bound cleanly, and shutdown
    closes the same instance on the same loop.
    """
    from app.redis_client import close_redis, open_redis  # local: keep top of file tidy

    state = app_  # the FastAPI app instance Starlette passes in
    state.state.redis = await open_redis()  # type: ignore[attr-defined]
    try:
        yield
    finally:
        await close_redis(state.state.redis)  # type: ignore[attr-defined]


@pytest.fixture
def ws_client(ws_redis: sync_redis.Redis) -> Iterator[TestClient]:
    """Sync ``TestClient`` for WebSocket-bearing routes.

    Lifespan is replaced with a redis-only one (see ``_redis_only_lifespan``).
    HTTP rate-limit deps are stubbed (the WS route has its own inline
    limiter). The in-process signaling registry is wiped between cases.
    """
    _ = ws_redis  # establish dependency order; ws_redis flushes first
    for _limit in _STUBBED_LIMITS:
        app.dependency_overrides[_limit] = _noop_rate_limit
    pair_signaling_registry.reset_for_tests()
    original_lifespan = app.router.lifespan_context
    app.router.lifespan_context = _redis_only_lifespan
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.router.lifespan_context = original_lifespan
        for _limit in _STUBBED_LIMITS:
            app.dependency_overrides.pop(_limit, None)
        pair_signaling_registry.reset_for_tests()
