from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from starlette.websockets import WebSocketDisconnect

from app.config import get_settings
from app.db import get_session
from app.lib.tokens import hash_token
from app.main import app
from app.models.accounts import Session as SessionRow
from app.models.accounts import User


@pytest.fixture(autouse=True)
def _portal_bound_db() -> Iterator[None]:
    """The WS runs on the TestClient's own event loop, but the app's global
    engine is bound to pytest's session loop by the HTTP tests. Override
    get_session with a NullPool engine created on the portal loop so the DB
    connection never crosses loops."""

    async def _session() -> AsyncIterator[AsyncSession]:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                yield session
        finally:
            await engine.dispose()

    app.dependency_overrides[get_session] = _session
    yield
    app.dependency_overrides.pop(get_session, None)


_NULL_PROVIDERS = {
    "resend_api_key": None,
    "sentry_api_token": None,
    "sentry_org": None,
    "sentry_project": None,
    "cloudflare_api_token": None,
    "cloudflare_account_id": None,
    "cloudflare_zone_id": None,
}


async def _seed_admin(token: str, *, is_admin: bool = True) -> None:
    # A separate engine on this asyncio.run loop, so it never fights the global
    # engine the WS route uses on the TestClient portal loop.
    engine = create_async_engine(get_settings().database_url)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        user = User(email="wsadmin@example.com", auth_credential_hash=b"x", is_admin=is_admin)
        session.add(user)
        await session.flush()
        session.add(SessionRow(user_id=user.id, token_hash=hash_token(token), device_label="t"))
        await session.commit()
    await engine.dispose()


async def _truncate() -> None:
    engine = create_async_engine(get_settings().database_url)
    async with engine.begin() as conn:
        await conn.execute(sa_text("TRUNCATE TABLE users, snippets CASCADE"))
    await engine.dispose()


def test_admin_ws_rejects_non_admin(ws_client: TestClient) -> None:
    with (
        pytest.raises(WebSocketDisconnect) as exc,
        ws_client.websocket_connect("/ws/admin") as ws,
    ):
        ws.receive_text()
    assert exc.value.code == 1008


def test_admin_ws_sends_snapshot(ws_client: TestClient) -> None:
    asyncio.run(_truncate())
    token = "wsadmin-token"
    asyncio.run(_seed_admin(token))
    app.state.http_client = httpx.AsyncClient()
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update=_NULL_PROVIDERS
    )
    ws_client.cookies.set("wispr_session", token)
    try:
        with ws_client.websocket_connect("/ws/admin") as ws:
            message = json.loads(ws.receive_text())
    finally:
        ws_client.cookies.clear()
        app.dependency_overrides.pop(get_settings, None)
        asyncio.run(_truncate())

    assert message["op"] == "snapshot"
    dashboard = message["dashboard"]
    assert dashboard["status"] in {"ok", "warn", "alert"}
    # The api health row is always present; providers are all "?" (no keys).
    assert "api" in {m["key"] for m in dashboard["health"]}
    assert all(q["status"] == "unknown" for q in dashboard["quotas"])
