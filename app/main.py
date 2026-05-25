from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.db import async_session_maker
from app.jobs.purge import run_purge_loop
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.redis_client import close_redis, open_redis
from app.routes import health, pair, pair_ws, snippet_watch, snippets

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    app.state.redis = await open_redis()
    stop_event = asyncio.Event()
    purge_task = asyncio.create_task(
        run_purge_loop(
            async_session_maker,
            settings.purge_interval_seconds,
            stop_event,
        ),
        name="purge-loop",
    )
    try:
        yield
    finally:
        stop_event.set()
        try:
            await asyncio.wait_for(purge_task, timeout=10)
        except TimeoutError:
            logger.warning("purge: shutdown timeout, cancelling")
            purge_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await purge_task
        await close_redis(app.state.redis)


def create_app() -> FastAPI:
    settings = get_settings()

    # Honour LOG_LEVEL for our own loggers so messages from app.jobs.* and
    # app.routes.* surface alongside uvicorn's. Uvicorn configures its own
    # logger tree, which by default leaves the root logger at WARNING.
    logging.basicConfig(level=settings.log_level.upper(), force=True)

    app = FastAPI(
        title="Wispr API",
        version="0.0.0",
        lifespan=lifespan,
    )

    # Middleware order: Starlette runs them last-added → first-executed,
    # so security headers wrap CORS, ensuring our headers are present even
    # on a CORS preflight reply.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(health.router)
    app.include_router(snippets.router)
    app.include_router(snippet_watch.router)
    app.include_router(pair.router)
    app.include_router(pair_ws.router)

    return app


app = create_app()
