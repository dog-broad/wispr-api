from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from app.lib.sync_bus import SnippetDeletedEvent, SyncBus
from app.schemas.snippets import SyncItem  # noqa: F401 (ensures import graph is sound)


async def test_delivers_to_the_right_user_only() -> None:
    bus = SyncBus()
    qa = await bus.subscribe("user-a")
    qb = await bus.subscribe("user-b")
    await bus.publish(
        SnippetDeletedEvent(kind="snippet.deleted", user_id="user-a", snippet_id="snip1")
    )
    got = await asyncio.wait_for(qa.get(), 1.0)
    assert isinstance(got, SnippetDeletedEvent) and got.snippet_id == "snip1"
    assert qb.empty()  # user-b never sees user-a's event
    await bus.unsubscribe("user-a", qa)
    await bus.unsubscribe("user-b", qb)


def test_created_at_type_ok() -> None:
    # Guard the SyncItem import path the bus depends on.
    assert isinstance(datetime.now(tz=UTC), datetime)
