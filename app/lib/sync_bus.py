from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Literal

from app.schemas.snippets import SyncItem

# In-process pub/sub for the Sync feed, keyed by user id. Snippet create /
# delete publish an event to the owner's topic; a /ws/sync subscriber for that
# user streams it so the /me feed updates live. Single-VM only, same as the
# watch bus — cross-host would need Redis pub/sub.


@dataclass(frozen=True, slots=True)
class SnippetCreatedEvent:
    kind: Literal["snippet.created"]
    user_id: str
    item: SyncItem


@dataclass(frozen=True, slots=True)
class SnippetDeletedEvent:
    kind: Literal["snippet.deleted"]
    user_id: str
    snippet_id: str


SyncEvent = SnippetCreatedEvent | SnippetDeletedEvent


class SyncBus:
    """User-keyed pub/sub. A subscriber drains an ``asyncio.Queue`` of
    ``SyncEvent`` for one user id until its WebSocket closes."""

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[SyncEvent]]] = {}
        self._lock = asyncio.Lock()

    async def publish(self, event: SyncEvent) -> None:
        async with self._lock:
            listeners = list(self._subscribers.get(event.user_id, ()))
        for queue in listeners:
            queue.put_nowait(event)

    async def subscribe(self, user_id: str) -> asyncio.Queue[SyncEvent]:
        queue: asyncio.Queue[SyncEvent] = asyncio.Queue()
        async with self._lock:
            self._subscribers.setdefault(user_id, set()).add(queue)
        return queue

    async def unsubscribe(self, user_id: str, queue: asyncio.Queue[SyncEvent]) -> None:
        async with self._lock:
            listeners = self._subscribers.get(user_id)
            if listeners is None:
                return
            listeners.discard(queue)
            if not listeners:
                del self._subscribers[user_id]

    async def listen(self, user_id: str) -> AsyncIterator[SyncEvent]:
        queue = await self.subscribe(user_id)
        try:
            while True:
                yield await queue.get()
        finally:
            await self.unsubscribe(user_id, queue)

    def connection_count(self) -> int:
        """Best-effort snapshot of live /ws/sync connections (sum across users).
        Lock-free for a cheap metric read; ``list()`` snapshots the values view
        so a concurrent mutation can't raise mid-iteration."""
        return sum(len(s) for s in list(self._subscribers.values()))

    def reset_for_tests(self) -> None:
        self._subscribers.clear()


bus = SyncBus()
