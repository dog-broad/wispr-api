from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Literal

# In-process pub/sub for watch-for-reads. The CAS path in the snippets
# route publishes a read or gone event when a snippet's state changes;
# WebSocket subscribers receive the event and stream it to the sender.
#
# Single-VM deployment means an in-process bus is enough — cross-host
# fan-out would need Redis pub/sub but isn't on the M2 path. The
# registry is the live state; the durable Snippet row is the truth
# source for everything else (snapshot read on attach, gone reasons).


@dataclass(frozen=True, slots=True)
class ReadEvent:
    kind: Literal["read"]
    snippet_id: str
    read_count: int


@dataclass(frozen=True, slots=True)
class GoneEvent:
    kind: Literal["gone"]
    snippet_id: str
    reason: Literal["expired", "burned", "taken_down"]


WatchEvent = ReadEvent | GoneEvent


class WatchBus:
    """Snippet-keyed pub/sub. Subscribers receive an ``asyncio.Queue``
    of ``WatchEvent`` instances they can drain in a loop until the
    snippet ends or the WebSocket closes.

    Concurrency: every mutation guards the ``_subscribers`` map with a
    single lock. Per-subscriber queues are unbounded — events are tiny
    and the publisher should never block on a slow consumer.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[WatchEvent]]] = {}
        self._lock = asyncio.Lock()

    async def publish(self, event: WatchEvent) -> None:
        async with self._lock:
            listeners = list(self._subscribers.get(event.snippet_id, ()))
        for queue in listeners:
            queue.put_nowait(event)

    async def subscribe(
        self, snippet_id: str
    ) -> tuple[asyncio.Queue[WatchEvent], asyncio.Lock]:
        """Register a listener and return its queue. Callers should
        use ``listen()`` instead of touching the queue directly — it
        wires the cleanup correctly when the listener task ends."""
        queue: asyncio.Queue[WatchEvent] = asyncio.Queue()
        async with self._lock:
            self._subscribers.setdefault(snippet_id, set()).add(queue)
        return queue, self._lock

    async def unsubscribe(
        self, snippet_id: str, queue: asyncio.Queue[WatchEvent]
    ) -> None:
        async with self._lock:
            listeners = self._subscribers.get(snippet_id)
            if listeners is None:
                return
            listeners.discard(queue)
            if not listeners:
                # Drop the empty set so the map doesn't grow unbounded
                # over a long-running process with churn through ids.
                del self._subscribers[snippet_id]

    async def listen(self, snippet_id: str) -> AsyncIterator[WatchEvent]:
        """Async generator that yields events for ``snippet_id`` until
        the consumer cancels. Handles registration / cleanup."""
        queue, _ = await self.subscribe(snippet_id)
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            await self.unsubscribe(snippet_id, queue)

    def reset_for_tests(self) -> None:
        """Synchronous wipe used between tests. Not safe to call against
        a running app."""
        self._subscribers.clear()


# Module-level singleton. Routes import this; tests use ``reset_for_tests``.
bus = WatchBus()
