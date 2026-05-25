from __future__ import annotations

import asyncio

import pytest

from app.lib.watch_bus import GoneEvent, ReadEvent, WatchBus


@pytest.fixture
def bus() -> WatchBus:
    return WatchBus()


async def test_subscriber_receives_published_events(bus: WatchBus) -> None:
    queue, _ = await bus.subscribe("abc")
    await bus.publish(ReadEvent(kind="read", snippet_id="abc", read_count=1))
    event = await asyncio.wait_for(queue.get(), timeout=1)
    assert event == ReadEvent(kind="read", snippet_id="abc", read_count=1)


async def test_only_matching_subscribers_receive(bus: WatchBus) -> None:
    a_queue, _ = await bus.subscribe("a")
    b_queue, _ = await bus.subscribe("b")

    await bus.publish(GoneEvent(kind="gone", snippet_id="a", reason="burned"))

    a = await asyncio.wait_for(a_queue.get(), timeout=1)
    assert isinstance(a, GoneEvent)
    assert a.snippet_id == "a"
    assert b_queue.empty()


async def test_multiple_subscribers_for_one_id(bus: WatchBus) -> None:
    q1, _ = await bus.subscribe("z")
    q2, _ = await bus.subscribe("z")
    await bus.publish(ReadEvent(kind="read", snippet_id="z", read_count=1))
    assert (await q1.get()).snippet_id == "z"
    assert (await q2.get()).snippet_id == "z"


async def test_publish_with_no_subscribers_is_noop(bus: WatchBus) -> None:
    # Should not raise even when nobody is listening.
    await bus.publish(ReadEvent(kind="read", snippet_id="never", read_count=1))


async def test_unsubscribe_clears_empty_id_entry(bus: WatchBus) -> None:
    queue, _ = await bus.subscribe("temp")
    await bus.unsubscribe("temp", queue)
    # Re-subscribing should still work after the entry was reaped.
    q2, _ = await bus.subscribe("temp")
    await bus.publish(ReadEvent(kind="read", snippet_id="temp", read_count=3))
    event = await asyncio.wait_for(q2.get(), timeout=1)
    assert event.snippet_id == "temp"
