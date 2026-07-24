from __future__ import annotations

import asyncio
import enum
from dataclasses import dataclass

from fastapi import WebSocket

# Per-frame ceiling on signaling messages. PROJECT.md §6 says "≤ 16 KiB
# per signal message"; SDP and ICE candidates are well under that in
# practice. The cap exists to bound a misbehaving or malicious client
# more than to gate legitimate WebRTC traffic.
MAX_SIGNAL_FRAME_BYTES = 16 * 1024

# Receiver-side PIN-redeem buckets. Numbers per PROJECT.md §12.
REDEEM_BURST_PER_MINUTE = 5
REDEEM_BURST_PER_HOUR = 30


class PairFailReason(enum.StrEnum):
    """Wire reasons accompanying every ``pair_failed`` op the server
    sends. The receiver-side §7.6.7 outcomes map onto these one-to-one;
    web client code branches on the string directly so it can render the
    spec'd copy without re-interpreting numeric codes.
    """

    unknown_pin = "unknown_pin"  # §7.6.7 #12 — PIN not in either namespace
    sender_offline = "sender_offline"  # §7.6.7 #9
    already_redeemed = "already_redeemed"  # §7.6.7 #10
    rate_limited_minute = "rate_limited_minute"  # §7.6.7 #13
    rate_limited_hour = "rate_limited_hour"  # §7.6.7 #14
    bad_op = "bad_op"  # malformed or whitelisted-out envelope
    bad_envelope = "bad_envelope"  # JSON parse failure or shape mismatch
    oversized_signal = "oversized_signal"  # frame exceeded MAX_SIGNAL_FRAME_BYTES
    premature_signal = "premature_signal"  # signal arrived before pair was established
    unknown_token = "unknown_token"  # noqa: S105 — wire reason string, not a credential
    duplicate_sender = "duplicate_sender"  # second sender attach for the same PIN


class AttachOutcome(enum.StrEnum):
    """Outcome of ``attach_receiver``. Distinct from ``PairFailReason``
    because the registry doesn't know about §7.6.7 numbering; the route
    translates."""

    ok = "ok"
    sender_offline = "sender_offline"
    already_redeemed = "already_redeemed"


@dataclass(slots=True)
class ActivePair:
    """In-process state for a pair whose sender has attached its WS.
    ``receiver_ws`` is filled in when the receiver successfully redeems.
    Holding the IP on the record lets the route audit-log without
    re-reading from Redis (and Redis state vanishes 60s after issue)."""

    pin: str
    sender_token: str
    sender_ip: str
    sender_ws: WebSocket
    receiver_ws: WebSocket | None = None


class PairSignalingRegistry:
    """Lifetime registry of live signaling pairs, keyed by PIN.

    The registry is process-local — Redis owns the durable issue-time
    state ([D-260525-02]), this owns the live-socket state. Single-VM
    deployment makes a process-local dict sufficient; cross-host
    signaling is out of scope for v1 and would require a pub/sub bus.
    """

    def __init__(self) -> None:
        self._by_pin: dict[str, ActivePair] = {}
        self._lock = asyncio.Lock()

    async def register_sender(
        self,
        pin: str,
        sender_token: str,
        sender_ip: str,
        ws: WebSocket,
    ) -> bool:
        """Claim the PIN slot for a sender WS. Returns False if some
        other sender already holds it (D-0024-16 says only one active
        waiting pair per sender IP, but a duplicate attach via the same
        token can race in)."""
        async with self._lock:
            if pin in self._by_pin:
                return False
            self._by_pin[pin] = ActivePair(
                pin=pin,
                sender_token=sender_token,
                sender_ip=sender_ip,
                sender_ws=ws,
            )
            return True

    async def attach_receiver(
        self, pin: str, ws: WebSocket
    ) -> tuple[ActivePair | None, AttachOutcome]:
        """Bind a receiver WS to an active pair. The pair is single-use:
        a second receiver hitting the same PIN gets
        ``AttachOutcome.already_redeemed`` and the first receiver keeps
        the slot."""
        async with self._lock:
            active = self._by_pin.get(pin)
            if active is None:
                return None, AttachOutcome.sender_offline
            if active.receiver_ws is not None:
                return None, AttachOutcome.already_redeemed
            active.receiver_ws = ws
            return active, AttachOutcome.ok

    async def get(self, pin: str) -> ActivePair | None:
        async with self._lock:
            return self._by_pin.get(pin)

    async def remove(self, pin: str) -> ActivePair | None:
        async with self._lock:
            return self._by_pin.pop(pin, None)

    def active_count(self) -> int:
        """Number of live signaling pairs (sender attached). Best-effort read
        for the operator dashboard."""
        return len(self._by_pin)

    def reset_for_tests(self) -> None:
        """Synchronous wipe used between tests to keep state-bleed out
        of the suite. Not safe to call against a running app."""
        self._by_pin.clear()


# Module-level singleton. The route reaches in for it; tests use
# ``reset_for_tests`` to clear state between cases.
registry = PairSignalingRegistry()
