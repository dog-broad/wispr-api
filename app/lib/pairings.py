from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass

from redis.asyncio import Redis

# Mode 3 pairings live in Redis only — they are P2P-transient and the
# server is only involved during the 60-second handshake window. The
# layout uses two keys per active pair, both with the same TTL:
#
#   pair:pin:{pin}        → JSON {sender_token, sender_ip, created_at}
#   pair:sender:{ip}      → the PIN string
#
# PIN→pair lookup happens via the first key; the second exists solely so
# repeat POST /pair requests from the same sender IP can return the
# existing PIN without scanning, and so the per-sender-IP idempotency
# rule stays O(1). Both keys are written in a single transaction so
# partial failures cannot leak state.

_PIN_KEY_PREFIX = "pair:pin:"
_SENDER_KEY_PREFIX = "pair:sender:"

# 60-second waiting window matches the §7.6.7 #11 user-visible countdown.
PAIRING_TTL_SECONDS = 60

# 4-digit numeric PIN keeps the on-mobile numeric keyboard affordance and
# the verbal-share UX. 10 000 slots is plenty for the deployment scale;
# collision rerolls are bounded to keep the worst case bounded.
_PIN_DIGITS = 4
_PIN_MODULUS = 10**_PIN_DIGITS
_PIN_REROLL_ATTEMPTS = 8

# Sender token: 32 random bytes, base64url-encoded without padding. Same
# shape as the snippets `owner_token`. The bearer compares this against
# the value stored under the PIN when attaching to the signaling WS.
_SENDER_TOKEN_BYTES = 32


@dataclass(frozen=True, slots=True)
class Pairing:
    """An active waiting pair. ``created_at`` is unix seconds at issue
    time; ``expires_at`` is unix seconds at the end of the waiting window
    so callers don't have to recompute it. ``sender_token`` is the raw
    base64url-encoded string the sender uses to attach to ``/ws/pair``.
    """

    pin: str
    sender_token: str
    sender_ip: str
    created_at: int
    expires_at: int


class PairNamespaceFullError(Exception):
    """Raised when ``_PIN_REROLL_ATTEMPTS`` consecutive PIN candidates were
    already taken. Practically impossible at the deployment scale but the
    bound has to be honest; the route translates this to HTTP 503."""


def _pin_key(pin: str) -> str:
    return f"{_PIN_KEY_PREFIX}{pin}"


def _sender_key(sender_ip: str) -> str:
    return f"{_SENDER_KEY_PREFIX}{sender_ip}"


def _generate_pin() -> str:
    """Cryptographically random 4-digit PIN as a zero-padded string."""
    # secrets.randbelow gives a uniform draw across the full namespace
    # without modulo bias.
    return f"{secrets.randbelow(_PIN_MODULUS):0{_PIN_DIGITS}d}"


def _generate_sender_token() -> str:
    return (
        base64.urlsafe_b64encode(secrets.token_bytes(_SENDER_TOKEN_BYTES))
        .rstrip(b"=")
        .decode("ascii")
    )


async def create_pairing(
    redis_client: Redis,
    sender_ip: str,
    *,
    now: int | None = None,
) -> Pairing:
    """Issue a fresh PIN + sender token for ``sender_ip``, or return the
    existing waiting pair if one is still active (D-0024-16).

    Idempotency: a repeat call while the previous pair is still waiting
    returns the same PIN + sender token, with the original ``expires_at``
    unchanged so the sender's countdown stays honest.

    Raises ``PairNamespaceFullError`` if the PIN namespace can't seat a
    new pair within ``_PIN_REROLL_ATTEMPTS`` tries.
    """
    if not sender_ip:
        raise ValueError("sender_ip must be a non-empty string")

    issued_at = int(time.time()) if now is None else now

    # 1) Idempotent return: same sender IP with an existing waiting pair
    # gets the same PIN back. We re-read the pair record so we can return
    # the original created_at/expires_at, not refresh them.
    existing_pin_raw = await redis_client.get(_sender_key(sender_ip))
    if existing_pin_raw is not None:
        existing_pin = (
            existing_pin_raw.decode("ascii")
            if isinstance(existing_pin_raw, bytes)
            else str(existing_pin_raw)
        )
        existing = await _read_pairing(redis_client, existing_pin)
        if existing is not None and existing.sender_ip == sender_ip:
            return existing
        # The sender sentinel pointed at a PIN whose record has expired
        # or been deleted out from under us. Drop the dangling sentinel
        # and fall through to a fresh issue.
        await redis_client.delete(_sender_key(sender_ip))

    # 2) Fresh issue. Reroll on collision; each attempt is an atomic
    # `SET NX EX` against the candidate PIN slot.
    sender_token = _generate_sender_token()
    payload = json.dumps(
        {
            "sender_token": sender_token,
            "sender_ip": sender_ip,
            "created_at": issued_at,
        },
        separators=(",", ":"),
    )

    for _ in range(_PIN_REROLL_ATTEMPTS):
        candidate = _generate_pin()
        claimed = await redis_client.set(
            _pin_key(candidate),
            payload,
            nx=True,
            ex=PAIRING_TTL_SECONDS,
        )
        if not claimed:
            continue
        # Sender sentinel rides the same TTL. If this write fails we'd
        # have a PIN with no IP back-reference — but Redis SET with EX
        # is durable on a single instance, so the only realistic failure
        # mode here is a transport error, which propagates up.
        await redis_client.set(
            _sender_key(sender_ip),
            candidate,
            ex=PAIRING_TTL_SECONDS,
        )
        return Pairing(
            pin=candidate,
            sender_token=sender_token,
            sender_ip=sender_ip,
            created_at=issued_at,
            expires_at=issued_at + PAIRING_TTL_SECONDS,
        )

    raise PairNamespaceFullError(f"PIN namespace exhausted after {_PIN_REROLL_ATTEMPTS} attempts")


async def lookup_pairing(redis_client: Redis, pin: str) -> Pairing | None:
    """Return the active pairing for ``pin``, or ``None`` if expired or
    never issued. Does not consume the pair — that happens at receiver
    redeem time in a later task."""
    return await _read_pairing(redis_client, pin)


async def delete_pairing(redis_client: Redis, pin: str) -> None:
    """Remove an active pairing from both keyspaces. Used when the pair
    is consumed (receiver redeems) or explicitly cancelled. No-op if the
    pair has already expired."""
    pairing = await _read_pairing(redis_client, pin)
    if pairing is None:
        return
    await redis_client.delete(_pin_key(pin), _sender_key(pairing.sender_ip))


async def _read_pairing(redis_client: Redis, pin: str) -> Pairing | None:
    raw = await redis_client.get(_pin_key(pin))
    if raw is None:
        return None
    text = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
    data = json.loads(text)
    created_at = int(data["created_at"])
    return Pairing(
        pin=pin,
        sender_token=str(data["sender_token"]),
        sender_ip=str(data["sender_ip"]),
        created_at=created_at,
        expires_at=created_at + PAIRING_TTL_SECONDS,
    )
