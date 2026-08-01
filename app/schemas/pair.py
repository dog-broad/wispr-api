from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class CreatePairResponse(BaseModel):
    """Body returned by POST /pair.

    ``sender_token`` is the opaque bearer the sender presents when
    attaching to ``/ws/pair``; the server compares it constant-time
    against the value stored alongside the PIN. ``expires_at`` is the
    end of the 60-second waiting window: when the same sender retries
    while a pair is still active, this value reflects the original
    issue time (not refreshed) so the on-screen countdown stays honest.
    """

    pin: str
    sender_token: str
    expires_at: datetime
