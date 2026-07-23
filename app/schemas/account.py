from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


class SessionInfo(BaseModel):
    id: uuid.UUID
    device_label: str
    created_at: datetime
    last_seen_at: datetime
    # True for the session the requesting cookie belongs to, so the UI can
    # label "this device" and guard against revoking it by accident.
    current: bool


class SessionListResponse(BaseModel):
    sessions: list[SessionInfo]


class InviteResponse(BaseModel):
    code: str


class OkResponse(BaseModel):
    ok: bool = True
