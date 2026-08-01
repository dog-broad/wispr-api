from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.snippets import ContentType
from app.schemas.snippets import Base64Field


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


# --- data export (M19) --------------------------------------------------------
# ``ciphertext`` is null + ``stored`` true for R2-backed file content, whose
# bytes aren't embedded; its encrypted_metadata (name/mime) still is, and it
# can be re-downloaded while the service is up.


class ExportSyncItem(BaseModel):
    id: str
    content_type: ContentType
    ciphertext: Base64Field | None
    stored: bool
    wrapped_dek: Base64Field
    wrapped_dek_iv: Base64Field
    encrypted_metadata: Base64Field
    created_at: datetime


class ExportPinItem(BaseModel):
    id: str
    content_type: ContentType
    ciphertext: Base64Field | None
    stored: bool
    # The server-unwrapped raw content key. PIN-share is server-key, not
    # zero-knowledge: the server already holds the wrapping key, so handing the
    # unwrapped key to the authenticated owner adds no exposure.
    content_key: Base64Field
    encrypted_metadata: Base64Field
    created_at: datetime


class ExportBundle(BaseModel):
    version: int = 1
    exported_at: datetime
    # PBKDF2 salt so the offline decryptor can re-derive the master KEK from the
    # passphrase. Null only if the account never set a passphrase.
    master_key_salt: Base64Field | None
    sync: list[ExportSyncItem]
    pins: list[ExportPinItem]
