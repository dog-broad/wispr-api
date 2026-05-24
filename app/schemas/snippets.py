from __future__ import annotations

import base64
import enum
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, PlainSerializer, model_validator

from app.models.snippets import ContentType, ShareMode


def _b64_decode(value: object) -> bytes:
    """Decode a base64 input on the way in.

    Accepts either a base64 string (the JSON wire form) or raw bytes
    (e.g. when constructing a response model from a SQLAlchemy row);
    raw bytes pass through unchanged so the inverse of `_b64_encode`
    holds.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return base64.b64decode(value)
    raise TypeError("expected base64 string or bytes")


def _b64_encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


# Bytes field that round-trips cleanly: JSON input is a base64 string,
# Python input is raw bytes, JSON output is always a base64 string.
Base64Field = Annotated[
    bytes,
    BeforeValidator(_b64_decode),
    PlainSerializer(_b64_encode, return_type=str, when_used="json"),
]

# Anonymous link payload caps. These match the inline-only ceiling for the
# first ship cycle; chunked file uploads (R2) push the ciphertext bound up
# but live in a later phase.
MAX_CIPHERTEXT_BYTES = 64 * 1024
MAX_ENCRYPTED_METADATA_BYTES = 4 * 1024

# TTL bounds for anonymous link mode: floor at one minute (no instant burn
# races), ceiling at 24 hours per the lifetime cap.
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 24 * 60 * 60


class CreateLinkSnippetRequest(BaseModel):
    """Body for `POST /snippets` when share_mode=link.

    The schema is mode-specific by design: any payload that doesn't pin
    share_mode to "link" is rejected by Pydantic before the handler runs.
    Pin-share and sync shapes will get their own schemas when those modes
    land in later phases.
    """

    model_config = ConfigDict(extra="forbid")

    share_mode: Literal[ShareMode.link]
    content_type: ContentType
    ciphertext: Base64Field = Field(..., max_length=MAX_CIPHERTEXT_BYTES)
    encrypted_metadata: Base64Field = Field(..., max_length=MAX_ENCRYPTED_METADATA_BYTES)
    ttl_seconds: int = Field(..., ge=MIN_TTL_SECONDS, le=MAX_TTL_SECONDS)
    max_reads: Literal[1] = 1
    password_hash: Base64Field | None = None
    password_salt: Base64Field | None = None

    @model_validator(mode="after")
    def _password_pair(self) -> Self:
        has_hash = self.password_hash is not None
        has_salt = self.password_salt is not None
        if has_hash != has_salt:
            raise ValueError(
                "password_hash and password_salt must be provided together or omitted together"
            )
        return self


class CreateSnippetResponse(BaseModel):
    id: str
    expires_at: datetime


class GoneReason(enum.StrEnum):
    expired = "expired"
    burned = "burned"
    taken_down = "taken_down"


class GoneResponse(BaseModel):
    status: Literal["gone"] = "gone"
    reason: GoneReason


class GetSnippetResponse(BaseModel):
    id: str
    share_mode: ShareMode
    content_type: ContentType
    ciphertext: Base64Field
    encrypted_metadata: Base64Field
    size_bytes: int
    created_at: datetime
    expires_at: datetime | None
    max_reads: int | None
    read_count: int
