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

# Anonymous link payload caps. The 256 KiB inline-file ceiling
# ([PROJECT.md §10 M2] / §6) drives the ciphertext bound — raw bytes
# plus a 12-byte IV + 16-byte AES-GCM tag fit within 257 KiB; we pad
# to 264 KiB so a small amount of base64-decoding slack doesn't
# bounce a legitimate request. Chunked file uploads (R2) push this
# further but live in M3.
MAX_CIPHERTEXT_BYTES = 264 * 1024
MAX_ENCRYPTED_METADATA_BYTES = 4 * 1024

# TTL bounds for anonymous link mode: floor at one minute (no instant burn
# races), ceiling at 24 hours per the lifetime cap.
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 24 * 60 * 60

# Password-gate bounds. The hash output is fixed at PBKDF2-SHA-256 with
# a 32-byte derived key; the salt is a fresh 16-byte random value per
# snippet. Anything else on the wire is a malformed request.
PASSWORD_HASH_BYTES = 32
PASSWORD_SALT_BYTES = 16


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
    # Per [D-260526-01], both fields are client-computed: the client
    # generates a fresh 16-byte salt and a 32-byte PBKDF2-SHA-256 hash
    # (100 000 iterations) at create time. The server only stores them.
    password_hash: Base64Field | None = Field(default=None, max_length=PASSWORD_HASH_BYTES)
    password_salt: Base64Field | None = Field(default=None, max_length=PASSWORD_SALT_BYTES)

    @model_validator(mode="after")
    def _password_pair(self) -> Self:
        has_hash = self.password_hash is not None
        has_salt = self.password_salt is not None
        if has_hash != has_salt:
            raise ValueError(
                "password_hash and password_salt must be provided together or omitted together"
            )
        if self.password_hash is not None and len(self.password_hash) != PASSWORD_HASH_BYTES:
            raise ValueError(f"password_hash must be exactly {PASSWORD_HASH_BYTES} bytes")
        if self.password_salt is not None and len(self.password_salt) != PASSWORD_SALT_BYTES:
            raise ValueError(f"password_salt must be exactly {PASSWORD_SALT_BYTES} bytes")
        return self


# PIN-share (Mode 2). Longer TTL ceiling than link (up to 7 days) and a
# raw 32-byte content key the server wraps at rest. max_reads may be null
# (unlimited within TTL).
PIN_MAX_TTL_SECONDS = 7 * 24 * 60 * 60
CONTENT_KEY_BYTES = 32
PIN_MAX_READS_CEILING = 1000


class CreatePinShareSnippetRequest(BaseModel):
    """Body for `POST /snippets` when share_mode=pin_share (members only).

    Unlike link, the client sends the raw ``content_key`` — Mode 2 is
    encryption-at-rest under operator trust, not zero-knowledge. The server
    wraps the key with the key-vault master before storing it.
    """

    model_config = ConfigDict(extra="forbid")

    share_mode: Literal[ShareMode.pin_share]
    content_type: ContentType
    ciphertext: Base64Field = Field(..., max_length=MAX_CIPHERTEXT_BYTES)
    content_key: Base64Field = Field(..., max_length=CONTENT_KEY_BYTES)
    encrypted_metadata: Base64Field = Field(..., max_length=MAX_ENCRYPTED_METADATA_BYTES)
    ttl_seconds: int = Field(..., ge=MIN_TTL_SECONDS, le=PIN_MAX_TTL_SECONDS)
    # null = unlimited reads within the TTL.
    max_reads: int | None = Field(default=None)
    password_hash: Base64Field | None = Field(default=None, max_length=PASSWORD_HASH_BYTES)
    password_salt: Base64Field | None = Field(default=None, max_length=PASSWORD_SALT_BYTES)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if len(self.content_key) != CONTENT_KEY_BYTES:
            raise ValueError(f"content_key must be exactly {CONTENT_KEY_BYTES} bytes")
        if self.max_reads is not None and not (1 <= self.max_reads <= PIN_MAX_READS_CEILING):
            raise ValueError(f"max_reads must be null or between 1 and {PIN_MAX_READS_CEILING}")
        if (self.password_hash is None) != (self.password_salt is None):
            raise ValueError("password_hash and password_salt must be provided together")
        return self


# Discriminated on share_mode: link stays anonymous, pin_share is member-only.
CreateSnippetRequest = Annotated[
    CreateLinkSnippetRequest | CreatePinShareSnippetRequest,
    Field(discriminator="share_mode"),
]


class CreatePinShareResponse(BaseModel):
    id: str
    pin: str
    expires_at: datetime


class ByPinRequest(BaseModel):
    """Body for `POST /snippets/by-pin`. Resolves a 4-digit PIN to a Mode 2
    share (or signals a live Mode 3 pairing). ``password_hash`` is supplied on
    the retry when a share is password-gated; ``turnstile_token`` after the
    per-IP failure threshold."""

    model_config = ConfigDict(extra="forbid")

    pin: str = Field(..., pattern=r"^[0-9]{4}$")
    password_hash: Base64Field | None = Field(default=None, max_length=PASSWORD_HASH_BYTES)
    turnstile_token: str | None = None


class PinResolveResponse(BaseModel):
    """200 body for a resolved Mode 2 PIN. Carries the server-unwrapped content
    key alongside the ciphertext — the client decrypts locally."""

    mode: Literal["pin_share"] = "pin_share"
    id: str
    content_type: ContentType
    content_key: Base64Field
    ciphertext: Base64Field
    encrypted_metadata: Base64Field
    size_bytes: int
    created_at: datetime
    expires_at: datetime | None
    max_reads: int | None
    read_count: int


class PairSignalResponse(BaseModel):
    """200 body when the PIN matches a live Mode 3 pairing — the client opens
    the pair WebSocket rather than fetching content."""

    mode: Literal["pair"] = "pair"


class VerifyPasswordRequest(BaseModel):
    """Body for `POST /snippets/{id}/verify-password`. The client has
    already computed PBKDF2 with the salt the server returned in the
    gating 401; the wire only carries the resulting 32-byte hash."""

    model_config = ConfigDict(extra="forbid")

    password_hash: Base64Field = Field(..., max_length=PASSWORD_HASH_BYTES)

    @model_validator(mode="after")
    def _hash_size(self) -> Self:
        if len(self.password_hash) != PASSWORD_HASH_BYTES:
            raise ValueError(f"password_hash must be exactly {PASSWORD_HASH_BYTES} bytes")
        return self


class PasswordRequiredResponse(BaseModel):
    """401 body for `GET /snippets/{id}` when the snippet is gated by
    a password. The client uses ``password_salt`` to recompute its
    PBKDF2 hash before calling ``verify-password``. The salt is not a
    secret — see [D-260526-01]."""

    status: Literal["password_required"] = "password_required"
    password_salt: Base64Field


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
