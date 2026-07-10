from __future__ import annotations

import hashlib
import secrets

# Opaque bearer tokens (magic links, session cookies). 32 bytes of entropy,
# URL-safe base64 encoded. Only the SHA-256 digest is ever persisted; the raw
# value lives in the email URL or the cookie and is never stored server-side.
_TOKEN_BYTES = 32


def generate_opaque_token() -> str:
    """A fresh 32-byte URL-safe random token."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(token: str) -> bytes:
    """SHA-256 of a raw token, matching what's stored in ``token_hash``."""
    return hashlib.sha256(token.encode("utf-8")).digest()
