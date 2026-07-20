from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.schemas.snippets import Base64Field

# Minimal email validation without pulling in the email-validator dependency:
# lowercase, strip, and require a single "@" with non-empty local and domain
# parts. This is an access-control identifier, not a deliverability guarantee.
_MAX_EMAIL_LEN = 320


def _normalize_email(value: str) -> str:
    email = value.strip().lower()
    if len(email) > _MAX_EMAIL_LEN:
        raise ValueError("email too long")
    local, sep, domain = email.partition("@")
    if not sep or not local or "." not in domain:
        raise ValueError("invalid email")
    return email


class RequestMagicLinkRequest(BaseModel):
    email: str
    # Present only when signing up (invite-gated). Ignored when the email
    # already belongs to an account (that path is always a sign-in).
    invite_code: str | None = None
    # Cloudflare Turnstile response token; verified server-side. Optional so
    # local dev (no Turnstile secret) can omit it.
    turnstile_token: str | None = None

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        return _normalize_email(value)


class MagicLinkResponse(BaseModel):
    # Always true and content-free: the endpoint never reveals whether the
    # email maps to an account, to avoid enumeration.
    ok: bool = True


class VerifyResponse(BaseModel):
    email: str
    # True when the account has no passphrase yet — the client routes to
    # first-time setup rather than the per-session prompt.
    needs_passphrase_setup: bool


class SessionResponse(BaseModel):
    email: str
    is_admin: bool
    needs_passphrase_setup: bool
    master_key_version: int
    # Client PBKDF2 salts for re-derivation; null until passphrase setup.
    auth_credential_salt: Base64Field | None = None
    master_key_salt: Base64Field | None = None


class UnlockRequest(BaseModel):
    auth_token: Base64Field = Field(..., max_length=64)


class SetupPassphraseRequest(BaseModel):
    # The client-derived auth token (PBKDF2, "wispr-auth-v1"). The passphrase
    # itself never leaves the browser.
    auth_token: Base64Field = Field(..., max_length=64)
    # The two client PBKDF2 salts, stored so later sessions re-derive the same
    # keys. 16 bytes each.
    auth_credential_salt: Base64Field = Field(..., max_length=32)
    master_key_salt: Base64Field = Field(..., max_length=32)
