from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.schemas.snippets import WRAP_IV_MAX_BYTES, WRAPPED_DEK_MAX_BYTES, Base64Field

# Safety bound on a single change-passphrase request. A personal Sync history
# won't approach this; it just caps a hostile request.
MAX_REWRAP_ITEMS = 100_000

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
    # True when the account has no passphrase yet: the client routes to
    # first-time setup rather than the per-session prompt.
    needs_passphrase_setup: bool
    # True when this link confirmed an email change (not a sign-in): the client
    # shows a "your email is now X" confirmation and doesn't route to setup.
    email_changed: bool = False


class ChangeEmailRequest(BaseModel):
    new_email: str
    # Re-auth proof (current passphrase's auth token). Required: changing the
    # email is account-recovery-sensitive, so the session cookie alone isn't
    # enough. The account must have a passphrase set.
    current_auth_token: Base64Field = Field(..., max_length=64)

    @field_validator("new_email")
    @classmethod
    def _validate_new_email(cls, value: str) -> str:
        return _normalize_email(value)


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


class DeleteAccountRequest(BaseModel):
    # Re-auth proof: the current passphrase's auth token. Deleting is permanent,
    # so the session cookie alone isn't enough.
    current_auth_token: Base64Field = Field(..., max_length=64)


class RewrappedDek(BaseModel):
    id: str
    wrapped_dek: Base64Field = Field(..., max_length=WRAPPED_DEK_MAX_BYTES)
    wrapped_dek_iv: Base64Field = Field(..., max_length=WRAP_IV_MAX_BYTES)


class ChangePassphraseRequest(BaseModel):
    # Re-auth proof: the auth token derived from the *current* passphrase.
    current_auth_token: Base64Field = Field(..., max_length=64)
    # New credential: token + both fresh PBKDF2 salts (the new master salt makes
    # the old KEK unrecoverable, which is why the rewrap below must be complete).
    new_auth_token: Base64Field = Field(..., max_length=64)
    new_auth_credential_salt: Base64Field = Field(..., max_length=32)
    new_master_key_salt: Base64Field = Field(..., max_length=32)
    # Every owned Sync item's DEK, re-wrapped with the new KEK. Must cover the
    # caller's exact current Sync set (server enforces) so nothing is stranded.
    rewrapped: list[RewrappedDek] = Field(default_factory=list, max_length=MAX_REWRAP_ITEMS)


class SetupPassphraseRequest(BaseModel):
    # The client-derived auth token (PBKDF2, "wispr-auth-v1"). The passphrase
    # itself never leaves the browser.
    auth_token: Base64Field = Field(..., max_length=64)
    # The two client PBKDF2 salts, stored so later sessions re-derive the same
    # keys. 16 bytes each.
    auth_credential_salt: Base64Field = Field(..., max_length=32)
    master_key_salt: Base64Field = Field(..., max_length=32)
