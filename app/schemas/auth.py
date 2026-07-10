from __future__ import annotations

from pydantic import BaseModel, field_validator

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
