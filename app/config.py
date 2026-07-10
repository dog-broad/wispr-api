from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: str = Field(default="dev")
    database_url: str = Field(
        default="postgresql+asyncpg://wispr:wispr@localhost:5432/wispr",
    )
    redis_url: str = Field(default="redis://localhost:6379/0")
    # Comma-separated list of origins permitted in CORS. Local dev
    # needs only the Next dev server.
    # ``NoDecode`` disables pydantic-settings' built-in JSON decoding
    # for this field — without it, the env var is interpreted as JSON
    # and a plain ``https://example.com`` value raises a parse error
    # before the ``_split_csv`` validator below gets a chance to run.
    cors_allowed_origins: Annotated[list[str], NoDecode] = Field(default=["http://localhost:3000"])
    # Optional regex matched against the request Origin in addition to
    # the exact-match list. Production sets this to cover the platform-
    # provided deployment URLs (preview + alias variants); local dev
    # leaves it None.
    cors_allowed_origin_regex: str | None = Field(default=None)
    log_level: str = Field(default="info")

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        # Env vars arrive as strings; split on commas so a single CSV
        # like "https://a,https://b" parses into the list shape.
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    # Background purge — sweeps expired snippets out of the table. 5 minutes
    # matches the cadence in §12; override via env for tests that want to
    # observe a purge tick without waiting (or to disable entirely with 0).
    purge_interval_seconds: int = Field(default=300, ge=0)

    # Transactional email (magic links, audit + confirmation notices). When
    # ``resend_api_key`` is unset the app falls back to a log-only transport
    # that writes the message (link included) to the app log, so the auth flow
    # is exercisable in local dev without an email provider.
    resend_api_key: str | None = Field(default=None)
    # Verified sender. Resend's shared sandbox sender works without a domain;
    # production overrides this with a DKIM-verified address on our domain.
    email_from: str = Field(default="Wispr <onboarding@resend.dev>")
    # Public base URL of the web app — magic-link and confirmation URLs are
    # built against this. Local dev is the Next dev server.
    app_base_url: str = Field(default="http://localhost:3000")

    # Session cookie scope. Production sets domain=".wispr.rushyendra.dev"
    # (the Wispr subtree only, never the apex — keeps the cookie off sibling
    # projects) and secure=True. Local dev leaves domain unset (host-only on
    # localhost) and secure=False so the cookie works over plain HTTP.
    session_cookie_domain: str | None = Field(default=None)
    session_cookie_secure: bool = Field(default=False)

    # Cloudflare Turnstile secret for verifying magic-link (and later report)
    # challenges. Unset in local dev — the verifier then bypasses the check so
    # the flow works without a provider.
    turnstile_secret_key: str | None = Field(default=None)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
