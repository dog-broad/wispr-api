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
    # for this field; without it, the env var is interpreted as JSON
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

    # Background purge: sweeps expired snippets out of the table. 5 minutes
    # matches the cadence in §12; override via env for tests that want to
    # observe a purge tick without waiting (or to disable entirely with 0).
    purge_interval_seconds: int = Field(default=300, ge=0)

    # Operator-console poll: every N seconds the backend builds the dashboard,
    # warms its Redis cache, and emails any red-state alerts. 0 disables the loop.
    alert_poll_interval_seconds: int = Field(default=30, ge=0)

    # Transactional email (magic links, audit + confirmation notices). When
    # ``resend_api_key`` is unset the app falls back to a log-only transport
    # that writes the message (link included) to the app log, so the auth flow
    # is exercisable in local dev without an email provider.
    resend_api_key: str | None = Field(default=None)
    # Verified sender. Resend's shared sandbox sender works without a domain;
    # production overrides this with a DKIM-verified address on our domain.
    email_from: str = Field(default="Wispr <onboarding@resend.dev>")
    # Public base URL of the web app: magic-link and confirmation URLs are
    # built against this. Local dev is the Next dev server.
    app_base_url: str = Field(default="http://localhost:3000")

    # Session cookie scope. Production sets domain=".wispr.rushyendra.dev"
    # (the Wispr subtree only, never the apex, which keeps the cookie off sibling
    # projects) and secure=True. Local dev leaves domain unset (host-only on
    # localhost) and secure=False so the cookie works over plain HTTP.
    session_cookie_domain: str | None = Field(default=None)
    session_cookie_secure: bool = Field(default=False)

    # Cloudflare Turnstile secret for verifying magic-link (and later report)
    # challenges. Unset in local dev; the verifier then bypasses the check so
    # the flow works without a provider.
    turnstile_secret_key: str | None = Field(default=None)

    # Server-side pepper mixed into argon2id when hashing the client-derived
    # auth token. A deployment secret, never in the DB. Empty in local dev
    # (argon2id still hashes, just without the extra secret). Changing it in
    # production invalidates every stored credential — set once.
    server_pepper: str | None = Field(default=None)

    # PIN-share key vault (Mode 2). base64-encoded 32-byte AES keys that wrap
    # per-share content keys at rest; identified by monotonic version for
    # rotation. Deployment secrets, never in the DB. Unset in local dev; the
    # vault then uses a deterministic insecure dev key (loud warning). Losing
    # the production key makes every Mode 2 share undecryptable.
    key_vault_master_v1: str | None = Field(default=None)
    key_vault_master_v2: str | None = Field(default=None)
    key_vault_current_version: int = Field(default=1)

    # Cloudflare R2 (S3-compatible) for file payloads > the inline cap. Each
    # 1 MiB ciphertext chunk is its own object (see the files decision). All
    # unset in local dev; the presign endpoint then returns 503, so file
    # uploads are simply unavailable locally rather than half-working.
    r2_account_id: str | None = Field(default=None)
    r2_access_key_id: str | None = Field(default=None)
    r2_secret_access_key: str | None = Field(default=None)
    r2_bucket: str | None = Field(default=None)
    # S3 API endpoint, e.g. https://<account>.r2.cloudflarestorage.com
    r2_endpoint: str | None = Field(default=None)

    # Operator-console provider integrations. All unset in local dev; each
    # dashboard quota row then renders a yellow "?" (never a false green). The
    # clients degrade to "?" on missing config OR an unreachable/errored call.
    # Sentry event-stats API (org + project slugs, an auth token with
    # project:read).
    sentry_api_token: str | None = Field(default=None)
    sentry_org: str | None = Field(default=None)
    sentry_project: str | None = Field(default=None)
    # Cloudflare GraphQL Analytics (R2 storage/ops, DNS queries, Turnstile). The
    # token needs Analytics read; account id scopes R2, zone id scopes DNS +
    # Turnstile. (``r2_account_id`` above is the same account but kept separate
    # so R2 storage can be configured without the analytics token.)
    cloudflare_api_token: str | None = Field(default=None)
    cloudflare_account_id: str | None = Field(default=None)
    cloudflare_zone_id: str | None = Field(default=None)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
