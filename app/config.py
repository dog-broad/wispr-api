from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    cors_allowed_origins: list[str] = Field(default=["http://localhost:3000"])
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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
