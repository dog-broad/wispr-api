from __future__ import annotations

from functools import lru_cache

from pydantic import Field
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
    cors_allowed_origin: str = Field(default="http://localhost:3000")
    log_level: str = Field(default="info")

    # Background purge — sweeps expired snippets out of the table. 5 minutes
    # matches the cadence in §12; override via env for tests that want to
    # observe a purge tick without waiting (or to disable entirely with 0).
    purge_interval_seconds: int = Field(default=300, ge=0)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
