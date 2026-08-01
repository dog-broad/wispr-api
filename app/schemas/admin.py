from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Public maintenance banner text cap.
MESSAGE_MAX_LEN = 500


class SetKillSwitchRequest(BaseModel):
    """Toggle body. ``message`` is the public banner text; it only matters for
    ``maintenance_mode`` (ignored by the other switches)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool
    message: str | None = Field(default=None, max_length=MESSAGE_MAX_LEN)


class KillSwitchState(BaseModel):
    name: str
    enabled: bool
    message: str | None


class MaintenanceState(BaseModel):
    """Public: read by the web to decide whether to show the maintenance
    banner. Carries no auth-sensitive data."""

    enabled: bool
    message: str | None


# --- thresholds + alert prefs ------------------------------------------------


class ThresholdItem(BaseModel):
    metric: str
    warn_pct: int
    alert_pct: int


class ThresholdListResponse(BaseModel):
    thresholds: list[ThresholdItem]


class SetThresholdRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    warn_pct: int = Field(ge=0, le=100)
    alert_pct: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.warn_pct > self.alert_pct:
            raise ValueError("warn_pct must be <= alert_pct")
        return self


class AlertPrefRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metric: str
    enabled: bool


class AlertPrefResponse(BaseModel):
    metric: str
    enabled: bool


# --- admin actions -----------------------------------------------------------

# Broadcast subject/body caps: keep a runaway paste from becoming a giant send.
BROADCAST_SUBJECT_MAX = 200
BROADCAST_BODY_MAX = 10_000


class PurgeResult(BaseModel):
    deleted: int
    swept_orphans: int


class BackupResult(BaseModel):
    key: str
    size_bytes: int


class BroadcastRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1, max_length=BROADCAST_SUBJECT_MAX)
    body: str = Field(min_length=1, max_length=BROADCAST_BODY_MAX)
    # First call previews (no send, no re-auth). Set true (with the current
    # passphrase's auth token) to actually send.
    confirm: bool = False
    current_auth_token: str | None = None


class BroadcastResult(BaseModel):
    # True for a preview (nothing sent); false once the send fired.
    preview: bool
    recipient_count: int
    subject: str
    sent: int


class RotateMasterKeyResult(BaseModel):
    rewrapped: int
    # Rows whose recorded version's key wasn't loaded (skipped, not corrupted).
    failed: int
    current_version: int
