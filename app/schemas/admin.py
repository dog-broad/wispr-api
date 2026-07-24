from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

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
    """Public — read by the web to decide whether to show the maintenance
    banner. Carries no auth-sensitive data."""

    enabled: bool
    message: str | None
