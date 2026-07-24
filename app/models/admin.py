from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

_UUID_PK = text("gen_random_uuid()")

# Free-form action verb + optional target. String columns are sized generously;
# the values are internal identifiers, not user input.
_ACTION_LEN = 64
_TARGET_TYPE_LEN = 32
_METRIC_LEN = 64
_KILL_SWITCH_NAME_LEN = 32


class KillSwitchName(enum.StrEnum):
    """The closed set of toggleable features. Stored as a CHECK-constrained
    string (not a DB enum) so the migration stays schema-only."""

    mode2 = "mode2"
    anon_link = "anon_link"
    maintenance_mode = "maintenance_mode"


class AdminAuditLog(Base):
    """Append-only record of every admin action, for accountability + the
    console's self-audit panel. The actor FK SET-NULLs so history survives a
    hard-deleted admin; account deletion soft-deletes the user row (tombstone),
    so in practice the actor usually survives anyway."""

    __tablename__ = "admin_audit_log"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=_UUID_PK
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL", name="fk_admin_audit_log_actor_user_id_users"),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(_ACTION_LEN), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(_TARGET_TYPE_LEN), nullable=True)
    target_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    # SQLAlchemy declarative reserves the attribute name ``metadata``; expose the
    # jsonb column as ``payload`` on the model.
    payload: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    __table_args__ = (
        Index("ix_admin_audit_log_actor_created", "actor_user_id", text("created_at DESC")),
        Index("ix_admin_audit_log_created", text("created_at DESC")),
    )


class AdminThreshold(Base):
    """Per-metric warn/alert percentages, editable inline from the console."""

    __tablename__ = "admin_thresholds"

    metric: Mapped[str] = mapped_column(String(_METRIC_LEN), primary_key=True)
    warn_pct: Mapped[int] = mapped_column(Integer, nullable=False)
    alert_pct: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL", name="fk_admin_thresholds_updated_by_users"),
        nullable=True,
    )

    __table_args__ = (
        CheckConstraint("warn_pct BETWEEN 0 AND 100", name="ck_admin_thresholds_warn_range"),
        CheckConstraint("alert_pct BETWEEN 0 AND 100", name="ck_admin_thresholds_alert_range"),
    )


class AdminAlertPref(Base):
    """Per-(admin, metric) opt-in to red-state email alerts. Personal state, so
    it cascades away with the account (unlike the audit trail). ``last_emailed_at``
    throttles to at most one email per metric per hour."""

    __tablename__ = "admin_alert_prefs"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE", name="fk_admin_alert_prefs_user_id_users"),
        primary_key=True,
    )
    metric: Mapped[str] = mapped_column(String(_METRIC_LEN), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    last_emailed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class KillSwitch(Base):
    """A toggleable feature gate. A missing row means the switch is off; the
    toggle endpoint upserts. ``message`` is the public banner text used only for
    ``maintenance_mode``."""

    __tablename__ = "kill_switches"

    name: Mapped[str] = mapped_column(String(_KILL_SWITCH_NAME_LEN), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    toggled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    toggled_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL", name="fk_kill_switches_toggled_by_users"),
        nullable=True,
    )

    __table_args__ = (
        CheckConstraint(
            "name IN ('mode2', 'anon_link', 'maintenance_mode')",
            name="ck_kill_switches_name",
        ),
    )
