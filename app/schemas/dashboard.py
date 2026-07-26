from __future__ import annotations

import enum
from datetime import date, datetime

from pydantic import BaseModel


class MetricStatus(enum.StrEnum):
    ok = "ok"
    warn = "warn"
    alert = "alert"
    # Source not wired / unreachable — the console renders a yellow "?" with the
    # detail as a tooltip. Never a silent green.
    unknown = "unknown"


class Metric(BaseModel):
    key: str
    label: str
    status: MetricStatus
    # Human-readable display value ("4 conns", "38 MB", "up"); None when unknown.
    value: str | None = None
    # Tooltip / reason — e.g. why a metric is unknown.
    detail: str | None = None


class QuotaMetric(Metric):
    used: float | None = None
    # None means "no cap" (e.g. Turnstile). Both None when the metric is unknown.
    total: float | None = None


class AuditEntry(BaseModel):
    action: str
    target_type: str | None
    target_id: str | None
    created_at: datetime


class DashboardResponse(BaseModel):
    generated_at: datetime
    # Worst status across all metrics (unknown does not count) — drives the banner.
    status: MetricStatus
    quotas: list[QuotaMetric]
    health: list[Metric]
    business: list[Metric]
    abuse: list[Metric]
    ops: list[Metric]
    recent_actions: list[AuditEntry]


class QuotaHistoryPoint(BaseModel):
    day: date
    value: int


class QuotaHistoryResponse(BaseModel):
    metric: str
    # False when the metric has no reconstructable 7-day series yet (provider
    # usage without a snapshot store) — the drill-down shows "no history".
    available: bool
    points: list[QuotaHistoryPoint]
