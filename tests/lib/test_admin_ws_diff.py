from __future__ import annotations

from datetime import UTC, datetime

from app.routes.admin_ws import _diff, _flatten
from app.schemas.dashboard import (
    DashboardResponse,
    Metric,
    MetricStatus,
    QuotaMetric,
)


def _dashboard() -> DashboardResponse:
    return DashboardResponse(
        generated_at=datetime(2026, 7, 24, tzinfo=UTC),
        status=MetricStatus.ok,
        quotas=[QuotaMetric(key="r2.storage", label="R2", status=MetricStatus.ok, value="1 / 10")],
        health=[Metric(key="api", label="api", status=MetricStatus.ok, value="up")],
        business=[Metric(key="members", label="members", status=MetricStatus.ok, value="3")],
        abuse=[],
        ops=[],
        recent_actions=[],
    )


def test_flatten_keys_every_metric() -> None:
    flat = _flatten(_dashboard())
    assert set(flat) == {"r2.storage", "api", "members"}
    assert flat["members"]["value"] == "3"


def test_diff_returns_only_changed() -> None:
    before = _flatten(_dashboard())
    after = dict(before)
    after["members"] = {**before["members"], "value": "4"}  # a new signup

    changed = _diff(after, before)
    assert set(changed) == {"members"}
    assert changed["members"]["value"] == "4"


def test_diff_empty_when_unchanged() -> None:
    flat = _flatten(_dashboard())
    assert _diff(flat, dict(flat)) == {}
