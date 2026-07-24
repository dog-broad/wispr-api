from __future__ import annotations

from app.lib.dashboard import _apply_thresholds
from app.schemas.dashboard import MetricStatus, QuotaMetric


def _quota(key: str, used: float | None, total: float | None) -> QuotaMetric:
    status = MetricStatus.unknown if used is None and total is None else MetricStatus.ok
    return QuotaMetric(key=key, label=key, status=status, value="x", used=used, total=total)


def test_default_thresholds_colour_by_percentage() -> None:
    alert = _quota("r2.storage", 9.5, 10)  # 95% ≥ 90
    warn = _quota("r2.ops", 800_000, 1_000_000)  # 80% ≥ 75
    ok = _quota("sentry.events", 2_000, 5_000)  # 40%
    _apply_thresholds([alert, warn, ok], {})
    assert alert.status is MetricStatus.alert
    assert warn.status is MetricStatus.warn
    assert ok.status is MetricStatus.ok


def test_configured_threshold_overrides_default() -> None:
    q = _quota("r2.storage", 6.0, 10)  # 60%
    # Default (75/90) would leave it ok; a tighter override warns at 50.
    _apply_thresholds([q], {"r2.storage": (50, 65)})
    assert q.status is MetricStatus.warn


def test_no_cap_and_unknown_rows_untouched() -> None:
    no_cap = _quota("cf.dns", 4_829, None)  # capless → no percentage
    unknown = _quota("resend.monthly", None, None)  # provider "?"
    _apply_thresholds([no_cap, unknown], {})
    assert no_cap.status is MetricStatus.ok
    assert unknown.status is MetricStatus.unknown
