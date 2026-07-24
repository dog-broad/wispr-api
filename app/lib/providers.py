from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.config import Settings
from app.schemas.dashboard import MetricStatus, QuotaMetric

# Quota denominators (the "/ total" side of the bar). Constants matching the
# deployment tier — thresholds (a later item) drive warn/alert, not these caps.
_RESEND_MONTHLY = 3_000
_R2_STORAGE_GB = 10
_R2_OPS_MONTHLY = 1_000_000
_SENTRY_MONTHLY = 5_000

_TIMEOUT = 8.0
_GB = 1024**3

# NOTE: the exact provider endpoints/response shapes below are best-effort
# against the documented APIs and are validated live only when keys are
# provisioned. Every call fails soft to a yellow "?" (see _unknown), so a wrong
# shape degrades gracefully rather than crashing the dashboard.


def _unknown(key: str, label: str, detail: str) -> QuotaMetric:
    return QuotaMetric(key=key, label=label, status=MetricStatus.unknown, detail=detail)


def _ok(
    key: str,
    label: str,
    *,
    value: str,
    used: float | None = None,
    total: float | None = None,
) -> QuotaMetric:
    return QuotaMetric(
        key=key, label=label, status=MetricStatus.ok, value=value, used=used, total=total
    )


def _period_start(days: int) -> str:
    return (datetime.now(tz=UTC) - timedelta(days=days)).replace(microsecond=0).isoformat()


# --- Resend ------------------------------------------------------------------


async def resend_usage(client: httpx.AsyncClient, settings: Settings) -> QuotaMetric:
    """Monthly email send count vs the plan cap. Resend's usage endpoint is
    unconfirmed; the call fails soft to "?" until validated against a live key."""
    if not settings.resend_api_key:
        return _unknown("resend.monthly", "Resend", "configure RESEND_API_KEY")
    try:
        response = await client.get(
            "https://api.resend.com/api-keys/usage",
            headers={"Authorization": f"Bearer {settings.resend_api_key}"},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        body = response.json()
        used = int(body["sent"])
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return _unknown("resend.monthly", "Resend", "usage API unreachable")
    return _ok(
        "resend.monthly",
        "Resend",
        value=f"{used:,} / {_RESEND_MONTHLY:,}",
        used=used,
        total=_RESEND_MONTHLY,
    )


# --- Sentry ------------------------------------------------------------------


def _sum_sentry_quantity(body: dict[str, Any]) -> int:
    total = 0
    for group in body.get("groups", []):
        total += int(group.get("totals", {}).get("sum(quantity)", 0))
    return total


async def sentry_usage(client: httpx.AsyncClient, settings: Settings) -> QuotaMetric:
    """Error events in the last 30 days vs the monthly quota (Sentry stats_v2)."""
    if not (settings.sentry_api_token and settings.sentry_org and settings.sentry_project):
        return _unknown("sentry.events", "Sentry", "configure Sentry token / org / project")
    try:
        response = await client.get(
            f"https://sentry.io/api/0/organizations/{settings.sentry_org}/stats_v2/",
            params={
                "field": "sum(quantity)",
                "category": "error",
                "statsPeriod": "30d",
                "project": settings.sentry_project,
            },
            headers={"Authorization": f"Bearer {settings.sentry_api_token}"},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        used = _sum_sentry_quantity(response.json())
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return _unknown("sentry.events", "Sentry", "Sentry API unreachable")
    return _ok(
        "sentry.events",
        "Sentry",
        value=f"{used:,} / {_SENTRY_MONTHLY:,}",
        used=used,
        total=_SENTRY_MONTHLY,
    )


# --- Cloudflare GraphQL Analytics --------------------------------------------

_CF_GRAPHQL = "https://api.cloudflare.com/client/v4/graphql"

# R2 storage (account), R2 ops (account), DNS queries (zone). Turnstile's
# analytics dataset is unconfirmed, so it stays "?" for now.
_CF_QUERY = """
query($accountTag: String!, $zoneTag: String!, $since: Time!) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      r2StorageAdaptiveGroups(limit: 1, filter: {datetime_geq: $since},
                              orderBy: [datetime_DESC]) {
        max { payloadSize }
      }
      r2OperationsAdaptiveGroups(limit: 10000, filter: {datetime_geq: $since}) {
        sum { requests }
      }
    }
    zones(filter: {zoneTag: $zoneTag}) {
      dnsAnalyticsAdaptiveGroups(limit: 1, filter: {datetime_geq: $since}) {
        sum { queryCount }
      }
    }
  }
}
"""


def _cf_all_unknown(detail: str) -> dict[str, QuotaMetric]:
    return {
        "r2.storage": _unknown("r2.storage", "R2 storage", detail),
        "r2.ops": _unknown("r2.ops", "R2 ops", detail),
        "turnstile.today": _unknown(
            "turnstile.today", "Turnstile", "analytics dataset not wired yet"
        ),
        "cf.dns": _unknown("cf.dns", "CF DNS", detail),
    }


async def cloudflare_usage(client: httpx.AsyncClient, settings: Settings) -> dict[str, QuotaMetric]:
    """R2 storage/ops + DNS query volume from Cloudflare's GraphQL Analytics.
    All rows fail soft to "?" together on missing config or an errored call."""
    if not (
        settings.cloudflare_api_token
        and settings.cloudflare_account_id
        and settings.cloudflare_zone_id
    ):
        return _cf_all_unknown("configure Cloudflare API token / account / zone")
    result = _cf_all_unknown("Cloudflare API unreachable")
    try:
        response = await client.post(
            _CF_GRAPHQL,
            json={
                "query": _CF_QUERY,
                "variables": {
                    "accountTag": settings.cloudflare_account_id,
                    "zoneTag": settings.cloudflare_zone_id,
                    "since": _period_start(30),
                },
            },
            headers={"Authorization": f"Bearer {settings.cloudflare_api_token}"},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        viewer = response.json()["data"]["viewer"]
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return result

    account = (viewer.get("accounts") or [{}])[0]
    zone = (viewer.get("zones") or [{}])[0]

    storage_bytes = _first_metric(account.get("r2StorageAdaptiveGroups"), "max", "payloadSize")
    if storage_bytes is not None:
        gb = storage_bytes / _GB
        result["r2.storage"] = _ok(
            "r2.storage",
            "R2 storage",
            value=f"{gb:.1f} / {_R2_STORAGE_GB} GB",
            used=gb,
            total=_R2_STORAGE_GB,
        )
    ops = _first_metric(account.get("r2OperationsAdaptiveGroups"), "sum", "requests")
    if ops is not None:
        result["r2.ops"] = _ok(
            "r2.ops",
            "R2 ops",
            value=f"{int(ops):,} / {_R2_OPS_MONTHLY:,}",
            used=ops,
            total=_R2_OPS_MONTHLY,
        )
    dns = _first_metric(zone.get("dnsAnalyticsAdaptiveGroups"), "sum", "queryCount")
    if dns is not None:
        result["cf.dns"] = _ok("cf.dns", "CF DNS", value=f"{int(dns):,} (30d)", used=dns)
    return result


def _first_metric(groups: Any, agg: str, field: str) -> float | None:
    """Pull ``groups[0][agg][field]`` defensively from a GraphQL group list."""
    if not isinstance(groups, list) or not groups:
        return None
    value = groups[0].get(agg, {}).get(field)
    return float(value) if isinstance(value, (int, float)) else None


# --- Assembly ----------------------------------------------------------------


async def collect_quotas(client: httpx.AsyncClient, settings: Settings) -> list[QuotaMetric]:
    """All six quota rows in the console's display order. Each is real when its
    provider is configured and reachable, else a yellow "?"."""
    resend = await resend_usage(client, settings)
    sentry = await sentry_usage(client, settings)
    cf = await cloudflare_usage(client, settings)
    return [
        resend,
        cf["r2.storage"],
        cf["r2.ops"],
        sentry,
        cf["turnstile.today"],
        cf["cf.dns"],
    ]
