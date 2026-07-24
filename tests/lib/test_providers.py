from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from app.config import Settings, get_settings
from app.lib.providers import (
    cloudflare_usage,
    collect_quotas,
    resend_usage,
    sentry_usage,
)


def _settings(**overrides: object) -> Settings:
    # Start from a fully-nulled provider config, then apply per-test overrides.
    base: dict[str, object] = {
        "resend_api_key": None,
        "sentry_api_token": None,
        "sentry_org": None,
        "sentry_project": None,
        "cloudflare_api_token": None,
        "cloudflare_account_id": None,
        "cloudflare_zone_id": None,
    }
    base.update(overrides)
    return get_settings().model_copy(update=base)


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# --- Resend ------------------------------------------------------------------


async def test_resend_unconfigured_is_unknown() -> None:
    async with _client(lambda r: httpx.Response(200)) as client:
        metric = await resend_usage(client, _settings())
    assert metric.status == "unknown"
    assert metric.detail is not None and "RESEND_API_KEY" in metric.detail


async def test_resend_configured_parses_usage() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer rk"
        return httpx.Response(200, json={"sent": 342})

    async with _client(handler) as client:
        metric = await resend_usage(client, _settings(resend_api_key="rk"))
    assert metric.status == "ok"
    assert metric.used == 342 and metric.total == 3000


async def test_resend_error_fails_soft() -> None:
    async with _client(lambda r: httpx.Response(500)) as client:
        metric = await resend_usage(client, _settings(resend_api_key="rk"))
    assert metric.status == "unknown" and metric.detail == "usage API unreachable"


# --- Sentry ------------------------------------------------------------------


async def test_sentry_unconfigured_is_unknown() -> None:
    async with _client(lambda r: httpx.Response(200)) as client:
        metric = await sentry_usage(client, _settings(sentry_api_token="t", sentry_org="o"))
    assert metric.status == "unknown"  # missing project


async def test_sentry_configured_sums_quantity() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "organizations/acme/stats_v2" in str(request.url)
        return httpx.Response(
            200,
            json={"groups": [{"totals": {"sum(quantity)": 12}}, {"totals": {"sum(quantity)": 5}}]},
        )

    async with _client(handler) as client:
        metric = await sentry_usage(
            client, _settings(sentry_api_token="t", sentry_org="acme", sentry_project="1")
        )
    assert metric.status == "ok" and metric.used == 17 and metric.total == 5000


# --- Cloudflare --------------------------------------------------------------


async def test_cloudflare_unconfigured_all_unknown() -> None:
    async with _client(lambda r: httpx.Response(200)) as client:
        result = await cloudflare_usage(client, _settings())
    assert set(result) == {"r2.storage", "r2.ops", "turnstile.today", "cf.dns"}
    assert all(m.status == "unknown" for m in result.values())


async def test_cloudflare_configured_parses_graphql() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "viewer": {
                        "accounts": [
                            {
                                "r2StorageAdaptiveGroups": [{"max": {"payloadSize": 2 * 1024**3}}],
                                "r2OperationsAdaptiveGroups": [{"sum": {"requests": 47000}}],
                            }
                        ],
                        "zones": [{"dnsAnalyticsAdaptiveGroups": [{"sum": {"queryCount": 18200}}]}],
                    }
                }
            },
        )

    async with _client(handler) as client:
        result = await cloudflare_usage(
            client,
            _settings(
                cloudflare_api_token="t", cloudflare_account_id="acc", cloudflare_zone_id="zone"
            ),
        )
    assert result["r2.storage"].status == "ok" and result["r2.storage"].used == pytest.approx(2.0)
    assert result["r2.ops"].status == "ok" and result["r2.ops"].used == 47000
    assert result["cf.dns"].status == "ok" and result["cf.dns"].used == 18200
    # Turnstile analytics dataset isn't wired yet.
    assert result["turnstile.today"].status == "unknown"


async def test_cloudflare_error_fails_soft() -> None:
    async with _client(lambda r: httpx.Response(502)) as client:
        result = await cloudflare_usage(
            client,
            _settings(
                cloudflare_api_token="t", cloudflare_account_id="acc", cloudflare_zone_id="zone"
            ),
        )
    assert all(m.status == "unknown" for m in result.values())


# --- Assembly ----------------------------------------------------------------


async def test_collect_quotas_order_and_all_unknown_without_keys() -> None:
    async with _client(lambda r: httpx.Response(200)) as client:
        quotas = await collect_quotas(client, _settings())
    assert [q.key for q in quotas] == [
        "resend.monthly",
        "r2.storage",
        "r2.ops",
        "sentry.events",
        "turnstile.today",
        "cf.dns",
    ]
    assert all(q.status == "unknown" for q in quotas)
