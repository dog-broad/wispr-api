from __future__ import annotations

from typing import Any

import pytest
from starlette.requests import Request

from app.lib.clientip import bucket_key, extract_client_ip


def _make_request(headers: dict[str, str] | None = None, client_host: str | None = None) -> Request:
    """Build a Starlette Request directly — we only need the scope shape,
    no transport or application instance."""
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope: dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": raw_headers,
        "client": (client_host, 12345) if client_host else None,
    }
    return Request(scope)


def test_extract_prefers_cf_connecting_ip() -> None:
    req = _make_request(
        headers={"CF-Connecting-IP": "203.0.113.42"},
        client_host="10.0.0.1",
    )
    assert extract_client_ip(req) == "203.0.113.42"


def test_extract_falls_back_to_peer_when_header_missing() -> None:
    req = _make_request(client_host="10.0.0.1")
    assert extract_client_ip(req) == "10.0.0.1"


def test_extract_returns_empty_string_when_no_client() -> None:
    req = _make_request()
    assert extract_client_ip(req) == ""


def test_extract_strips_whitespace() -> None:
    req = _make_request(headers={"CF-Connecting-IP": "  203.0.113.42  "})
    assert extract_client_ip(req) == "203.0.113.42"


@pytest.mark.parametrize(
    "ipv4",
    ["1.2.3.4", "10.0.0.1", "255.255.255.255", "127.0.0.1"],
)
def test_bucket_key_ipv4_passes_through(ipv4: str) -> None:
    assert bucket_key(ipv4) == ipv4


@pytest.mark.parametrize(
    "ipv6, expected",
    [
        # /64 prefix takes the first four hex groups
        ("2001:db8:abcd:0012:3456:789a:bcde:f012", "2001:db8:abcd:12::"),
        # The address is already a /64 boundary
        ("2001:db8::", "2001:db8::"),
        # Variant low bits — bucket key should be identical
        ("2001:db8:abcd:0012:ffff:ffff:ffff:ffff", "2001:db8:abcd:12::"),
    ],
)
def test_bucket_key_ipv6_truncates_to_slash_64(ipv6: str, expected: str) -> None:
    assert bucket_key(ipv6) == expected


def test_bucket_key_handles_unparseable_ip() -> None:
    assert bucket_key("not-an-ip") == "not-an-ip"
    assert bucket_key("") == ""
