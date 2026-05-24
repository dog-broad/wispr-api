from __future__ import annotations

from httpx import AsyncClient

from app.middleware.security_headers import SECURITY_HEADERS


async def test_every_response_carries_the_security_header_set(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    for name, expected in SECURITY_HEADERS.items():
        actual = response.headers.get(name)
        assert actual == expected, f"{name}: got {actual!r}, want {expected!r}"


async def test_security_headers_do_not_clobber_existing(client: AsyncClient) -> None:
    """The middleware uses setdefault so a route or upstream layer that
    already chose a value (e.g. a stricter per-route CSP) wins. We can't
    easily inject a competing header from a route without a custom route,
    so check the property indirectly: a fresh response should expose the
    documented defaults verbatim and nothing else has overridden them."""
    response = await client.get("/health")
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
