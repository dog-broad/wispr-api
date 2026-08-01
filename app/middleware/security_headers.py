from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# The header set is fixed; the api returns the same
# strict policy as Caddy so a misconfigured proxy can't silently weaken
# the posture. CSP includes the production hostnames for `connect-src`;
# browsers don't apply CSP to JSON responses, so the policy mainly
# matters when a human points a browser at the api directly (e.g. /docs
# in dev). HSTS is harmless over HTTP — browsers only honour it after a
# successful HTTPS request.
_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' wss://wispr-api.rushyendra.dev https://wispr-api.rushyendra.dev; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "upgrade-insecure-requests"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(self), microphone=(), geolocation=(), interest-cohort=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Append the strict security-header set to every response.

    Existing values are preserved: the api never overrides a header an
    upstream layer (Caddy, downstream FastAPI middleware) has already
    chosen. New headers fall through verbatim.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        for name, value in _HEADERS.items():
            response.headers.setdefault(name, value)
        return response


# Public for tests so we can assert against the same source of truth
# without re-stating the values.
SECURITY_HEADERS: dict[str, str] = dict(_HEADERS)
