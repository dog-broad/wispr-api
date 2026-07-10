from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
_VERIFY_TIMEOUT_SECONDS = 5.0


async def verify_turnstile(
    *,
    token: str | None,
    remote_ip: str,
    secret: str | None,
    client: httpx.AsyncClient,
) -> bool:
    """Validate a Turnstile challenge response.

    Two deliberate fall-open cases keep a challenge outage from locking every
    user out of the app (the app pairs this with stricter rate limits):

    - No ``secret`` configured (local dev): bypass entirely and pass.
    - Cloudflare unreachable / errors: log and pass, rather than hard-fail.

    A configured secret with a missing or rejected token fails closed.
    """
    if not secret:
        return True
    if not token:
        return False
    try:
        response = await client.post(
            _SITEVERIFY_URL,
            data={"secret": secret, "response": token, "remoteip": remote_ip},
            timeout=_VERIFY_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        body = response.json()
    except (httpx.HTTPError, ValueError):
        logger.warning("turnstile: siteverify unreachable - failing open")
        return True
    return bool(body.get("success", False))
