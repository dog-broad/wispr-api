from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

import httpx
from fastapi import Request

logger = logging.getLogger(__name__)

# Resend's transactional send endpoint. https://resend.com/docs/api-reference
_RESEND_ENDPOINT = "https://api.resend.com/emails"
_SEND_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class EmailMessage:
    """A plain-text transactional email. HTML bodies are intentionally omitted:
    every message we send (magic links, sign-in audits, deletion notices) is
    a short line of text plus a link, and plain text sidesteps a whole class of
    rendering and phishing-lookalike concerns."""

    to: str
    subject: str
    text_body: str


class EmailTransport(Protocol):
    async def send(self, message: EmailMessage) -> None: ...


class LogTransport:
    """Dev fallback used whenever no Resend API key is configured.

    Writes the full message (crucially including any magic-link URL) to the
    app log instead of sending, so the auth flow can be driven end-to-end
    locally without an email provider. Never selected when an API key is set.
    """

    def __init__(self, sender: str) -> None:
        self._sender = sender

    async def send(self, message: EmailMessage) -> None:
        logger.info(
            "email [log transport] from=%s to=%s subject=%r\n%s",
            self._sender,
            message.to,
            message.subject,
            message.text_body,
        )


class ResendTransport:
    """Sends via Resend's HTTP API over a shared client owned by the app
    lifespan. Raises on a non-2xx response so the caller can surface a 502
    rather than silently dropping a link the user is waiting on."""

    def __init__(self, api_key: str, sender: str, client: httpx.AsyncClient) -> None:
        self._api_key = api_key
        self._sender = sender
        self._client = client

    async def send(self, message: EmailMessage) -> None:
        response = await self._client.post(
            _RESEND_ENDPOINT,
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={
                "from": self._sender,
                "to": [message.to],
                "subject": message.subject,
                "text": message.text_body,
            },
            timeout=_SEND_TIMEOUT_SECONDS,
        )
        response.raise_for_status()


def build_email_transport(
    *,
    api_key: str | None,
    sender: str,
    client: httpx.AsyncClient,
) -> EmailTransport:
    """Pick the transport from configuration. A configured API key selects the
    real Resend sender; its absence selects the log-only dev fallback."""
    if api_key:
        return ResendTransport(api_key=api_key, sender=sender, client=client)
    logger.warning("RESEND_API_KEY not set - using log-only email transport (dev fallback)")
    return LogTransport(sender=sender)


def get_email_transport(request: Request) -> EmailTransport:
    """FastAPI dependency handing routes the app-wide transport, built once in
    the lifespan. Tests override this to capture sent messages."""
    transport: EmailTransport = request.app.state.email_transport
    return transport
