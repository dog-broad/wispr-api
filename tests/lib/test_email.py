from __future__ import annotations

import json
import logging

import httpx
import pytest

from app.lib.email import (
    EmailMessage,
    LogTransport,
    ResendTransport,
    build_email_transport,
)


def _mock_client(handler: httpx.MockTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=handler)


async def test_build_selects_log_transport_without_key() -> None:
    client = _mock_client(httpx.MockTransport(lambda _: httpx.Response(200)))
    transport = build_email_transport(api_key=None, sender="Wispr <x@y.z>", client=client)
    assert isinstance(transport, LogTransport)
    await client.aclose()


async def test_build_selects_resend_transport_with_key() -> None:
    client = _mock_client(httpx.MockTransport(lambda _: httpx.Response(200)))
    transport = build_email_transport(api_key="re_test_key", sender="Wispr <x@y.z>", client=client)
    assert isinstance(transport, ResendTransport)
    await client.aclose()


async def test_log_transport_writes_link_to_log(caplog: pytest.LogCaptureFixture) -> None:
    transport = LogTransport(sender="Wispr <x@y.z>")
    link = "http://localhost:3000/auth/verify?token=abc123"
    with caplog.at_level(logging.INFO, logger="app.lib.email"):
        await transport.send(
            EmailMessage(to="alice@example.com", subject="Your sign-in link", text_body=link)
        )
    # The dev fallback must surface the actual link and recipient so a local
    # operator can complete the flow from the log alone.
    assert link in caplog.text
    assert "alice@example.com" in caplog.text


async def test_resend_transport_posts_expected_payload() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"id": "email_1"})

    client = _mock_client(httpx.MockTransport(handler))
    transport = ResendTransport(
        api_key="re_test_key", sender="Wispr <no-reply@wispr.test>", client=client
    )
    await transport.send(EmailMessage(to="bob@example.com", subject="Hi", text_body="body text"))
    await client.aclose()

    assert captured["url"] == "https://api.resend.com/emails"
    assert captured["auth"] == "Bearer re_test_key"
    assert captured["body"] == {
        "from": "Wispr <no-reply@wispr.test>",
        "to": ["bob@example.com"],
        "subject": "Hi",
        "text": "body text",
    }


async def test_resend_transport_raises_on_error_status() -> None:
    client = _mock_client(httpx.MockTransport(lambda _: httpx.Response(422, json={})))
    transport = ResendTransport(api_key="re_test_key", sender="Wispr <x@y.z>", client=client)
    with pytest.raises(httpx.HTTPStatusError):
        await transport.send(EmailMessage(to="a@b.c", subject="s", text_body="t"))
    await client.aclose()
