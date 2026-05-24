from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _link_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "share_mode": "link",
        "content_type": "text",
        "ciphertext": _b64(b"\xde\xad\xbe\xef" * 4),
        "encrypted_metadata": _b64(b"meta"),
        "ttl_seconds": 600,
        "max_reads": 1,
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------------------
# POST /snippets
# ---------------------------------------------------------------------------


async def test_create_link_snippet_returns_id_and_expiry(db_client: AsyncClient) -> None:
    response = await db_client.post("/snippets", json=_link_body(ttl_seconds=300))

    assert response.status_code == 201
    body = response.json()
    assert isinstance(body["id"], str)
    assert len(body["id"]) == 12
    expires = datetime.fromisoformat(body["expires_at"])
    delta = expires - datetime.now(tz=UTC)
    assert 290 <= delta.total_seconds() <= 310


async def test_create_rejects_non_link_share_mode(db_client: AsyncClient) -> None:
    response = await db_client.post("/snippets", json=_link_body(share_mode="pin_share"))
    assert response.status_code == 422


async def test_create_rejects_max_reads_above_one(db_client: AsyncClient) -> None:
    response = await db_client.post("/snippets", json=_link_body(max_reads=2))
    assert response.status_code == 422


async def test_create_rejects_ttl_too_long(db_client: AsyncClient) -> None:
    response = await db_client.post("/snippets", json=_link_body(ttl_seconds=24 * 60 * 60 + 1))
    assert response.status_code == 422


async def test_create_rejects_ttl_too_short(db_client: AsyncClient) -> None:
    response = await db_client.post("/snippets", json=_link_body(ttl_seconds=10))
    assert response.status_code == 422


async def test_create_rejects_extra_fields(db_client: AsyncClient) -> None:
    response = await db_client.post(
        "/snippets",
        json=_link_body(pin="1234"),
    )
    assert response.status_code == 422


async def test_create_rejects_password_hash_without_salt(db_client: AsyncClient) -> None:
    response = await db_client.post(
        "/snippets",
        json=_link_body(password_hash=_b64(b"\x01" * 32)),
    )
    assert response.status_code == 422


async def test_create_accepts_paired_password_fields(db_client: AsyncClient) -> None:
    response = await db_client.post(
        "/snippets",
        json=_link_body(
            password_hash=_b64(b"\x01" * 32),
            password_salt=_b64(b"\x02" * 16),
        ),
    )
    assert response.status_code == 201


# ---------------------------------------------------------------------------
# GET /snippets/{id}
# ---------------------------------------------------------------------------


async def test_get_returns_ciphertext_on_first_read(db_client: AsyncClient) -> None:
    ciphertext = b"\x10\x20\x30\x40\x50"
    create = await db_client.post(
        "/snippets",
        json=_link_body(ciphertext=_b64(ciphertext)),
    )
    snippet_id = create.json()["id"]

    response = await db_client.get(f"/snippets/{snippet_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == snippet_id
    assert body["share_mode"] == "link"
    assert body["content_type"] == "text"
    assert base64.b64decode(body["ciphertext"]) == ciphertext
    assert body["read_count"] == 1
    assert body["max_reads"] == 1


async def test_get_second_read_returns_410_burned(db_client: AsyncClient) -> None:
    create = await db_client.post("/snippets", json=_link_body())
    snippet_id = create.json()["id"]

    first = await db_client.get(f"/snippets/{snippet_id}")
    assert first.status_code == 200

    second = await db_client.get(f"/snippets/{snippet_id}")
    assert second.status_code == 410
    assert second.json() == {"status": "gone", "reason": "burned"}


async def test_get_unknown_id_returns_404(db_client: AsyncClient) -> None:
    response = await db_client.get("/snippets/aaaaaaaaaaaa")
    assert response.status_code == 404


async def test_get_expired_returns_410_expired(
    db_session: AsyncSession, db_client: AsyncClient
) -> None:
    create = await db_client.post("/snippets", json=_link_body())
    snippet_id = create.json()["id"]

    # Backdate expires_at by an hour so the readability CAS fails on the
    # next GET. Done at the DB layer because the public POST won't let us
    # set ttl_seconds below the schema floor.
    past = datetime.now(tz=UTC) - timedelta(hours=1)
    await db_session.execute(
        sa_text("UPDATE snippets SET expires_at = :p WHERE id = :id"),
        {"p": past, "id": snippet_id},
    )
    await db_session.commit()

    response = await db_client.get(f"/snippets/{snippet_id}")
    assert response.status_code == 410
    assert response.json() == {"status": "gone", "reason": "expired"}


async def test_get_taken_down_returns_410_taken_down(
    db_session: AsyncSession, db_client: AsyncClient
) -> None:
    create = await db_client.post("/snippets", json=_link_body())
    snippet_id = create.json()["id"]

    now = datetime.now(tz=UTC)
    await db_session.execute(
        sa_text(
            "UPDATE snippets SET taken_down_at = :p, taken_down_reason = :r WHERE id = :id"
        ),
        {"p": now, "r": "spam", "id": snippet_id},
    )
    await db_session.commit()

    response = await db_client.get(f"/snippets/{snippet_id}")
    assert response.status_code == 410
    assert response.json() == {"status": "gone", "reason": "taken_down"}


# ---------------------------------------------------------------------------
# Concurrency — the atomic CAS must prevent double-burn
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("attempts", [4])
async def test_burn_is_atomic_under_concurrency(
    db_client: AsyncClient, attempts: int
) -> None:
    """Fire N concurrent GETs at a freshly-created single-read snippet and
    assert exactly one wins. Catches the classic read-then-write race that
    a naive implementation would have."""
    import asyncio

    create = await db_client.post("/snippets", json=_link_body())
    snippet_id = create.json()["id"]

    responses = await asyncio.gather(
        *(db_client.get(f"/snippets/{snippet_id}") for _ in range(attempts))
    )
    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 1, statuses
    assert statuses.count(410) == attempts - 1, statuses
