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


# ---------------------------------------------------------------------------
# Password gate — GET 401 + POST /verify-password
# ---------------------------------------------------------------------------


_RIGHT_HASH = b"\xa5" * 32
_WRONG_HASH = b"\x5a" * 32
_SALT = b"\x07" * 16


async def _create_with_password(
    db_client: AsyncClient,
    hash_bytes: bytes = _RIGHT_HASH,
    salt_bytes: bytes = _SALT,
) -> str:
    create = await db_client.post(
        "/snippets",
        json=_link_body(
            password_hash=_b64(hash_bytes),
            password_salt=_b64(salt_bytes),
        ),
    )
    assert create.status_code == 201, create.text
    return str(create.json()["id"])


async def test_get_password_protected_returns_401_with_salt(
    db_client: AsyncClient,
) -> None:
    snippet_id = await _create_with_password(db_client)
    response = await db_client.get(f"/snippets/{snippet_id}")
    assert response.status_code == 401
    body = response.json()
    assert body["status"] == "password_required"
    assert base64.b64decode(body["password_salt"]) == _SALT


async def test_get_password_protected_does_not_burn(db_client: AsyncClient) -> None:
    """A wrong-password GET must NOT consume the read budget; otherwise
    a single failed attempt would torch a max_reads=1 snippet."""
    snippet_id = await _create_with_password(db_client)
    for _ in range(5):
        gated = await db_client.get(f"/snippets/{snippet_id}")
        assert gated.status_code == 401

    # Successful verify on the right hash should still find the snippet
    # unburned and return it.
    verified = await db_client.post(
        f"/snippets/{snippet_id}/verify-password",
        json={"password_hash": _b64(_RIGHT_HASH)},
    )
    assert verified.status_code == 200


async def test_verify_password_wrong_hash_returns_401(db_client: AsyncClient) -> None:
    snippet_id = await _create_with_password(db_client)
    response = await db_client.post(
        f"/snippets/{snippet_id}/verify-password",
        json={"password_hash": _b64(_WRONG_HASH)},
    )
    assert response.status_code == 401


async def test_verify_password_correct_hash_burns_and_returns_content(
    db_client: AsyncClient,
) -> None:
    snippet_id = await _create_with_password(db_client)
    first = await db_client.post(
        f"/snippets/{snippet_id}/verify-password",
        json={"password_hash": _b64(_RIGHT_HASH)},
    )
    assert first.status_code == 200
    body = first.json()
    assert body["id"] == snippet_id
    assert body["read_count"] == 1

    # The second correct-password attempt now sees a burned snippet.
    second = await db_client.post(
        f"/snippets/{snippet_id}/verify-password",
        json={"password_hash": _b64(_RIGHT_HASH)},
    )
    assert second.status_code == 410
    assert second.json() == {"status": "gone", "reason": "burned"}


async def test_verify_password_unknown_snippet_returns_404(
    db_client: AsyncClient,
) -> None:
    response = await db_client.post(
        "/snippets/aaaaaaaaaaaa/verify-password",
        json={"password_hash": _b64(_RIGHT_HASH)},
    )
    assert response.status_code == 404


async def test_verify_password_unprotected_snippet_returns_400(
    db_client: AsyncClient,
) -> None:
    create = await db_client.post("/snippets", json=_link_body())
    snippet_id = create.json()["id"]
    response = await db_client.post(
        f"/snippets/{snippet_id}/verify-password",
        json={"password_hash": _b64(_RIGHT_HASH)},
    )
    assert response.status_code == 400


async def test_verify_password_rate_limited_per_snippet(
    rate_limit_client: AsyncClient,
) -> None:
    """5/min/IP/snippet from PROJECT.md §12. The 6th attempt from the
    same IP within a minute on the same snippet returns 429; another
    snippet from the same IP still gets through."""
    # Two separate snippets, both password-protected.
    create_a = await rate_limit_client.post(
        "/snippets",
        json=_link_body(
            password_hash=_b64(_RIGHT_HASH),
            password_salt=_b64(_SALT),
        ),
        headers={"CF-Connecting-IP": "203.0.113.71"},
    )
    create_b = await rate_limit_client.post(
        "/snippets",
        json=_link_body(
            password_hash=_b64(_RIGHT_HASH),
            password_salt=_b64(_SALT),
        ),
        headers={"CF-Connecting-IP": "203.0.113.71"},
    )
    id_a = create_a.json()["id"]
    id_b = create_b.json()["id"]

    headers = {"CF-Connecting-IP": "203.0.113.71"}
    body_wrong = {"password_hash": _b64(_WRONG_HASH)}

    # Five wrong attempts against snippet A burn the bucket.
    for _ in range(5):
        resp = await rate_limit_client.post(
            f"/snippets/{id_a}/verify-password", json=body_wrong, headers=headers
        )
        assert resp.status_code == 401

    overflow = await rate_limit_client.post(
        f"/snippets/{id_a}/verify-password", json=body_wrong, headers=headers
    )
    assert overflow.status_code == 429
    assert "retry-after" in {k.lower() for k in overflow.headers}

    # Snippet B from the same IP is unaffected.
    other = await rate_limit_client.post(
        f"/snippets/{id_b}/verify-password", json=body_wrong, headers=headers
    )
    assert other.status_code == 401


async def test_verify_password_rejects_extra_fields(db_client: AsyncClient) -> None:
    snippet_id = await _create_with_password(db_client)
    response = await db_client.post(
        f"/snippets/{snippet_id}/verify-password",
        json={"password_hash": _b64(_RIGHT_HASH), "uninvited": "guest"},
    )
    assert response.status_code == 422
