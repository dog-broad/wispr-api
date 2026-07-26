from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.lib.storage import get_object_store
from app.main import app
from app.models.snippets import ShareMode, Snippet


class FakeStore:
    """In-memory stand-in for R2: records presigned keys and answers HEADs from
    a preset size map so file finalize is testable without a bucket."""

    def __init__(self, sizes: dict[str, int] | None = None) -> None:
        self.sizes = sizes if sizes is not None else {}
        self.put_keys: list[str] = []

    def presign_put(self, key: str) -> str:
        self.put_keys.append(key)
        return f"https://r2.example/{key}?sig=put"

    def presign_get(self, key: str) -> str:
        return f"https://r2.example/{key}?sig=get"

    async def head_size(self, key: str) -> int | None:
        return self.sizes.get(key)

    async def delete_keys(self, keys: list[str]) -> None:
        for key in keys:
            self.sizes.pop(key, None)

    async def list_objects(self, prefix: str) -> list[tuple[str, datetime]]:
        now = datetime.now(tz=UTC)
        return [(k, now) for k in self.sizes if k.startswith(prefix)]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _use_store(store: object | None) -> None:
    app.dependency_overrides[get_object_store] = lambda: store


def _clear_store() -> None:
    app.dependency_overrides.pop(get_object_store, None)


async def test_presign_returns_one_url_per_chunk(db_client: AsyncClient) -> None:
    store = FakeStore()
    _use_store(store)
    try:
        resp = await db_client.post("/snippets/files/presign", json={"chunk_count": 3})
    finally:
        _clear_store()
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["storage_object_key"].startswith("files/")
    assert body["chunk_count"] == 3
    assert [c["index"] for c in body["chunks"]] == [0, 1, 2]
    assert all(c["url"] for c in body["chunks"])
    # Each chunk is its own object under the key prefix.
    assert store.put_keys == [f"{body['storage_object_key']}/{i}" for i in range(3)]


async def test_presign_503_when_r2_unconfigured(db_client: AsyncClient) -> None:
    _use_store(None)
    try:
        resp = await db_client.post("/snippets/files/presign", json={"chunk_count": 1})
    finally:
        _clear_store()
    assert resp.status_code == 503


async def test_presign_rejects_out_of_range_chunk_count(db_client: AsyncClient) -> None:
    _use_store(FakeStore())
    try:
        assert (
            await db_client.post("/snippets/files/presign", json={"chunk_count": 0})
        ).status_code == 422
        assert (
            await db_client.post("/snippets/files/presign", json={"chunk_count": 26})
        ).status_code == 422
    finally:
        _clear_store()


def _file_link_body(key: str, chunk_count: int, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "share_mode": "link",
        "content_type": "file",
        "encrypted_metadata": _b64(b"meta"),
        "ttl_seconds": 600,
        "storage_object_key": key,
        "chunk_count": chunk_count,
    }
    body.update(overrides)
    return body


async def test_finalize_file_link_heads_chunks_and_sums_size(
    db_client: AsyncClient, db_session: AsyncSession
) -> None:
    key = "files/abc123"
    store = FakeStore({f"{key}/0": 1_048_576, f"{key}/1": 500})
    _use_store(store)
    try:
        resp = await db_client.post("/snippets", json=_file_link_body(key, 2))
    finally:
        _clear_store()
    assert resp.status_code == 201, resp.text
    snippet_id = resp.json()["id"]
    db_session.expunge_all()
    snip = await db_session.scalar(select(Snippet).where(Snippet.id == snippet_id))
    assert snip is not None
    assert snip.share_mode is ShareMode.link
    assert snip.storage_object_key == key
    assert snip.chunk_count == 2
    assert snip.ciphertext_inline is None
    assert snip.size_bytes == 1_048_576 + 500


async def test_finalize_rejects_missing_chunk(db_client: AsyncClient) -> None:
    key = "files/missing1"
    # Only chunk 0 landed; chunk 1 never uploaded.
    store = FakeStore({f"{key}/0": 100})
    _use_store(store)
    try:
        resp = await db_client.post("/snippets", json=_file_link_body(key, 2))
    finally:
        _clear_store()
    assert resp.status_code == 400
    assert "chunk 1" in resp.json()["detail"]


async def test_create_rejects_both_inline_and_storage(db_client: AsyncClient) -> None:
    resp = await db_client.post(
        "/snippets",
        json=_file_link_body("files/x", 1, ciphertext=_b64(b"inline")),
    )
    assert resp.status_code == 422


async def test_create_rejects_neither_source(db_client: AsyncClient) -> None:
    resp = await db_client.post(
        "/snippets",
        json={
            "share_mode": "link",
            "content_type": "text",
            "encrypted_metadata": _b64(b"m"),
            "ttl_seconds": 600,
        },
    )
    assert resp.status_code == 422


async def test_file_finalize_503_when_store_unconfigured(db_client: AsyncClient) -> None:
    _use_store(None)
    try:
        resp = await db_client.post("/snippets", json=_file_link_body("files/x", 1))
    finally:
        _clear_store()
    assert resp.status_code == 503


async def test_get_file_link_returns_presigned_download_urls(db_client: AsyncClient) -> None:
    key = "files/dl123"
    store = FakeStore({f"{key}/0": 1000, f"{key}/1": 1000})
    _use_store(store)
    try:
        created = await db_client.post("/snippets", json=_file_link_body(key, 2))
        assert created.status_code == 201, created.text
        snippet_id = created.json()["id"]
        got = await db_client.get(f"/snippets/{snippet_id}")
    finally:
        _clear_store()
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["ciphertext"] == ""  # file-backed: nothing inline
    assert body["chunk_count"] == 2
    assert len(body["download_urls"]) == 2
    assert all("sig=get" in url for url in body["download_urls"])
