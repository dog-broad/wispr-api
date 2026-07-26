from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Annotated, Protocol

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from fastapi import Depends

from app.config import Settings, get_settings

# File payloads live in R2 as one object per 1 MiB ciphertext chunk, keyed
# ``{storage_object_key}/{index}`` under a ``files/`` prefix. See the files
# decision. Presigned URLs let the browser talk to R2 directly so file bytes
# never transit the API.

_PUT_EXPIRY_SECONDS = 15 * 60
_GET_EXPIRY_SECONDS = 15 * 60
_DELETE_BATCH = 1000


class ObjectStore(Protocol):
    def presign_put(self, key: str) -> str: ...
    def presign_get(self, key: str) -> str: ...
    async def head_size(self, key: str) -> int | None: ...
    async def delete_keys(self, keys: list[str]) -> None: ...
    async def list_objects(self, prefix: str) -> list[tuple[str, datetime]]: ...
    # Server-side upload (backups) — the browser uses presigned PUTs instead.
    async def put_object(self, key: str, data: bytes) -> None: ...


class R2Store:
    def __init__(self, *, endpoint: str, access_key: str, secret_key: str, bucket: str) -> None:
        self._bucket = bucket
        # region_name is irrelevant to R2 but boto3 requires one; s3v4 signing
        # is what R2 expects for presigned URLs.
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name="auto",
            config=Config(signature_version="s3v4"),
        )

    def presign_put(self, key: str) -> str:
        return str(
            self._client.generate_presigned_url(
                "put_object",
                Params={"Bucket": self._bucket, "Key": key},
                ExpiresIn=_PUT_EXPIRY_SECONDS,
            )
        )

    def presign_get(self, key: str) -> str:
        return str(
            self._client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self._bucket, "Key": key},
                ExpiresIn=_GET_EXPIRY_SECONDS,
            )
        )

    async def head_size(self, key: str) -> int | None:
        def _head() -> int | None:
            try:
                resp = self._client.head_object(Bucket=self._bucket, Key=key)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
                    return None
                raise
            size: int = resp["ContentLength"]
            return size

        return await asyncio.to_thread(_head)

    async def delete_keys(self, keys: list[str]) -> None:
        if not keys:
            return

        def _delete() -> None:
            for start in range(0, len(keys), _DELETE_BATCH):
                batch = keys[start : start + _DELETE_BATCH]
                self._client.delete_objects(
                    Bucket=self._bucket,
                    Delete={"Objects": [{"Key": k} for k in batch], "Quiet": True},
                )

        await asyncio.to_thread(_delete)

    async def put_object(self, key: str, data: bytes) -> None:
        def _put() -> None:
            self._client.put_object(Bucket=self._bucket, Key=key, Body=data)

        await asyncio.to_thread(_put)

    async def list_objects(self, prefix: str) -> list[tuple[str, datetime]]:
        def _list() -> list[tuple[str, datetime]]:
            out: list[tuple[str, datetime]] = []
            paginator = self._client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    out.append((obj["Key"], obj["LastModified"]))
            return out

        return await asyncio.to_thread(_list)


# Cache one client per credential set so we don't rebuild a boto3 client per
# request; keyed on the config tuple so a test that swaps settings gets a
# fresh store.
_cache: tuple[tuple[str, str, str, str], R2Store] | None = None


def build_object_store(settings: Settings) -> ObjectStore | None:
    """An R2 store, or None when R2 isn't configured (local dev). A None store
    makes the file endpoints report 503 rather than half-work."""
    global _cache
    endpoint = settings.r2_endpoint
    access_key = settings.r2_access_key_id
    secret_key = settings.r2_secret_access_key
    bucket = settings.r2_bucket
    if not (endpoint and access_key and secret_key and bucket):
        return None
    key = (endpoint, access_key, secret_key, bucket)
    if _cache is not None and _cache[0] == key:
        return _cache[1]
    store = R2Store(endpoint=endpoint, access_key=access_key, secret_key=secret_key, bucket=bucket)
    _cache = (key, store)
    return store


def get_object_store(settings: Annotated[Settings, Depends(get_settings)]) -> ObjectStore | None:
    return build_object_store(settings)


ObjectStoreDep = Annotated[ObjectStore | None, Depends(get_object_store)]
