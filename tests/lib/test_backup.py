from __future__ import annotations

from typing import cast

import pytest

from app.lib import backup
from app.lib.storage import ObjectStore


class _FakeStore:
    def __init__(self) -> None:
        self.puts: list[tuple[str, bytes]] = []

    async def put_object(self, key: str, data: bytes) -> None:
        self.puts.append((key, data))


async def test_create_backup_uploads_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_dump(database_url: str) -> bytes:
        return b"PGDUMPDATA"

    monkeypatch.setattr(backup, "run_pg_dump", _fake_dump)
    store = _FakeStore()

    key, size = await backup.create_backup(cast(ObjectStore, store), "postgresql://u:p@h/db")

    assert key.startswith("backups/wispr-") and key.endswith(".dump")
    assert size == len(b"PGDUMPDATA")
    assert store.puts == [(key, b"PGDUMPDATA")]
