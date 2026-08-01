from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from app.lib.storage import ObjectStore

_BACKUP_PREFIX = "backups/"


async def run_pg_dump(database_url: str) -> bytes:
    """Dump the database to a compressed-custom-format blob via ``pg_dump``.

    Isolated behind its own function so the upload/audit path can be tested
    without a live ``pg_dump`` binary. The URL is passed as a single argument
    (SQLAlchemy's ``+asyncpg`` driver suffix stripped; pg_dump wants a plain
    ``postgresql://`` DSN)."""
    dsn = database_url.replace("+asyncpg", "")
    proc = await asyncio.create_subprocess_exec(
        "pg_dump",
        "--format=custom",
        dsn,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"pg_dump failed ({proc.returncode}): {stderr.decode(errors='replace')}")
    return stdout


async def create_backup(store: ObjectStore, database_url: str) -> tuple[str, int]:
    """Dump the DB and upload it to R2 under ``backups/``. Returns (key, size)."""
    dump = await run_pg_dump(database_url)
    stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    key = f"{_BACKUP_PREFIX}wispr-{stamp}.dump"
    await store.put_object(key, dump)
    return key, len(dump)
