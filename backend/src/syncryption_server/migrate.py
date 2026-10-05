"""`MIGRATE_TO_S3`: copy local blobs to S3 before the server starts (docs/PLAN.md, Hosting).

Blobs are content addressed, so the copy is idempotent: a blob that is already in the
bucket with the right size is skipped, and a run that was killed partway simply continues.
Every uploaded blob is checked with a HEAD request. Local files are never deleted.
"""

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

from syncryption_server.storage import BlobStore, LocalBlobStore

MARKER = ".migrated_to_s3"
CONCURRENCY = 8
PROGRESS_EVERY = 1000

log = logging.getLogger(__name__)


class MigrationError(Exception):
    pass


@dataclass
class MigrationResult:
    copied: int = 0
    skipped: int = 0
    bytes_copied: int = 0
    already_done: bool = False


async def migrate_to_s3(data_dir: Path, s3: BlobStore) -> MigrationResult:
    result = MigrationResult()
    marker = data_dir / MARKER
    if marker.exists():
        result.already_done = True
        log.info(
            "blobs were already migrated to S3 (%s exists); set MIGRATE_TO_S3 back to FALSE",
            marker,
        )
        return result

    local = LocalBlobStore(data_dir)

    async def copy(key: str) -> None:
        data = await local.get(key)
        if hashlib.sha256(data).hexdigest() != key.rsplit("/", 1)[-1]:
            raise MigrationError(f"local blob {key} doesn't match its hash")
        if await s3.size(key) == len(data):
            result.skipped += 1
            return
        await s3.put(key, data)
        if await s3.size(key) != len(data):
            raise MigrationError(f"S3 copy of {key} has the wrong size")
        result.copied += 1
        result.bytes_copied += len(data)
        if (result.copied + result.skipped) % PROGRESS_EVERY == 0:
            log.info("migration progress: %d blobs", result.copied + result.skipped)

    queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=CONCURRENCY * 2)

    async def worker() -> None:
        while (key := await queue.get()) is not None:
            await copy(key)

    if (data_dir / "blobs").is_dir():
        try:
            async with asyncio.TaskGroup() as tasks:
                for _ in range(CONCURRENCY):
                    tasks.create_task(worker())
                async for key in local.iter_keys("blobs/"):
                    await queue.put(key)
                for _ in range(CONCURRENCY):
                    await queue.put(None)
        except ExceptionGroup as group:
            raise group.exceptions[0] from None

    marker.write_text(f"copied {result.copied}, already present {result.skipped}\n")
    log.info(
        "migration to S3 complete: %d blobs copied (%d bytes), %d already present. "
        "Set MIGRATE_TO_S3 back to FALSE. Local blobs in %s were kept; delete them once "
        "you are satisfied.",
        result.copied,
        result.bytes_copied,
        result.skipped,
        data_dir / "blobs",
    )
    return result
