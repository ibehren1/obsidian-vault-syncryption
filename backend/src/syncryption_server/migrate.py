"""`MIGRATE_TO_S3` and `MIGRATE_FROM_S3`: copy blobs between local storage and S3 before the
server starts (docs/self-hosting.md 7 and 8).

Blobs are content addressed, so a copy is idempotent: a blob that is already at the
destination with the right size is skipped, and a run that was killed partway simply
continues. Every blob is checked against its SHA-256 key before it is written, and its
size is checked again afterwards. The source is never deleted from.
"""

import asyncio
import hashlib
import logging
import shutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from syncryption_server.storage import BlobStore, LocalBlobStore

MARKER = ".migrated_to_s3"
FROM_MARKER = ".migrated_from_s3"
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
    # Blobs found at the source when the run started.
    total: int = 0


def _check_hash(key: str, data: bytes, where: str) -> None:
    if hashlib.sha256(data).hexdigest() != key.rsplit("/", 1)[-1]:
        raise MigrationError(f"{where} blob {key} doesn't match its hash")


async def _copy_all(
    source: BlobStore,
    copy: Callable[[str], Awaitable[None]],
    result: MigrationResult,
) -> None:
    # Counted with a first listing (keys aren't kept in memory) so progress has a total.
    # The server isn't serving yet, so the source doesn't change in between.
    async for _ in source.iter_keys("blobs/"):
        result.total += 1
    log.info("migration: %d blobs to copy or check", result.total)
    queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=CONCURRENCY * 2)

    async def worker() -> None:
        while (key := await queue.get()) is not None:
            await copy(key)
            done = result.copied + result.skipped
            if done % PROGRESS_EVERY == 0:
                log.info(
                    "migration progress: %d of %d blobs (%d%%)",
                    done,
                    result.total,
                    100 * done // result.total,
                )

    try:
        async with asyncio.TaskGroup() as tasks:
            for _ in range(CONCURRENCY):
                tasks.create_task(worker())
            async for key in source.iter_keys("blobs/"):
                await queue.put(key)
            for _ in range(CONCURRENCY):
                await queue.put(None)
    except ExceptionGroup as group:
        raise group.exceptions[0] from None


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
        _check_hash(key, data, "local")
        if await s3.size(key) == len(data):
            result.skipped += 1
            return
        await s3.put(key, data)
        if await s3.size(key) != len(data):
            raise MigrationError(f"S3 copy of {key} has the wrong size")
        result.copied += 1
        result.bytes_copied += len(data)

    if (data_dir / "blobs").is_dir():
        await _copy_all(local, copy, result)

    marker.write_text(f"copied {result.copied}, already present {result.skipped}\n")
    (data_dir / FROM_MARKER).unlink(missing_ok=True)
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


def litestream_state(db_path: Path) -> Path:
    """Litestream's local replication state next to the database (not part of the data)."""
    return db_path.with_name(f".{db_path.name}-litestream")


async def migrate_from_s3(data_dir: Path, s3: BlobStore, db_path: Path) -> MigrationResult:
    """Copy every blob in the bucket to `data_dir`. Litestream doesn't run afterwards, so
    its local state is removed: a later move back to S3 then starts a fresh replica."""
    result = MigrationResult()
    marker = data_dir / FROM_MARKER
    if marker.exists():
        result.already_done = True
        log.info(
            "blobs were already migrated from S3 (%s exists); set MIGRATE_FROM_S3 back to "
            "FALSE and remove the S3 variables",
            marker,
        )
        return result

    local = LocalBlobStore(data_dir)
    await local.start()

    async def copy(key: str) -> None:
        # A local copy left from before the move to S3 is reused if it is intact.
        size = await local.size(key)
        if size is not None and size == await s3.size(key):
            existing = await local.get(key)
            if hashlib.sha256(existing).hexdigest() == key.rsplit("/", 1)[-1]:
                result.skipped += 1
                return
        data = await s3.get(key)
        _check_hash(key, data, "S3")
        await local.put(key, data)
        if await local.size(key) != len(data):
            raise MigrationError(f"local copy of {key} has the wrong size")
        result.copied += 1
        result.bytes_copied += len(data)

    await _copy_all(s3, copy, result)

    await asyncio.to_thread(shutil.rmtree, litestream_state(db_path), ignore_errors=True)
    marker.write_text(f"copied {result.copied}, already present {result.skipped}\n")
    (data_dir / MARKER).unlink(missing_ok=True)
    log.info(
        "migration from S3 complete: %d blobs copied (%d bytes), %d already present. "
        "Remove the S3 variables and set MIGRATE_FROM_S3 back to FALSE. The bucket was "
        "kept, including the stale database replica in litestream/; delete its contents "
        "once you are satisfied.",
        result.copied,
        result.bytes_copied,
        result.skipped,
    )
    return result


def check_not_moved_off_s3(data_dir: Path) -> None:
    """With S3 configured and no migration: refuse data that was moved off S3, or the
    server would serve the stale bucket and miss every blob written locally since."""
    if (data_dir / FROM_MARKER).exists():
        raise MigrationError(
            f"blobs were moved off S3 ({data_dir / FROM_MARKER} exists). Remove the S3 "
            "variables to keep local storage, or set MIGRATE_TO_S3=TRUE to move back"
        )
