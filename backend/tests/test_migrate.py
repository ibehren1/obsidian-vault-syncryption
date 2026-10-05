import hashlib
import secrets

import pytest

from syncryption_server.migrate import MARKER, MigrationError, migrate_to_s3
from syncryption_server.storage import LocalBlobStore, S3BlobStore, blob_key


async def local_blobs(data_dir, count: int) -> dict[str, bytes]:
    store = LocalBlobStore(data_dir)
    await store.start()
    blobs = {}
    for i in range(count):
        data = secrets.token_bytes(100 + i)
        key = blob_key("user", "vault", hashlib.sha256(data).hexdigest())
        await store.put(key, data)
        blobs[key] = data
    return blobs


@pytest.fixture
async def s3(s3_settings):
    store = S3BlobStore(s3_settings)
    await store.start()
    yield store
    await store.close()


class FailingAfter:
    """Wraps a store and fails every put once `n` have finished, like a run that is killed.

    Puts already in flight when the failure cancels the workers may or may not finish, so
    `stored` counts the ones that did.
    """

    def __init__(self, store, n: int):
        self.store, self.n, self.stored = store, n, 0

    async def put(self, key, data):
        if self.stored >= self.n:
            raise OSError("connection lost")
        await self.store.put(key, data)
        self.stored += 1

    def __getattr__(self, name):
        return getattr(self.store, name)


async def test_copies_every_blob_and_keeps_local_files(tmp_path, s3):
    blobs = await local_blobs(tmp_path, 25)
    result = await migrate_to_s3(tmp_path, s3)
    assert (result.copied, result.skipped) == (25, 0)
    for key, data in blobs.items():
        assert await s3.get(key) == data
        assert (tmp_path / key).read_bytes() == data
    assert (tmp_path / MARKER).exists()


async def test_resumes_after_an_interrupted_run(tmp_path, s3):
    await local_blobs(tmp_path, 20)
    failing = FailingAfter(s3, 7)
    with pytest.raises(OSError):
        await migrate_to_s3(tmp_path, failing)
    assert not (tmp_path / MARKER).exists()
    assert failing.stored >= 7

    result = await migrate_to_s3(tmp_path, s3)
    assert result.copied + result.skipped == 20
    assert result.skipped >= failing.stored
    assert len([k async for k in s3.iter_keys("blobs/")]) == 20


async def test_second_run_does_nothing(tmp_path, s3):
    await local_blobs(tmp_path, 3)
    await migrate_to_s3(tmp_path, s3)
    again = await migrate_to_s3(tmp_path, s3)
    assert again.already_done and again.copied == 0


async def test_no_local_blobs(tmp_path, s3):
    result = await migrate_to_s3(tmp_path, s3)
    assert (result.copied, result.skipped) == (0, 0)
    assert (tmp_path / MARKER).exists()


async def test_stops_on_a_corrupt_local_blob(tmp_path, s3):
    blobs = await local_blobs(tmp_path, 3)
    key = next(iter(blobs))
    (tmp_path / key).write_bytes(b"damaged")
    with pytest.raises(MigrationError, match="doesn't match its hash"):
        await migrate_to_s3(tmp_path, s3)
    assert not (tmp_path / MARKER).exists()
