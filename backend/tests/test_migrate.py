import hashlib
import secrets

import pytest

from syncryption_server.migrate import (
    FROM_MARKER,
    MARKER,
    MigrationError,
    litestream_state,
    migrate_from_s3,
    migrate_to_s3,
)
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
    assert result.total == 25
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


async def s3_blobs(s3, count: int) -> dict[str, bytes]:
    blobs = {}
    for i in range(count):
        data = secrets.token_bytes(100 + i)
        key = blob_key("user", "vault", hashlib.sha256(data).hexdigest())
        await s3.put(key, data)
        blobs[key] = data
    return blobs


async def test_from_s3_copies_every_blob_and_keeps_the_bucket(tmp_path, s3):
    blobs = await s3_blobs(s3, 25)
    state = litestream_state(tmp_path / "meta.db")
    state.mkdir()
    (state / "ltx").write_text("x")
    result = await migrate_from_s3(tmp_path, s3, tmp_path / "meta.db")
    assert (result.copied, result.skipped) == (25, 0)
    for key, data in blobs.items():
        assert (tmp_path / key).read_bytes() == data
        assert await s3.get(key) == data
    assert (tmp_path / FROM_MARKER).exists()
    assert not state.exists()


async def test_from_s3_resumes_after_an_interrupted_run(tmp_path, s3):
    await s3_blobs(s3, 20)
    local = LocalBlobStore(tmp_path)
    failing = FailingAfter(local, 7)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("syncryption_server.migrate.LocalBlobStore", lambda _: failing)
        with pytest.raises(OSError):
            await migrate_from_s3(tmp_path, s3, tmp_path / "meta.db")
    assert not (tmp_path / FROM_MARKER).exists()
    assert failing.stored >= 7

    result = await migrate_from_s3(tmp_path, s3, tmp_path / "meta.db")
    assert result.copied + result.skipped == 20
    assert result.skipped >= failing.stored
    assert len([k async for k in local.iter_keys("blobs/")]) == 20


async def test_from_s3_reuses_intact_local_blobs_and_replaces_damaged_ones(tmp_path, s3):
    blobs = await s3_blobs(s3, 3)
    intact, damaged, _ = blobs
    local = LocalBlobStore(tmp_path)
    await local.put(intact, blobs[intact])
    await local.put(damaged, bytes(len(blobs[damaged])))
    result = await migrate_from_s3(tmp_path, s3, tmp_path / "meta.db")
    assert (result.copied, result.skipped) == (2, 1)
    assert (tmp_path / damaged).read_bytes() == blobs[damaged]


async def test_from_s3_second_run_does_nothing(tmp_path, s3):
    await s3_blobs(s3, 3)
    await migrate_from_s3(tmp_path, s3, tmp_path / "meta.db")
    again = await migrate_from_s3(tmp_path, s3, tmp_path / "meta.db")
    assert again.already_done and again.copied == 0


async def test_from_s3_empty_bucket(tmp_path, s3):
    result = await migrate_from_s3(tmp_path, s3, tmp_path / "meta.db")
    assert (result.copied, result.skipped) == (0, 0)
    assert (tmp_path / FROM_MARKER).exists()


async def test_from_s3_stops_on_a_corrupt_blob(tmp_path, s3):
    blobs = await s3_blobs(s3, 3)
    await s3.put(next(iter(blobs)), b"damaged")
    with pytest.raises(MigrationError, match="S3 blob .* doesn't match its hash"):
        await migrate_from_s3(tmp_path, s3, tmp_path / "meta.db")
    assert not (tmp_path / FROM_MARKER).exists()


async def test_round_trip_clears_the_other_marker(tmp_path, s3):
    await local_blobs(tmp_path, 2)
    await migrate_to_s3(tmp_path, s3)
    await migrate_from_s3(tmp_path, s3, tmp_path / "meta.db")
    assert (tmp_path / FROM_MARKER).exists() and not (tmp_path / MARKER).exists()
    again = await migrate_to_s3(tmp_path, s3)
    assert not again.already_done
    assert (tmp_path / MARKER).exists() and not (tmp_path / FROM_MARKER).exists()


async def test_progress_counts_against_the_total(tmp_path, s3, caplog, monkeypatch):
    monkeypatch.setattr("syncryption_server.migrate.PROGRESS_EVERY", 4)
    await s3_blobs(s3, 10)
    with caplog.at_level("INFO", logger="syncryption_server.migrate"):
        await migrate_from_s3(tmp_path, s3, tmp_path / "meta.db")
    messages = [r.getMessage() for r in caplog.records if r.name == "syncryption_server.migrate"]
    assert messages[0] == "migration: 10 blobs to copy or check"
    assert [m for m in messages if "progress" in m] == [
        "migration progress: 4 of 10 blobs (40%)",
        "migration progress: 8 of 10 blobs (80%)",
    ]
