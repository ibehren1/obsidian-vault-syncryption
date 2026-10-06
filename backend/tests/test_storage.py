import os
from pathlib import Path

import aioboto3
import pytest
from botocore.exceptions import ClientError

from syncryption_server import storage
from syncryption_server.config import S3Settings
from syncryption_server.storage import BlobNotFound, LocalBlobStore, S3BlobStore, blob_key

KEY = blob_key("user", "vault", "ab" + "0" * 62)


@pytest.fixture(params=["local", "s3"])
async def store(request, tmp_path):
    if request.param == "local":
        s = LocalBlobStore(tmp_path)
    else:
        s = S3BlobStore(request.getfixturevalue("s3_settings"))
    await s.start()
    yield s
    await s.close()


def test_blob_key_layout():
    assert KEY == "blobs/user/vault/ab/ab" + "0" * 62


async def test_round_trip(store):
    await store.ping()
    assert not await store.exists(KEY)
    assert await store.size(KEY) is None
    with pytest.raises(BlobNotFound):
        await store.get(KEY)

    await store.put(KEY, b"ciphertext")
    assert await store.exists(KEY)
    assert await store.size(KEY) == 10
    assert await store.get(KEY) == b"ciphertext"
    await store.put(KEY, b"ciphertext")  # idempotent
    assert [k async for k in store.iter_keys()] == [KEY]
    assert [k async for k in store.iter_keys("blobs/other/")] == []

    await store.delete(KEY)
    assert not await store.exists(KEY)
    await store.delete(KEY)  # deleting a missing blob is fine


async def test_iter_keys_by_prefix(store):
    keys = sorted(
        blob_key(user, vault, c * 64)
        for user, vault, c in [
            ("u1", "v1", "a"),
            ("u1", "v1", "b"),
            ("u1", "v2", "c"),
            ("u2", "v3", "d"),
        ]
    )
    for key in keys:
        await store.put(key, b"x")
    assert [k async for k in store.iter_keys()] == keys
    assert [k async for k in store.iter_keys("blobs/")] == keys
    assert [k async for k in store.iter_keys("blobs/u1/v1/")] == keys[:2]
    assert [k async for k in store.iter_keys("blobs/u1/")] == keys[:3]
    assert [k async for k in store.iter_keys("blobs/u1/v")] == keys[:3]
    assert [k async for k in store.iter_keys("blobs/nobody/")] == []
    assert [k async for k in store.iter_keys("other/")] == []


async def test_local_iter_keys_walks_only_the_prefix(tmp_path, monkeypatch):
    s = LocalBlobStore(tmp_path)
    await s.start()
    await s.put(blob_key("u1", "v1", "a" * 64), b"x")
    await s.put(blob_key("u2", "v2", "b" * 64), b"x")
    walked = []
    rglob = Path.rglob

    def spy(self, pattern):
        walked.append(self)
        return rglob(self, pattern)

    monkeypatch.setattr(Path, "rglob", spy)
    assert [k async for k in s.iter_keys("blobs/u2/v2/")] == [blob_key("u2", "v2", "b" * 64)]
    assert walked == [tmp_path / "blobs/u2/v2"]
    (tmp_path / "blobs/u2/v2/bb/.tmp-123").write_bytes(b"partial")
    assert [k async for k in s.iter_keys("blobs/u2/")] == [blob_key("u2", "v2", "b" * 64)]


@pytest.mark.parametrize("key", ["", "/etc/passwd", "blobs/../x", "blobs//x", "blobs/./x"])
async def test_rejects_unsafe_keys(store, key):
    with pytest.raises(ValueError):
        await store.put(key, b"x")


async def test_local_store_writes_atomically(tmp_path):
    s = LocalBlobStore(tmp_path)
    await s.start()
    await s.put(KEY, b"data")
    leftovers = [p for p in (tmp_path / "blobs").rglob(".tmp-*")]
    assert leftovers == []
    assert (tmp_path / KEY).read_bytes() == b"data"


async def test_s3_store_finds_the_bucket_region(s3_settings):
    s = S3BlobStore(s3_settings)
    await s.start()
    try:
        assert s._client.meta.region_name == "eu-west-1"
    finally:
        await s.close()


async def test_s3_store_falls_back_when_the_provider_has_no_bucket_location(
    s3_settings, monkeypatch
):
    # Some S3-compatible providers don't implement GetBucketLocation.
    def not_implemented(**_):
        error = {"Error": {"Code": "NotImplemented", "Message": "not implemented"}}
        raise ClientError(error, "GetBucketLocation")

    real_session = aioboto3.Session

    def session():
        s = real_session()
        s._session.register("before-call.s3.GetBucketLocation", not_implemented)
        return s

    monkeypatch.setattr(storage.aioboto3, "Session", session)
    s = S3BlobStore(s3_settings)
    await s.start()
    try:
        assert s._client.meta.region_name == "us-east-1"
        await s.put(KEY, b"x")
        assert await s.get(KEY) == b"x"
    finally:
        await s.close()


@pytest.mark.skipif(not os.environ.get("MINIO_ENDPOINT"), reason="set MINIO_ENDPOINT to run")
async def test_minio_round_trip():
    settings = S3Settings(
        os.environ.get("MINIO_BUCKET", "syncryption"),
        os.environ.get("MINIO_ACCESS_KEY", "minioadmin"),
        os.environ.get("MINIO_SECRET_KEY", "minioadmin"),
        endpoint_url=os.environ["MINIO_ENDPOINT"],
    )
    s = S3BlobStore(settings)
    await s.start()
    try:
        await s.put(KEY, b"minio")
        assert await s.get(KEY) == b"minio"
        await s.delete(KEY)
    finally:
        await s.close()
