import os

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
