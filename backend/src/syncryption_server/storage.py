"""Blob storage (docs/architecture.md 2.2).

Both stores use the same keys, `blobs/<userId>/<vaultId>/<blobId[0:2]>/<blobId>`, so
`MIGRATE_TO_S3` is a straight copy.
"""

import asyncio
import os
import tempfile
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any, Protocol

import aioboto3
from botocore.exceptions import ClientError

from syncryption_server.config import S3Settings


def blob_key(user_id: str, vault_id: str, blob_id: str) -> str:
    return f"blobs/{user_id}/{vault_id}/{blob_id[:2]}/{blob_id}"


class BlobNotFound(Exception):
    pass


class BlobStore(Protocol):
    async def start(self) -> None: ...
    async def close(self) -> None: ...
    async def ping(self) -> None: ...
    async def put(self, key: str, data: bytes) -> None: ...
    async def get(self, key: str) -> bytes: ...
    async def exists(self, key: str) -> bool: ...
    async def size(self, key: str) -> int | None: ...
    async def delete(self, key: str) -> None: ...
    def iter_keys(self, prefix: str = "") -> AsyncIterator[str]: ...


def _check_key(key: str) -> None:
    parts = key.split("/")
    if not key or key.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise ValueError("invalid blob key")


class LocalBlobStore:
    """Files under a root directory, written atomically (temp file, fsync, rename)."""

    def __init__(self, root: Path):
        self.root = root

    def _path(self, key: str) -> Path:
        _check_key(key)
        return self.root / key

    async def start(self) -> None:
        await asyncio.to_thread((self.root / "blobs").mkdir, parents=True, exist_ok=True)

    async def close(self) -> None:
        pass

    async def ping(self) -> None:
        if not await asyncio.to_thread(os.access, self.root / "blobs", os.W_OK):
            raise OSError("blob directory is not writable")

    async def put(self, key: str, data: bytes) -> None:
        await asyncio.to_thread(self._put, self._path(key), data)

    @staticmethod
    def _put(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    async def get(self, key: str) -> bytes:
        try:
            return await asyncio.to_thread(self._path(key).read_bytes)
        except FileNotFoundError as e:
            raise BlobNotFound(key) from e

    async def exists(self, key: str) -> bool:
        return await asyncio.to_thread(self._path(key).is_file)

    async def size(self, key: str) -> int | None:
        try:
            return (await asyncio.to_thread(self._path(key).stat)).st_size
        except FileNotFoundError:
            return None

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self._path(key).unlink, missing_ok=True)

    async def iter_keys(self, prefix: str = "") -> AsyncIterator[str]:
        base = self.root / "blobs"
        paths = await asyncio.to_thread(lambda: sorted(p for p in base.rglob("*") if p.is_file()))
        for p in paths:
            key = p.relative_to(self.root).as_posix()
            if not p.name.startswith(".tmp-") and key.startswith(prefix):
                yield key


class S3BlobStore:
    """Objects in an S3 bucket, through aioboto3.

    The region comes from GetBucketLocation. Some S3-compatible providers don't implement
    it, so with a custom endpoint a failure falls back to `us-east-1`, which MinIO, R2 and
    most others accept.
    """

    def __init__(self, settings: S3Settings):
        self.settings = settings
        self._stack: AsyncExitStack | None = None
        self._client: Any = None

    def _client_args(self, region: str) -> dict[str, Any]:
        return {
            "service_name": "s3",
            "region_name": region,
            "aws_access_key_id": self.settings.access_key,
            "aws_secret_access_key": self.settings.secret_key,
            "endpoint_url": self.settings.endpoint_url,
        }

    async def start(self) -> None:
        session = aioboto3.Session()
        async with session.client(**self._client_args("us-east-1")) as probe:
            try:
                location = await probe.get_bucket_location(Bucket=self.settings.bucket)
            except ClientError:
                if self.settings.endpoint_url is None:
                    raise
                location = {}
        region = location.get("LocationConstraint") or "us-east-1"
        self._stack = AsyncExitStack()
        self._client = await self._stack.enter_async_context(
            session.client(**self._client_args(region))
        )

    async def close(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None

    async def ping(self) -> None:
        await self._client.head_bucket(Bucket=self.settings.bucket)

    @staticmethod
    def _not_found(e: Exception) -> bool:
        code = getattr(e, "response", {}).get("Error", {}).get("Code")
        return code in ("404", "NoSuchKey", "NotFound")

    async def put(self, key: str, data: bytes) -> None:
        _check_key(key)
        await self._client.put_object(Bucket=self.settings.bucket, Key=key, Body=data)

    async def get(self, key: str) -> bytes:
        _check_key(key)
        try:
            response = await self._client.get_object(Bucket=self.settings.bucket, Key=key)
        except Exception as e:
            if self._not_found(e):
                raise BlobNotFound(key) from e
            raise
        async with response["Body"] as body:
            return await body.read()

    async def size(self, key: str) -> int | None:
        _check_key(key)
        try:
            response = await self._client.head_object(Bucket=self.settings.bucket, Key=key)
        except Exception as e:
            if self._not_found(e):
                return None
            raise
        return response["ContentLength"]

    async def exists(self, key: str) -> bool:
        return await self.size(key) is not None

    async def delete(self, key: str) -> None:
        _check_key(key)
        await self._client.delete_object(Bucket=self.settings.bucket, Key=key)

    async def iter_keys(self, prefix: str = "") -> AsyncIterator[str]:
        paginator = self._client.get_paginator("list_objects_v2")
        async for page in paginator.paginate(
            Bucket=self.settings.bucket, Prefix=prefix or "blobs/"
        ):
            for item in page.get("Contents", []):
                if item["Key"].startswith("blobs/"):
                    yield item["Key"]
