"""Blob storage (docs/architecture.md 2.2).

Both stores use the same keys, `blobs/<userId>/<vaultId>/<blobId[0:2]>/<blobId>`, so
`MIGRATE_TO_S3` and `MIGRATE_FROM_S3` are straight copies.
"""

import asyncio
import os
import tempfile
import time
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any, Protocol

import aioboto3
from botocore.exceptions import ClientError, HTTPClientError
from botocore.exceptions import ConnectionError as BotoConnectionError

from syncryption_server.config import S3Settings
from syncryption_server.metrics import S3Metrics

NOT_FOUND_CODES = ("404", "NoSuchKey", "NotFound")
THROTTLE_CODES = ("SlowDown", "Throttling", "ThrottlingException", "RequestLimitExceeded")


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
        # Walk only the deepest directory the prefix names (a vault purge lists one vault).
        head, _, _ = prefix.rpartition("/")
        if head == "blobs" or head.startswith("blobs/"):
            _check_key(head)
            base = self.root / head
        else:
            base = self.root / "blobs"

        def walk() -> list[Path]:
            if not base.is_dir():
                return []
            return sorted(p for p in base.rglob("*") if p.is_file())

        for p in await asyncio.to_thread(walk):
            key = p.relative_to(self.root).as_posix()
            if not p.name.startswith(".tmp-") and key.startswith(prefix):
                yield key


def s3_result(error: Exception) -> str:
    """The `result` label (metrics.S3_RESULTS) of a failed S3 call. Never the raw error
    code, which a provider could make anything."""
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code")
        status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") or 0
        if code in NOT_FOUND_CODES:
            return "not_found"
        if code in THROTTLE_CODES or status in (429, 503):
            return "throttled"
        if 400 <= status < 500:
            return "client_error"
        return "server_error"
    if isinstance(error, BotoConnectionError | HTTPClientError):
        return "connection"
    return "other"


class _Call:
    """One measured S3 call: `seen` notes the retries botocore made for its response."""

    def __init__(self, metrics: S3Metrics | None, operation: str):
        self.metrics = metrics
        self.operation = operation

    def seen(self, response: dict[str, Any]) -> dict[str, Any]:
        retries = response.get("ResponseMetadata", {}).get("RetryAttempts") or 0
        if self.metrics is not None and retries:
            self.metrics.retries.labels(self.operation).inc(retries)
        return response


class S3BlobStore:
    """Objects in an S3 bucket, through aioboto3.

    The region comes from GetBucketLocation. Some S3-compatible providers don't implement
    it, so with a custom endpoint a failure falls back to `us-east-1`, which MinIO, R2 and
    most others accept.
    """

    def __init__(self, settings: S3Settings, metrics: S3Metrics | None = None):
        self.settings = settings
        self.metrics = metrics
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

    @asynccontextmanager
    async def _measure(self, operation: str) -> AsyncIterator[_Call]:
        """Count and time the S3 call made inside, by its result. A cancelled call is left
        out of the counts."""
        m = self.metrics
        call = _Call(m, operation)
        if m is None:
            yield call
            return
        start = time.perf_counter()
        m.in_flight.inc()
        try:
            yield call
            result = "ok"
        except Exception as e:
            result = s3_result(e)
            if isinstance(e, ClientError):
                call.seen(e.response)
            raise
        except BaseException:
            result = None
            raise
        finally:
            m.in_flight.dec()
            if result is not None:
                m.requests.labels(operation, result).inc()
                m.duration.labels(operation).observe(time.perf_counter() - start)

    async def ping(self) -> None:
        async with self._measure("ping") as call:
            call.seen(await self._client.head_bucket(Bucket=self.settings.bucket))

    @staticmethod
    def _not_found(e: Exception) -> bool:
        code = getattr(e, "response", {}).get("Error", {}).get("Code")
        return code in NOT_FOUND_CODES

    async def put(self, key: str, data: bytes) -> None:
        _check_key(key)
        async with self._measure("put") as call:
            call.seen(
                await self._client.put_object(Bucket=self.settings.bucket, Key=key, Body=data)
            )
        if self.metrics is not None:
            self.metrics.uploaded.inc(len(data))

    async def get(self, key: str) -> bytes:
        _check_key(key)
        try:
            async with self._measure("get") as call:
                response = call.seen(
                    await self._client.get_object(Bucket=self.settings.bucket, Key=key)
                )
                async with response["Body"] as body:
                    data = await body.read()
        except Exception as e:
            if self._not_found(e):
                raise BlobNotFound(key) from e
            raise
        if self.metrics is not None:
            self.metrics.downloaded.inc(len(data))
        return data

    async def size(self, key: str) -> int | None:
        _check_key(key)
        try:
            async with self._measure("head") as call:
                response = call.seen(
                    await self._client.head_object(Bucket=self.settings.bucket, Key=key)
                )
        except Exception as e:
            if self._not_found(e):
                return None
            raise
        return response["ContentLength"]

    async def exists(self, key: str) -> bool:
        return await self.size(key) is not None

    async def delete(self, key: str) -> None:
        _check_key(key)
        async with self._measure("delete") as call:
            call.seen(await self._client.delete_object(Bucket=self.settings.bucket, Key=key))

    async def iter_keys(self, prefix: str = "") -> AsyncIterator[str]:
        args: dict[str, Any] = {"Bucket": self.settings.bucket, "Prefix": prefix or "blobs/"}
        while True:
            # One page per call, so each is measured on its own.
            async with self._measure("list") as call:
                page = call.seen(await self._client.list_objects_v2(**args))
            for item in page.get("Contents", []):
                if item["Key"].startswith("blobs/"):
                    yield item["Key"]
            if not page.get("IsTruncated"):
                return
            args["ContinuationToken"] = page["NextContinuationToken"]
