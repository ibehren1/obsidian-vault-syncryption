"""Encrypted chunk blobs, scoped per vault (docs/protocol.md 8)."""

import hashlib
import logging
import shutil
import sqlite3

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from syncryption_server.auth import ActiveCaller, Caller, State
from syncryption_server.config import DEMO_QUOTA
from syncryption_server.encoding import BLOB_ID_RE
from syncryption_server.errors import (
    ApiError,
    bad_request,
    not_found,
    quota_exceeded,
    storage_full,
    too_large,
)
from syncryption_server.state import AppState
from syncryption_server.storage import BlobNotFound, blob_key
from syncryption_server.vaults import require_member

MAX_BLOB_SIZE = 4 * 1024 * 1024 + 45
MAX_MISSING_IDS = 1000
GC_GRACE = 24 * 3600
# Free space kept on the data volume, where meta.db lives: below it, uploads and commits are
# refused, so the database never runs out of room (protocol.md 12).
DISK_RESERVE = 1024**3

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vaults/{vault_id}/blobs", tags=["blobs"])


class OctetStream(Response):
    """Only so the OpenAPI schema (and `docs/api.md`) says `application/octet-stream`."""

    media_type = "application/octet-stream"


RAW_BODY = {"requestBody": {"required": True, "content": {"application/octet-stream": {}}}}


class BlobInfo(BaseModel):
    id: str
    size: int


class MissingRequest(BaseModel):
    ids: list[str] = Field(max_length=MAX_MISSING_IDS)


class MissingResponse(BaseModel):
    missing: list[str]


def _blob_id(blob_id: str) -> str:
    if not BLOB_ID_RE.match(blob_id):
        raise bad_request("Blob ids are 64 lowercase hex characters.")
    return blob_id


async def _read_body(request: Request) -> bytes:
    length = request.headers.get("content-length")
    if length is not None and length.isdigit() and int(length) > MAX_BLOB_SIZE:
        raise too_large("Blobs are at most 4 MiB + 45 bytes.")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BLOB_SIZE:
            raise too_large("Blobs are at most 4 MiB + 45 bytes.")
    return bytes(body)


def require_disk(state: AppState) -> None:
    """Raise `507 storage_full` when the data volume has less than DISK_RESERVE free. The
    volume always holds meta.db, whether blobs go there or to S3."""
    try:
        free = shutil.disk_usage(state.settings.data_dir).free
    except OSError:
        return
    if free < DISK_RESERVE:
        log.warning("data volume has %d bytes free: refusing new data", free)
        raise storage_full()


@router.put(
    "/{blob_id}",
    status_code=201,
    response_model=BlobInfo,
    openapi_extra=RAW_BODY,
    responses={200: {"model": BlobInfo, "description": "The blob was already stored."}},
)
async def put_blob(
    vault_id: str, blob_id: str, request: Request, caller: ActiveCaller, state: State
) -> Response | BlobInfo:
    """Upload one encrypted chunk as raw bytes. The server hashes the body and refuses it
    with `422 hash_mismatch` unless the hash equals `blob_id`. A new blob is refused with
    `507 storage_full` when the server's data volume is nearly full, and with
    `507 quota_exceeded` when it would take the vault's stored blobs past the quota the
    administrator set (protocol.md 12)."""
    vault = await state.db.read(lambda: require_member(state, caller, vault_id))
    _blob_id(blob_id)
    data = await _read_body(request)
    if hashlib.sha256(data).hexdigest() != blob_id:
        raise ApiError(422, "hash_mismatch", "The blob doesn't match its id.")

    def exists() -> bool:
        return bool(
            state.db.one(
                "SELECT 1 FROM blobs WHERE vault_id = ? AND blob_id = ?", vault_id, blob_id
            )
        )

    def record() -> None:
        with state.db.transaction() as db:
            added = db.execute(
                "INSERT OR IGNORE INTO blobs (vault_id, blob_id, size, created_at) "
                "VALUES (?, ?, ?, ?)",
                (vault_id, blob_id, len(data), state.now()),
            ).rowcount
            if added:
                db.execute(
                    "UPDATE vaults SET blob_bytes = blob_bytes + ? WHERE id = ?",
                    (len(data), vault_id),
                )

    def check_quota() -> None:
        row = state.db.one("SELECT blob_bytes, blob_quota FROM vaults WHERE id = ?", vault_id)
        quota = row["blob_quota"]
        if state.settings.demo_mode:
            # Also caps vaults created before demo mode was turned on.
            quota = min(quota or DEMO_QUOTA, DEMO_QUOTA)
        if quota is not None and row["blob_bytes"] + len(data) > quota:
            raise quota_exceeded(quota, row["blob_bytes"])

    async with state.blob_lock(blob_id):
        if await state.db.read(exists):
            return Response(
                BlobInfo(id=blob_id, size=len(data)).model_dump_json(),
                status_code=200,
                media_type="application/json",
            )
        require_disk(state)
        await state.db.read(check_quota)
        # Store first, then record: a blob row always means the bytes are there.
        await state.store.put(blob_key(vault["user_id"], vault_id, blob_id), data)
        await state.db.run(record)
    return BlobInfo(id=blob_id, size=len(data))


@router.head("/{blob_id}", response_class=OctetStream)
async def head_blob(vault_id: str, blob_id: str, caller: ActiveCaller, state: State) -> Response:
    """Whether the blob is stored: `200` with its `Content-Length`, or `404` with no body."""
    return await state.db.read(lambda: _head_blob(vault_id, blob_id, caller, state))


def _head_blob(vault_id: str, blob_id: str, caller: Caller, state: AppState) -> Response:
    require_member(state, caller, vault_id)
    row = state.db.one(
        "SELECT size FROM blobs WHERE vault_id = ? AND blob_id = ?", vault_id, _blob_id(blob_id)
    )
    if row is None:
        return Response(status_code=404)
    return Response(
        status_code=200,
        headers={"Content-Length": str(row["size"])},
        media_type="application/octet-stream",
    )


@router.get("/{blob_id}", response_class=OctetStream)
async def get_blob(vault_id: str, blob_id: str, caller: ActiveCaller, state: State) -> Response:
    """Download one encrypted chunk as raw bytes."""

    def find() -> sqlite3.Row:
        vault = require_member(state, caller, vault_id)
        if not state.db.one(
            "SELECT 1 FROM blobs WHERE vault_id = ? AND blob_id = ?", vault_id, _blob_id(blob_id)
        ):
            raise not_found("No such blob.")
        return vault

    vault = await state.db.read(find)
    try:
        data = await state.store.get(blob_key(vault["user_id"], vault_id, blob_id))
    except BlobNotFound as e:
        log.error("blob %s of vault %s is recorded but missing from the store", blob_id, vault_id)
        raise not_found("No such blob.") from e
    return Response(data, media_type="application/octet-stream")


@router.post("/missing")
async def missing_blobs(
    vault_id: str, body: MissingRequest, caller: ActiveCaller, state: State
) -> MissingResponse:
    """Of the blob ids sent, the ones the vault doesn't have yet, so a client uploads only
    what is missing."""
    return await state.db.read(lambda: _missing_blobs(vault_id, body, caller, state))


def _missing_blobs(
    vault_id: str, body: MissingRequest, caller: Caller, state: AppState
) -> MissingResponse:
    require_member(state, caller, vault_id)
    ids = [_blob_id(i) for i in body.ids]
    present: set[str] = set()
    if ids:
        marks = ",".join("?" * len(ids))
        rows = state.db.all(
            f"SELECT blob_id FROM blobs WHERE vault_id = ? AND blob_id IN ({marks})",  # noqa: S608
            vault_id,
            *ids,
        )
        present = {r[0] for r in rows}
    return MissingResponse(missing=list(dict.fromkeys(i for i in ids if i not in present)))


async def collect_garbage(state: AppState) -> int:
    """Delete blobs no revision references, once they are older than the grace period."""
    rows = await state.db.read(
        lambda: state.db.all(
            "SELECT b.vault_id, b.blob_id, v.user_id FROM blobs b "
            "JOIN vaults v ON v.id = b.vault_id "
            "WHERE b.created_at <= ? AND NOT EXISTS (SELECT 1 FROM revision_blobs r "
            "WHERE r.vault_id = b.vault_id AND r.blob_id = b.blob_id)",
            state.now() - GC_GRACE,
        )
    )

    def forget(row: sqlite3.Row) -> int:
        with state.db.transaction() as db:
            # Re-check: a commit may have referenced the blob since the query.
            gone = db.execute(
                "DELETE FROM blobs WHERE vault_id = ? AND blob_id = ? AND NOT EXISTS "
                "(SELECT 1 FROM revision_blobs r WHERE r.vault_id = ? AND r.blob_id = ?) "
                "RETURNING size",
                (row["vault_id"], row["blob_id"], row["vault_id"], row["blob_id"]),
            ).fetchall()
            if gone:
                db.execute(
                    "UPDATE vaults SET blob_bytes = MAX(blob_bytes - ?, 0) WHERE id = ?",
                    (gone[0][0], row["vault_id"]),
                )
            return len(gone)

    deleted = 0
    for row in rows:
        # The row goes first, so no commit can reference the blob any more. The lock keeps a
        # concurrent upload of the same blob from being deleted from the store.
        async with state.blob_lock(row["blob_id"]):
            if await state.db.run(lambda row=row: forget(row)):
                key = blob_key(row["user_id"], row["vault_id"], row["blob_id"])
                await state.store.delete(key)
                deleted += 1
    return deleted
