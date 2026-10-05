"""File revisions, the change feed and long-poll (docs/protocol.md 9 and 10)."""

import sqlite3
from collections import defaultdict
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from syncryption_server.auth import ActiveCaller, State
from syncryption_server.encoding import BLOB_ID_RE, FILE_ID_RE, b64u, from_b64u, rfc3339
from syncryption_server.errors import ApiError, bad_request, not_found, too_large
from syncryption_server.state import AppState
from syncryption_server.vaults import require_member

MAX_META_SIZE = 64 * 1024
MAX_BLOBS_PER_REVISION = 10_000
MAX_WAIT = 25

router = APIRouter(prefix="/api/v1/vaults/{vault_id}", tags=["sync"])


class Revision(BaseModel):
    fileId: str
    rev: int
    parentRev: int | None
    deleted: bool
    meta: str
    blobs: list[str]
    size: int
    device: str
    createdAt: str


class CommitRequest(BaseModel):
    parentRev: int | None
    deleted: bool = False
    meta: str = Field(max_length=2 * MAX_META_SIZE)
    blobs: list[str] = Field(default_factory=list, max_length=MAX_BLOBS_PER_REVISION)


class History(BaseModel):
    revisions: list[Revision]
    more: bool


class Changes(BaseModel):
    changes: list[Revision]
    cursor: int
    more: bool
    # The vault's current keyring version, so clients notice a new one (crypto.md 8.4).
    keyringVersion: int


class WaitResponse(BaseModel):
    seq: int
    locksSeq: int
    keyringVersion: int
    changed: bool


def _file_id(file_id: str) -> str:
    if not FILE_ID_RE.match(file_id):
        raise bad_request("File ids are 43 base64url characters.")
    return file_id


def _revisions(state: AppState, rows: list[sqlite3.Row]) -> list[Revision]:
    """Revision objects for rows of one vault, with their blob lists."""
    if not rows:
        return []
    vault_id = rows[0]["vault_id"]
    revs = [r["rev"] for r in rows]
    blobs: dict[int, list[str]] = defaultdict(list)
    for b in state.db.all(
        "SELECT rev, blob_id FROM revision_blobs WHERE vault_id = ? AND rev BETWEEN ? AND ? "
        "ORDER BY rev, idx",
        vault_id,
        min(revs),
        max(revs),
    ):
        blobs[b["rev"]].append(b["blob_id"])
    return [
        Revision(
            fileId=r["file_id"],
            rev=r["rev"],
            parentRev=r["parent_rev"],
            deleted=bool(r["deleted"]),
            meta=b64u(r["meta"]),
            blobs=blobs.get(r["rev"], []),
            size=r["size"],
            device=r["device_id"],
            createdAt=rfc3339(r["created_at"]),
        )
        for r in rows
    ]


def _revision(state: AppState, vault_id: str, rev: int) -> Revision:
    row = state.db.one("SELECT * FROM revisions WHERE vault_id = ? AND rev = ?", vault_id, rev)
    return _revisions(state, [row])[0]


@router.put("/files/{file_id}", status_code=201)
async def commit(
    vault_id: str, file_id: str, body: CommitRequest, caller: ActiveCaller, state: State
) -> Revision:
    require_member(state, caller, vault_id)
    _file_id(file_id)
    try:
        meta = from_b64u(body.meta)
    except ValueError as e:
        raise bad_request("meta must be base64url.") from e
    if len(meta) > MAX_META_SIZE:
        raise too_large("Encrypted metadata is at most 64 KiB.")
    if not meta:
        raise bad_request("meta must not be empty.")
    if any(not BLOB_ID_RE.match(b) for b in body.blobs):
        raise bad_request("Blob ids are 64 lowercase hex characters.")
    if body.deleted and body.blobs:
        raise bad_request("A deletion has no blobs.")

    stale = False
    with state.db.transaction() as db:
        head = db.execute(
            "SELECT head_rev FROM files WHERE vault_id = ? AND file_id = ?", (vault_id, file_id)
        ).fetchone()
        head_rev = head[0] if head else None
        if body.parentRev != head_rev:
            stale = True
        else:
            unique = list(dict.fromkeys(body.blobs))
            sizes: dict[str, int] = {}
            for i in range(0, len(unique), 500):
                part = unique[i : i + 500]
                sizes.update(
                    db.execute(
                        "SELECT blob_id, size FROM blobs WHERE vault_id = ? AND blob_id IN "  # noqa: S608
                        f"({','.join('?' * len(part))})",
                        (vault_id, *part),
                    ).fetchall()
                )
            missing = [b for b in unique if b not in sizes]
            if missing:
                raise ApiError(
                    422, "missing_blobs", "Upload the missing blobs first.", {"missing": missing}
                )
            rev = db.execute(
                "UPDATE vaults SET seq = seq + 1 WHERE id = ? RETURNING seq", (vault_id,)
            ).fetchone()[0]
            db.execute(
                "INSERT INTO revisions (vault_id, rev, file_id, parent_rev, deleted, meta, size, "
                "device_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    vault_id,
                    rev,
                    file_id,
                    body.parentRev,
                    int(body.deleted),
                    meta,
                    len(meta) + sum(sizes[b] for b in body.blobs),
                    caller.device_id,
                    state.now(),
                ),
            )
            db.executemany(
                "INSERT INTO revision_blobs (vault_id, rev, idx, blob_id) VALUES (?, ?, ?, ?)",
                [(vault_id, rev, i, b) for i, b in enumerate(body.blobs)],
            )
            db.execute(
                "INSERT INTO files (vault_id, file_id, head_rev) VALUES (?, ?, ?) "
                "ON CONFLICT (vault_id, file_id) DO UPDATE SET head_rev = excluded.head_rev",
                (vault_id, file_id, rev),
            )
    if stale:
        # The head comes along so the client can merge without another round trip.
        head_obj = _revision(state, vault_id, head_rev).model_dump() if head_rev else None
        raise ApiError(
            409,
            "stale_parent",
            "The file has changed since its parent revision.",
            {"head": head_obj},
        )
    await state.notifier.notify(vault_id)
    return _revision(state, vault_id, rev)


@router.get("/files/{file_id}")
async def head_revision(
    vault_id: str, file_id: str, caller: ActiveCaller, state: State
) -> Revision:
    require_member(state, caller, vault_id)
    row = state.db.one(
        "SELECT head_rev FROM files WHERE vault_id = ? AND file_id = ?", vault_id, _file_id(file_id)
    )
    if row is None:
        raise not_found("No such file.")
    return _revision(state, vault_id, row[0])


@router.get("/files/{file_id}/revs")
async def history(
    vault_id: str,
    file_id: str,
    caller: ActiveCaller,
    state: State,
    before: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> History:
    require_member(state, caller, vault_id)
    rows = state.db.all(
        "SELECT * FROM revisions WHERE vault_id = ? AND file_id = ? AND rev < ? "
        "ORDER BY rev DESC LIMIT ?",
        vault_id,
        _file_id(file_id),
        before if before is not None else 2**63 - 1,
        limit + 1,
    )
    return History(revisions=_revisions(state, rows[:limit]), more=len(rows) > limit)


@router.get("/files/{file_id}/revs/{rev}")
async def get_revision(
    vault_id: str, file_id: str, rev: int, caller: ActiveCaller, state: State
) -> Revision:
    require_member(state, caller, vault_id)
    row = state.db.one(
        "SELECT * FROM revisions WHERE vault_id = ? AND file_id = ? AND rev = ?",
        vault_id,
        _file_id(file_id),
        rev,
    )
    if row is None:
        raise not_found("No such revision.")
    return _revisions(state, [row])[0]


@router.get("/changes")
async def changes(
    vault_id: str,
    caller: ActiveCaller,
    state: State,
    since: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
) -> Changes:
    require_member(state, caller, vault_id)
    rows = state.db.all(
        "SELECT * FROM revisions WHERE vault_id = ? AND rev > ? ORDER BY rev LIMIT ?",
        vault_id,
        since,
        limit + 1,
    )
    page = rows[:limit]
    vault = state.db.one("SELECT keyring_version FROM vaults WHERE id = ?", vault_id)
    return Changes(
        changes=_revisions(state, page),
        cursor=page[-1]["rev"] if page else since,
        more=len(rows) > limit,
        keyringVersion=vault["keyring_version"],
    )


@router.get("/wait")
async def wait(
    vault_id: str,
    caller: ActiveCaller,
    state: State,
    since: Annotated[int, Query(ge=0)] = 0,
    locksSince: Annotated[int, Query(ge=0)] = 0,
    keyringSince: Annotated[int | None, Query(ge=0)] = None,
    timeout: Annotated[float, Query(ge=0, le=MAX_WAIT)] = MAX_WAIT,  # noqa: ASYNC109
) -> WaitResponse:
    require_member(state, caller, vault_id)

    def current() -> sqlite3.Row:
        return state.db.one(
            "SELECT seq, locks_seq, keyring_version FROM vaults WHERE id = ?", vault_id
        )

    def changed() -> bool:
        row = current()
        return (
            row["seq"] > since
            or row["locks_seq"] > locksSince
            or (keyringSince is not None and row["keyring_version"] > keyringSince)
        )

    moved = await state.notifier.wait(vault_id, caller.device_id, changed, timeout)
    row = current()
    return WaitResponse(
        seq=row["seq"],
        locksSeq=row["locks_seq"],
        keyringVersion=row["keyring_version"],
        changed=moved,
    )
