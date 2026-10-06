"""Soft lease locks (docs/protocol.md 11). They warn other devices and never block a commit."""

import re
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel, Field

from syncryption_server.auth import ActiveCaller, Caller, State
from syncryption_server.encoding import FILE_ID_RE, rfc3339
from syncryption_server.errors import ApiError, bad_request
from syncryption_server.state import AppState
from syncryption_server.vaults import require_member

MIN_TTL = 30
MAX_TTL = 300
DEFAULT_TTL = 120
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")

router = APIRouter(prefix="/api/v1/vaults/{vault_id}/locks", tags=["locks"])


class Lock(BaseModel):
    fileId: str
    device: str
    clientId: str
    deviceName: str
    expiresAt: str


class Locks(BaseModel):
    locks: list[Lock]
    locksSeq: int


class AcquireRequest(BaseModel):
    clientId: str
    ttl: int = Field(default=DEFAULT_TTL, ge=MIN_TTL, le=MAX_TTL)


def _file_id(file_id: str) -> str:
    if not FILE_ID_RE.match(file_id):
        raise bad_request("File ids are 43 base64url characters.")
    return file_id


def _client_id(client_id: str) -> str:
    if not CLIENT_ID_RE.match(client_id):
        raise bad_request("Client ids are 22 base64url characters (16 bytes).")
    return client_id


async def _sweep(state: AppState, caller: Caller, vault_id: str) -> None:
    """Check membership and delete expired locks. Removing any counts as a lock change."""

    def sweep() -> int:
        require_member(state, caller, vault_id)
        with state.db.transaction() as db:
            gone = db.execute(
                "DELETE FROM locks WHERE vault_id = ? AND expires_at <= ?", (vault_id, state.now())
            ).rowcount
            if gone:
                db.execute("UPDATE vaults SET locks_seq = locks_seq + 1 WHERE id = ?", (vault_id,))
        return gone

    if await state.db.run(sweep):
        await state.notifier.notify(vault_id)


def _lock(state: AppState, vault_id: str, file_id: str) -> Lock:
    """The current lock on a file that is known to be locked."""
    row = state.db.one(
        "SELECT l.*, d.name AS device_name FROM locks l JOIN devices d ON d.id = l.device_id "
        "WHERE l.vault_id = ? AND l.file_id = ?",
        vault_id,
        file_id,
    )
    return _model(row)


def _model(row) -> Lock:
    return Lock(
        fileId=row["file_id"],
        device=row["device_id"],
        clientId=row["client_id"],
        deviceName=row["device_name"],
        expiresAt=rfc3339(row["expires_at"]),
    )


@router.get("")
async def list_locks(vault_id: str, caller: ActiveCaller, state: State) -> Locks:
    await _sweep(state, caller, vault_id)

    def read() -> Locks:
        rows = state.db.all(
            "SELECT l.*, d.name AS device_name FROM locks l JOIN devices d ON d.id = l.device_id "
            "WHERE l.vault_id = ? ORDER BY l.file_id",
            vault_id,
        )
        seq = state.db.one("SELECT locks_seq FROM vaults WHERE id = ?", vault_id)[0]
        return Locks(locks=[_model(r) for r in rows], locksSeq=seq)

    return await state.db.read(read)


@router.post("/{file_id}")
async def acquire(
    vault_id: str, file_id: str, body: AcquireRequest, caller: ActiveCaller, state: State
) -> Lock:
    await state.db.read(lambda: require_member(state, caller, vault_id))
    file_id = _file_id(file_id)
    client_id = _client_id(body.clientId)
    await _sweep(state, caller, vault_id)

    def take() -> tuple[sqlite3.Row | None, bool, Lock]:
        with state.db.transaction() as db:
            held = db.execute(
                "SELECT device_id, client_id FROM locks WHERE vault_id = ? AND file_id = ?",
                (vault_id, file_id),
            ).fetchone()
            mine = held is not None and (held[0], held[1]) == (caller.device_id, client_id)
            if held is None or mine:
                db.execute(
                    "INSERT INTO locks (vault_id, file_id, device_id, client_id, expires_at) "
                    "VALUES (?, ?, ?, ?, ?) ON CONFLICT (vault_id, file_id) "
                    "DO UPDATE SET expires_at = excluded.expires_at",
                    (vault_id, file_id, caller.device_id, client_id, state.now() + body.ttl),
                )
                if held is None:
                    # Renewals don't wake anyone: other devices already know the holder.
                    db.execute(
                        "UPDATE vaults SET locks_seq = locks_seq + 1 WHERE id = ?", (vault_id,)
                    )
        return held, mine, _lock(state, vault_id, file_id)

    held, mine, lock = await state.db.run(take)
    if held is not None and not mine:
        raise ApiError(
            423, "locked", f"{lock.deviceName} is editing this file.", {"lock": lock.model_dump()}
        )
    if held is None:
        await state.notifier.notify(vault_id)
    return lock


@router.delete("/{file_id}", status_code=204)
async def release(
    vault_id: str,
    file_id: str,
    caller: ActiveCaller,
    state: State,
    clientId: Annotated[str, Query()],
) -> Response:
    file_id = _file_id(file_id)
    client_id = _client_id(clientId)

    def drop() -> int:
        require_member(state, caller, vault_id)
        with state.db.transaction() as db:
            gone = db.execute(
                "DELETE FROM locks WHERE vault_id = ? AND file_id = ? AND device_id = ? "
                "AND client_id = ?",
                (vault_id, file_id, caller.device_id, client_id),
            ).rowcount
            if gone:
                db.execute("UPDATE vaults SET locks_seq = locks_seq + 1 WHERE id = ?", (vault_id,))
        return gone

    if await state.db.run(drop):
        await state.notifier.notify(vault_id)
    return Response(status_code=204)
