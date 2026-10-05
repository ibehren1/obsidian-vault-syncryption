"""Devices: one registered Ed25519 key of a user (docs/protocol.md 6)."""

import sqlite3

from fastapi import APIRouter
from pydantic import BaseModel

from syncryption_server.auth import ActiveCaller, AnyCaller, State, sweep_expired
from syncryption_server.encoding import rfc3339
from syncryption_server.errors import ApiError, bad_request, not_found
from syncryption_server.sshkeys import fingerprint, pairing_code, parse_public_key
from syncryption_server.state import AppState

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


class Device(BaseModel):
    id: str
    name: str
    publicKey: str
    fingerprint: str
    pairingCode: str
    status: str
    createdAt: str
    lastSeenAt: str | None


class DeviceList(BaseModel):
    devices: list[Device]


def device_model(row: sqlite3.Row) -> Device:
    pk = parse_public_key(row["public_key"])
    return Device(
        id=row["id"],
        name=row["name"],
        publicKey=row["public_key"],
        fingerprint=fingerprint(pk),
        pairingCode=pairing_code(pk),
        status=row["status"],
        createdAt=rfc3339(row["created_at"]),
        lastSeenAt=rfc3339(row["last_seen_at"]) if row["last_seen_at"] else None,
    )


def get_user_device(state: AppState, user_id: str, device_id: str) -> sqlite3.Row:
    row = state.db.one("SELECT * FROM devices WHERE id = ? AND user_id = ?", device_id, user_id)
    if row is None:
        raise not_found("No such device.")
    return row


def activate_device(db: sqlite3.Connection, device_id: str) -> None:
    db.execute(
        "UPDATE devices SET status = 'active' WHERE id = ? AND status = 'pending'", (device_id,)
    )


@router.get("")
async def list_devices(caller: ActiveCaller, state: State) -> DeviceList:
    sweep_expired(state)
    rows = state.db.all(
        "SELECT * FROM devices WHERE user_id = ? ORDER BY created_at, rowid", caller.user_id
    )
    return DeviceList(devices=[device_model(r) for r in rows])


@router.get("/self")
async def self_device(caller: AnyCaller, state: State) -> Device:
    return device_model(get_user_device(state, caller.user_id, caller.device_id))


@router.post("/{device_id}/approve")
async def approve_device(device_id: str, caller: ActiveCaller, state: State) -> Device:
    row = get_user_device(state, caller.user_id, device_id)
    if row["status"] == "revoked":
        raise bad_request("A revoked device can't be approved.")
    with state.db.transaction() as db:
        activate_device(db, device_id)
    return device_model(get_user_device(state, caller.user_id, device_id))


@router.delete("/{device_id}")
async def revoke_device(device_id: str, caller: ActiveCaller, state: State) -> Device:
    row = get_user_device(state, caller.user_id, device_id)
    with state.db.transaction() as db:
        others = db.execute(
            "SELECT COUNT(*) FROM devices WHERE user_id = ? AND status = 'active' AND id != ?",
            (caller.user_id, device_id),
        ).fetchone()[0]
        if row["status"] == "active" and others == 0:
            raise ApiError(409, "exists", "The last active device can't be revoked.")
        lock_vaults = [
            r[0]
            for r in db.execute(
                "SELECT DISTINCT vault_id FROM locks WHERE device_id = ?", (device_id,)
            )
        ]
        db.execute("UPDATE devices SET status = 'revoked' WHERE id = ?", (device_id,))
        db.execute("DELETE FROM memberships WHERE device_id = ?", (device_id,))
        db.execute("DELETE FROM sessions WHERE device_id = ?", (device_id,))
        db.execute("DELETE FROM locks WHERE device_id = ?", (device_id,))
        for vault_id in lock_vaults:
            db.execute("UPDATE vaults SET locks_seq = locks_seq + 1 WHERE id = ?", (vault_id,))
    for vault_id in lock_vaults:
        await state.notifier.notify(vault_id)
    return device_model(get_user_device(state, caller.user_id, device_id))
