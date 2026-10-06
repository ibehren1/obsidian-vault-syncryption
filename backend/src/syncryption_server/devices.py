"""Devices: one encryption key (an Ed25519 key) in one vault (docs/protocol.md 6).

A device's status is its membership of the vault: pending until a device of the vault
approves it, active, or revoked once removed. Revoked rows stay, so the key can't log in
or be registered again.
"""

import sqlite3

from fastapi import APIRouter
from pydantic import BaseModel

from syncryption_server.auth import ActiveCaller, AnyCaller, State, sweep_expired
from syncryption_server.encoding import rfc3339
from syncryption_server.errors import ApiError, bad_request, not_found
from syncryption_server.sshkeys import fingerprint, pairing_code, parse_public_key
from syncryption_server.state import AppState
from syncryption_server.vaults import require_member

router = APIRouter(prefix="/api/v1", tags=["devices"])


class Device(BaseModel):
    id: str
    name: str
    publicKey: str
    fingerprint: str
    pairingCode: str
    status: str
    createdAt: str
    lastSeenAt: str | None


class SelfDevice(Device):
    vaultId: str | None
    vaultName: str
    username: str


class DeviceList(BaseModel):
    devices: list[Device]


def _fields(row: sqlite3.Row) -> dict:
    pk = parse_public_key(row["public_key"])
    return {
        "id": row["id"],
        "name": row["name"],
        "publicKey": row["public_key"],
        "fingerprint": fingerprint(pk),
        "pairingCode": pairing_code(pk),
        "status": row["status"],
        "createdAt": rfc3339(row["created_at"]),
        "lastSeenAt": rfc3339(row["last_seen_at"]) if row["last_seen_at"] else None,
    }


def device_model(row: sqlite3.Row) -> Device:
    return Device(**_fields(row))


def _vault_device(state: AppState, vault_id: str, device_id: str) -> sqlite3.Row:
    row = state.db.one("SELECT * FROM devices WHERE id = ? AND vault_id = ?", device_id, vault_id)
    if row is None:
        raise not_found("No such device in this vault.")
    return row


@router.get("/devices/self")
async def self_device(caller: AnyCaller, state: State) -> SelfDevice:
    row = state.db.one("SELECT * FROM devices WHERE id = ?", caller.device_id)
    return SelfDevice(
        **_fields(row),
        vaultId=row["vault_id"],
        vaultName=row["vault_name"],
        username=caller.username,
    )


@router.get("/vaults/{vault_id}/devices")
async def list_devices(vault_id: str, caller: ActiveCaller, state: State) -> DeviceList:
    require_member(state, caller, vault_id)
    sweep_expired(state)
    rows = state.db.all(
        "SELECT * FROM devices WHERE vault_id = ? ORDER BY created_at, rowid", vault_id
    )
    return DeviceList(devices=[device_model(r) for r in rows])


@router.post("/vaults/{vault_id}/devices/{device_id}/approve")
async def approve_device(
    vault_id: str, device_id: str, caller: ActiveCaller, state: State
) -> Device:
    require_member(state, caller, vault_id)
    row = _vault_device(state, vault_id, device_id)
    if row["status"] == "revoked":
        raise bad_request("A removed device can't be approved.")
    with state.db.transaction() as db:
        db.execute(
            "UPDATE devices SET status = 'active' WHERE id = ? AND status = 'pending'",
            (device_id,),
        )
    return device_model(_vault_device(state, vault_id, device_id))


@router.delete("/vaults/{vault_id}/devices/{device_id}")
async def remove_device(
    vault_id: str, device_id: str, caller: ActiveCaller, state: State
) -> Device:
    """Revoke a device of the vault, the caller included (to replace its key)."""
    require_member(state, caller, vault_id)
    row = _vault_device(state, vault_id, device_id)
    with state.db.transaction() as db:
        others = db.execute(
            "SELECT COUNT(*) FROM devices WHERE vault_id = ? AND status = 'active' AND id != ?",
            (vault_id, device_id),
        ).fetchone()[0]
        if row["status"] == "active" and others == 0:
            raise ApiError(409, "exists", "The last active device of a vault can't be removed.")
        db.execute("UPDATE devices SET status = 'revoked' WHERE id = ?", (device_id,))
        db.execute("DELETE FROM sessions WHERE device_id = ?", (device_id,))
        released = db.execute(
            "DELETE FROM locks WHERE vault_id = ? AND device_id = ?", (vault_id, device_id)
        ).rowcount
        if released:
            db.execute("UPDATE vaults SET locks_seq = locks_seq + 1 WHERE id = ?", (vault_id,))
    if released:
        await state.notifier.notify(vault_id)
    return device_model(_vault_device(state, vault_id, device_id))
