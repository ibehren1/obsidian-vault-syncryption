"""Devices: one encryption key (an Ed25519 key) in one vault (docs/protocol.md 6).

A device's status is its membership of the vault: pending until a device of the vault
approves it, active, or revoked once removed. Revoked rows stay, so the key can't log in
or be registered again.
"""

import sqlite3

from fastapi import APIRouter
from pydantic import BaseModel, Field

from syncryption_server.auth import (
    REMOTE_ONLY_SESSION_TTL,
    ActiveCaller,
    AnyCaller,
    Caller,
    FullCaller,
    State,
    sweep_expired,
)
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
    remoteOnly: bool = Field(default=False, description="Approved as remote-only.")
    locked: bool = Field(
        default=False, description="A remote-only device locked by another device of the vault."
    )


class ApproveRequest(BaseModel):
    remoteOnly: bool = Field(
        default=False,
        description="Approve as remote-only: short sessions, no vault management "
        "(remote-only.md 4). Must match the policy in the keyring.",
    )


class PolicyRequest(BaseModel):
    remoteOnly: bool = Field(
        description="The device's new policy (remote-only.md 4). Must match the keyring."
    )


class LockRequest(BaseModel):
    locked: bool = Field(description="Lock or unlock a remote-only device (remote-only.md 5).")


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
        "remoteOnly": bool(row["remote_only"]),
        "locked": bool(row["locked"]),
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
    return await state.db.read(lambda: _self_device(caller, state))


def _self_device(caller: Caller, state: AppState) -> SelfDevice:
    row = state.db.one("SELECT * FROM devices WHERE id = ?", caller.device_id)
    return SelfDevice(
        **_fields(row),
        vaultId=row["vault_id"],
        vaultName=row["vault_name"],
        username=caller.username,
    )


@router.get("/vaults/{vault_id}/devices")
async def list_devices(vault_id: str, caller: ActiveCaller, state: State) -> DeviceList:
    return await state.db.run(lambda: _list_devices(vault_id, caller, state))


def _list_devices(vault_id: str, caller: Caller, state: AppState) -> DeviceList:
    require_member(state, caller, vault_id)
    sweep_expired(state)
    rows = state.db.all(
        "SELECT * FROM devices WHERE vault_id = ? ORDER BY created_at, rowid", vault_id
    )
    return DeviceList(devices=[device_model(r) for r in rows])


@router.post("/vaults/{vault_id}/devices/{device_id}/approve")
async def approve_device(
    vault_id: str,
    device_id: str,
    caller: FullCaller,
    state: State,
    body: ApproveRequest | None = None,
) -> Device:
    remote = body.remoteOnly if body else False
    return await state.db.run(lambda: _approve_device(vault_id, device_id, remote, caller, state))


def _approve_device(
    vault_id: str, device_id: str, remote: bool, caller: Caller, state: AppState
) -> Device:
    require_member(state, caller, vault_id)
    row = _vault_device(state, vault_id, device_id)
    if row["status"] == "revoked":
        raise bad_request("A removed device can't be approved.")
    with state.db.transaction() as db:
        approved = db.execute(
            "UPDATE devices SET status = 'active', remote_only = ? "
            "WHERE id = ? AND status = 'pending'",
            (int(remote), device_id),
        ).rowcount
        if approved and remote:
            # The sessions it has as a pending device get the remote-only lifetime.
            db.execute(
                "UPDATE sessions SET expires_at = MIN(expires_at, ?) WHERE device_id = ?",
                (state.now() + REMOTE_ONLY_SESSION_TTL, device_id),
            )
    return device_model(_vault_device(state, vault_id, device_id))


def _other_active(state: AppState, caller: Caller, vault_id: str, device_id: str) -> sqlite3.Row:
    require_member(state, caller, vault_id)
    row = _vault_device(state, vault_id, device_id)
    if row["status"] != "active":
        raise bad_request("Only an active device can be changed.")
    if device_id == caller.device_id:
        raise bad_request("A device can't change its own policy.")
    return row


def _release_locks(db: sqlite3.Connection, vault_id: str, device_id: str) -> None:
    released = db.execute(
        "DELETE FROM locks WHERE vault_id = ? AND device_id = ?", (vault_id, device_id)
    ).rowcount
    if released:
        db.execute("UPDATE vaults SET locks_seq = locks_seq + 1 WHERE id = ?", (vault_id,))


@router.put("/vaults/{vault_id}/devices/{device_id}/policy")
async def set_device_policy(
    vault_id: str, device_id: str, body: PolicyRequest, caller: FullCaller, state: State
) -> Device:
    """Make another active device remote-only, or a full device again (remote-only.md 4)."""

    def update() -> Device:
        _other_active(state, caller, vault_id, device_id)
        with state.db.transaction() as db:
            # A full device has no lock: making one full unlocks it.
            db.execute(
                "UPDATE devices SET remote_only = ?, locked = 0 WHERE id = ?",
                (int(body.remoteOnly), device_id),
            )
            if body.remoteOnly:
                db.execute(
                    "UPDATE sessions SET expires_at = MIN(expires_at, ?) WHERE device_id = ?",
                    (state.now() + REMOTE_ONLY_SESSION_TTL, device_id),
                )
        return device_model(_vault_device(state, vault_id, device_id))

    device = await state.db.run(update)
    await state.notifier.notify(vault_id)
    return device


@router.put("/vaults/{vault_id}/devices/{device_id}/lock")
async def set_device_locked(
    vault_id: str, device_id: str, body: LockRequest, caller: FullCaller, state: State
) -> Device:
    """Lock a remote-only device: its sessions end and it can't log in until unlocked."""

    def update() -> Device:
        row = _other_active(state, caller, vault_id, device_id)
        if not row["remote_only"]:
            raise bad_request("Only a remote-only device can be locked.")
        with state.db.transaction() as db:
            db.execute("UPDATE devices SET locked = ? WHERE id = ?", (int(body.locked), device_id))
            if body.locked:
                db.execute("DELETE FROM sessions WHERE device_id = ?", (device_id,))
                _release_locks(db, vault_id, device_id)
        return device_model(_vault_device(state, vault_id, device_id))

    device = await state.db.run(update)
    # The locked device's long-poll wakes and finds its session gone.
    await state.notifier.notify(vault_id)
    return device


@router.delete("/vaults/{vault_id}/devices/{device_id}")
async def remove_device(vault_id: str, device_id: str, caller: FullCaller, state: State) -> Device:
    """Revoke a device of the vault, the caller included (to replace its key)."""

    def revoke() -> Device:
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
            _release_locks(db, vault_id, device_id)
        return device_model(_vault_device(state, vault_id, device_id))

    device = await state.db.run(revoke)
    # Always: the removed device's long-poll wakes and finds its session gone (remote-only.md 5).
    await state.notifier.notify(vault_id)
    return device
