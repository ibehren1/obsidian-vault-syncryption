"""Vaults, membership and keyrings (docs/protocol.md 3 and 7)."""

import sqlite3
import unicodedata
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel, Field

from syncryption_server.auth import ActiveCaller, AnyCaller, Caller, State
from syncryption_server.devices import Device, activate_device, device_model
from syncryption_server.encoding import b64u, from_b64u, is_uuid4, rfc3339
from syncryption_server.errors import (
    ApiError,
    bad_request,
    forbidden,
    not_found,
    too_large,
    vault_disabled,
)
from syncryption_server.sshkeys import (
    NAMESPACE_KEYRING,
    KeyFormatError,
    SshSigError,
    parse_public_key,
    public_key_text,
    verify_sshsig,
)
from syncryption_server.state import AppState

MAX_KEYRING_SIZE = 1024 * 1024
RECOVER_LIMIT = (10, 60.0)  # recovery uploads per device

router = APIRouter(prefix="/api/v1/vaults", tags=["vaults"])


class Vault(BaseModel):
    id: str
    name: str
    keyringVersion: int
    seq: int
    createdAt: str


class OpenRequest(BaseModel):
    name: str = Field(max_length=256)


class OpenResponse(BaseModel):
    vault: Vault
    membership: Literal["active", "pending"]


class VaultEntry(BaseModel):
    vault: Vault
    membership: Literal["active", "pending"] | None


class VaultList(BaseModel):
    vaults: list[VaultEntry]


class KeyringUpload(BaseModel):
    version: int = Field(ge=1)
    keyring: str = Field(max_length=2 * MAX_KEYRING_SIZE)
    signature: str = Field(max_length=4096)
    signer: str
    # A copy of the keyring's `recoverySigner`, so the server can check recovery uploads.
    recoverySigner: str | None = Field(default=None, max_length=256)


class Keyring(KeyringUpload):
    byRecovery: bool
    createdAt: str


class CreateRequest(BaseModel):
    id: str
    name: str = Field(max_length=256)
    keyring: KeyringUpload


class Member(BaseModel):
    device: Device
    status: Literal["active", "pending"]
    createdAt: str


class MemberList(BaseModel):
    members: list[Member]


def vault_name(name: str) -> str:
    """NFC, trimmed, 1 to 64 characters, no control characters."""
    name = unicodedata.normalize("NFC", name).strip()
    if not 1 <= len(name) <= 64 or any(unicodedata.category(c).startswith("C") for c in name):
        raise bad_request("Vault names are 1 to 64 characters, without control characters.")
    return name


def vault_model(row: sqlite3.Row) -> Vault:
    return Vault(
        id=row["id"],
        name=row["name"],
        keyringVersion=row["keyring_version"],
        seq=row["seq"],
        createdAt=rfc3339(row["created_at"]),
    )


def require_member(state: AppState, caller: Caller, vault_id: str) -> sqlite3.Row:
    """The vault, if the caller's device is an active member of it (protocol.md 3)."""
    row = state.db.one(
        "SELECT v.* FROM vaults v JOIN memberships m ON m.vault_id = v.id "
        "WHERE v.id = ? AND m.device_id = ? AND m.status = 'active'",
        vault_id,
        caller.device_id,
    )
    if row is None:
        raise forbidden()
    if row["disabled_at"] is not None:
        raise vault_disabled(state.settings.admin_contact)
    return row


def _membership(state: AppState, vault_id: str, device_id: str) -> sqlite3.Row | None:
    return state.db.one(
        "SELECT * FROM memberships WHERE vault_id = ? AND device_id = ?", vault_id, device_id
    )


def _check_keyring(caller: Caller, upload: KeyringUpload, signed_by: str | None = None) -> bytes:
    """Defence in depth (crypto.md 6.3): signed in the keyring namespace by the caller, or
    by `signed_by` (a recovery signer) when given."""
    try:
        data = from_b64u(upload.keyring)
    except ValueError as e:
        raise bad_request("keyring must be base64url.") from e
    if len(data) > MAX_KEYRING_SIZE:
        raise too_large("The keyring is larger than 1 MiB.")
    if upload.signer != caller.device_id:
        raise forbidden("The keyring must be uploaded by the device named as signer.")
    if upload.recoverySigner is not None:
        try:
            upload.recoverySigner = public_key_text(parse_public_key(upload.recoverySigner))
        except KeyFormatError as e:
            raise bad_request("recoverySigner must be an Ed25519 public key.") from e
    try:
        signer = verify_sshsig(upload.signature, NAMESPACE_KEYRING, data)
    except SshSigError as e:
        raise ApiError(400, "bad_signature_format", "The keyring signature is invalid.") from e
    expected = signed_by if signed_by is not None else caller.public_key
    if public_key_text(signer) != expected:
        raise ApiError(400, "bad_signature_format", "The keyring is not signed by this device.")
    return data


def _keyring_model(row: sqlite3.Row) -> Keyring:
    return Keyring(
        version=row["version"],
        keyring=b64u(row["keyring"]),
        signature=row["signature"],
        signer=row["signer"],
        recoverySigner=row["recovery_signer"],
        byRecovery=bool(row["by_recovery"]),
        createdAt=rfc3339(row["created_at"]),
    )


@router.post("/open")
async def open_vault(body: OpenRequest, caller: AnyCaller, state: State) -> OpenResponse:
    name = vault_name(body.name)
    vault = state.db.one(
        "SELECT * FROM vaults WHERE user_id = ? AND name = ?", caller.user_id, name
    )
    if vault is None:
        raise not_found("No vault with this name.")
    if vault["disabled_at"] is not None:
        raise vault_disabled(state.settings.admin_contact)
    with state.db.transaction() as db:
        db.execute(
            "INSERT OR IGNORE INTO memberships (vault_id, device_id, status, created_at) "
            "VALUES (?, ?, 'pending', ?)",
            (vault["id"], caller.device_id, state.now()),
        )
    membership = _membership(state, vault["id"], caller.device_id)
    return OpenResponse(vault=vault_model(vault), membership=membership["status"])


@router.get("")
async def list_vaults(caller: ActiveCaller, state: State) -> VaultList:
    rows = state.db.all(
        "SELECT v.*, m.status AS membership FROM vaults v LEFT JOIN memberships m "
        "ON m.vault_id = v.id AND m.device_id = ? WHERE v.user_id = ? ORDER BY v.name",
        caller.device_id,
        caller.user_id,
    )
    return VaultList(
        vaults=[VaultEntry(vault=vault_model(r), membership=r["membership"]) for r in rows]
    )


@router.post("", status_code=201)
async def create_vault(body: CreateRequest, caller: ActiveCaller, state: State) -> Vault:
    name = vault_name(body.name)
    if not is_uuid4(body.id):
        raise bad_request("The vault id must be a lowercase UUIDv4.")
    if body.keyring.version != 1:
        raise ApiError(
            409, "keyring_version", "A new vault starts at keyring version 1.", {"current": 0}
        )
    data = _check_keyring(caller, body.keyring)
    now = state.now()
    try:
        with state.db.transaction() as db:
            db.execute(
                "INSERT INTO vaults (id, user_id, name, keyring_version, created_at) "
                "VALUES (?, ?, ?, 1, ?)",
                (body.id, caller.user_id, name, now),
            )
            db.execute(
                "INSERT INTO memberships (vault_id, device_id, status, created_at) "
                "VALUES (?, ?, 'active', ?)",
                (body.id, caller.device_id, now),
            )
            db.execute(
                "INSERT INTO keyrings (vault_id, version, keyring, signature, signer, "
                "recovery_signer, created_at) VALUES (?, 1, ?, ?, ?, ?, ?)",
                (
                    body.id,
                    data,
                    body.keyring.signature,
                    caller.device_id,
                    body.keyring.recoverySigner,
                    now,
                ),
            )
    except sqlite3.IntegrityError as e:
        raise ApiError(409, "exists", "A vault with this name or id already exists.") from e
    return vault_model(state.db.one("SELECT * FROM vaults WHERE id = ?", body.id))


@router.get("/{vault_id}/members")
async def list_members(vault_id: str, caller: ActiveCaller, state: State) -> MemberList:
    require_member(state, caller, vault_id)
    rows = state.db.all(
        "SELECT d.*, m.status AS m_status, m.created_at AS m_created FROM memberships m "
        "JOIN devices d ON d.id = m.device_id WHERE m.vault_id = ? ORDER BY m.created_at, m.rowid",
        vault_id,
    )
    return MemberList(
        members=[
            Member(device=device_model(r), status=r["m_status"], createdAt=rfc3339(r["m_created"]))
            for r in rows
        ]
    )


@router.post("/{vault_id}/members/{device_id}/approve")
async def approve_member(
    vault_id: str, device_id: str, caller: ActiveCaller, state: State
) -> Member:
    require_member(state, caller, vault_id)
    if _membership(state, vault_id, device_id) is None:
        raise not_found("This device hasn't asked to join the vault.")
    with state.db.transaction() as db:
        db.execute(
            "UPDATE memberships SET status = 'active' WHERE vault_id = ? AND device_id = ?",
            (vault_id, device_id),
        )
        activate_device(db, device_id)
    row = state.db.one(
        "SELECT d.*, m.created_at AS m_created FROM memberships m JOIN devices d "
        "ON d.id = m.device_id WHERE m.vault_id = ? AND m.device_id = ?",
        vault_id,
        device_id,
    )
    return Member(device=device_model(row), status="active", createdAt=rfc3339(row["m_created"]))


@router.delete("/{vault_id}/members/{device_id}", status_code=204)
async def remove_member(
    vault_id: str, device_id: str, caller: ActiveCaller, state: State
) -> Response:
    require_member(state, caller, vault_id)
    membership = _membership(state, vault_id, device_id)
    if membership is None:
        raise not_found("This device is not a member of the vault.")
    with state.db.transaction() as db:
        others = db.execute(
            "SELECT COUNT(*) FROM memberships WHERE vault_id = ? AND status = 'active' "
            "AND device_id != ?",
            (vault_id, device_id),
        ).fetchone()[0]
        if membership["status"] == "active" and others == 0:
            raise ApiError(409, "exists", "The last active member can't be removed.")
        db.execute(
            "DELETE FROM memberships WHERE vault_id = ? AND device_id = ?", (vault_id, device_id)
        )
        released = db.execute(
            "DELETE FROM locks WHERE vault_id = ? AND device_id = ?", (vault_id, device_id)
        ).rowcount
        if released:
            db.execute("UPDATE vaults SET locks_seq = locks_seq + 1 WHERE id = ?", (vault_id,))
    if released:
        await state.notifier.notify(vault_id)
    return Response(status_code=204)


@router.get("/{vault_id}/keyring")
async def get_keyring(
    vault_id: str,
    caller: ActiveCaller,
    state: State,
    version: Annotated[int | None, Query(ge=1)] = None,
) -> Keyring:
    vault = require_member(state, caller, vault_id)
    row = state.db.one(
        "SELECT * FROM keyrings WHERE vault_id = ? AND version = ?",
        vault_id,
        version if version is not None else vault["keyring_version"],
    )
    if row is None:
        raise not_found("No keyring with this version.")
    return _keyring_model(row)


@router.put("/{vault_id}/keyring", status_code=201)
async def put_keyring(
    vault_id: str, body: KeyringUpload, caller: ActiveCaller, state: State
) -> Keyring:
    require_member(state, caller, vault_id)
    data = _check_keyring(caller, body)
    with state.db.transaction() as db:
        _insert_next_keyring(db, state, vault_id, caller, body, data, by_recovery=False)
    await state.notifier.notify(vault_id)
    return _keyring_model(_keyring_row(state, vault_id, body.version))


def _keyring_row(state: AppState, vault_id: str, version: int) -> sqlite3.Row:
    return state.db.one(
        "SELECT * FROM keyrings WHERE vault_id = ? AND version = ?", vault_id, version
    )


def _current_keyring(db: sqlite3.Connection, vault_id: str) -> sqlite3.Row:
    return db.execute(
        "SELECT k.* FROM keyrings k JOIN vaults v ON v.id = k.vault_id "
        "AND k.version = v.keyring_version WHERE v.id = ?",
        (vault_id,),
    ).fetchone()


def _insert_next_keyring(
    db: sqlite3.Connection,
    state: AppState,
    vault_id: str,
    caller: Caller,
    body: KeyringUpload,
    data: bytes,
    *,
    by_recovery: bool,
) -> None:
    current = db.execute("SELECT keyring_version FROM vaults WHERE id = ?", (vault_id,)).fetchone()[
        0
    ]
    if body.version != current + 1:
        raise ApiError(
            409,
            "keyring_version",
            "The keyring version must be the current version plus one.",
            {"current": current},
        )
    db.execute(
        "INSERT INTO keyrings (vault_id, version, keyring, signature, signer, recovery_signer, "
        "by_recovery, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            vault_id,
            body.version,
            data,
            body.signature,
            caller.device_id,
            body.recoverySigner,
            int(by_recovery),
            state.now(),
        ),
    )
    db.execute("UPDATE vaults SET keyring_version = ? WHERE id = ?", (body.version, vault_id))


def _require_membership(state: AppState, caller: Caller, vault_id: str) -> None:
    """Pending or active: the recovery endpoints serve devices that wait for approval."""
    if _membership(state, vault_id, caller.device_id) is None:
        raise forbidden()
    if state.db.one("SELECT disabled_at FROM vaults WHERE id = ?", vault_id)["disabled_at"]:
        raise vault_disabled(state.settings.admin_contact)


def _no_recovery() -> ApiError:
    return ApiError(404, "no_recovery", "This vault has no recovery key.")


@router.get("/{vault_id}/recovery")
async def get_recovery_keyring(vault_id: str, caller: AnyCaller, state: State) -> Keyring:
    """The current keyring, for a device that recovers the vault (crypto.md 9)."""
    _require_membership(state, caller, vault_id)
    row = _current_keyring(state.db.conn, vault_id)
    if row["recovery_signer"] is None:
        raise _no_recovery()
    return _keyring_model(row)


@router.post("/{vault_id}/recover", status_code=201)
async def recover(vault_id: str, body: KeyringUpload, caller: AnyCaller, state: State) -> Keyring:
    """Upload the next keyring signed by the recovery key, and become an active member."""
    _require_membership(state, caller, vault_id)
    state.limiter.check(f"recover:{caller.device_id}", *RECOVER_LIMIT)
    current = _current_keyring(state.db.conn, vault_id)
    if current["recovery_signer"] is None:
        raise _no_recovery()
    data = _check_keyring(caller, body, signed_by=current["recovery_signer"])
    if body.recoverySigner != current["recovery_signer"]:
        # crypto.md 6.4: only a device can change the recovery key.
        raise bad_request("A recovery upload must keep the recovery key.")
    with state.db.transaction() as db:
        # Checked against `current`: a newer version (maybe another recovery key) fails here.
        _insert_next_keyring(db, state, vault_id, caller, body, data, by_recovery=True)
        db.execute(
            "UPDATE memberships SET status = 'active' WHERE vault_id = ? AND device_id = ?",
            (vault_id, caller.device_id),
        )
        activate_device(db, caller.device_id)
    await state.notifier.notify(vault_id)
    return _keyring_model(_keyring_row(state, vault_id, body.version))
