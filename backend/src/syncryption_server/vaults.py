"""Vaults and keyrings (docs/protocol.md 3 and 7).

A session belongs to one device, and a device to one vault, so every vault endpoint checks
that the vault is the caller's own (`require_member`).
"""

import sqlite3
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from syncryption_server.auth import ActiveCaller, AnyCaller, Caller, State, vault_name
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
    status: Literal["active", "pending"] = Field(description="The calling device's status.")
    membership: Literal["active", "pending"] = Field(description="The same as `status`.")


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


def vault_model(row: sqlite3.Row) -> Vault:
    return Vault(
        id=row["id"],
        name=row["name"],
        keyringVersion=row["keyring_version"],
        seq=row["seq"],
        createdAt=rfc3339(row["created_at"]),
    )


def _own_vault(state: AppState, caller: Caller, vault_id: str) -> sqlite3.Row:
    """The vault, if it is the caller's device's vault and enabled (pending or active)."""
    if caller.vault_id is None or caller.vault_id != vault_id:
        raise forbidden()
    row = state.db.one("SELECT * FROM vaults WHERE id = ?", vault_id)
    if row is None:
        raise forbidden()
    if row["disabled_at"] is not None:
        raise vault_disabled(state.settings.admin_contact)
    return row


def require_member(state: AppState, caller: Caller, vault_id: str) -> sqlite3.Row:
    """The vault, if the caller's device belongs to it and is active (protocol.md 3)."""
    row = _own_vault(state, caller, vault_id)
    if caller.status != "active":
        raise ApiError(403, "device_pending", "This device is waiting for approval.")
    return row


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
    """The caller's vault. 404 while the device still has to create it."""
    return await state.db.read(lambda: _open_vault(body, caller, state))


def _open_vault(body: OpenRequest, caller: Caller, state: AppState) -> OpenResponse:
    if vault_name(body.name) != caller.vault_name:
        raise forbidden("This device's key belongs to another vault.")
    if caller.vault_id is None:
        raise not_found("No vault with this name.")
    vault = _own_vault(state, caller, caller.vault_id)
    status = caller.status
    return OpenResponse(vault=vault_model(vault), status=status, membership=status)


@router.post("", status_code=201)
async def create_vault(body: CreateRequest, caller: ActiveCaller, state: State) -> Vault:
    return await state.db.run(lambda: _create_vault(body, caller, state))


def _create_vault(body: CreateRequest, caller: Caller, state: AppState) -> Vault:
    name = vault_name(body.name)
    if caller.vault_id is not None:
        raise ApiError(409, "exists", "This device's key already belongs to a vault.")
    if name != caller.vault_name:
        raise forbidden("This device's key was registered for another vault.")
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
            db.execute("UPDATE devices SET vault_id = ? WHERE id = ?", (body.id, caller.device_id))
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


@router.get("/{vault_id}/keyring")
async def get_keyring(
    vault_id: str,
    caller: ActiveCaller,
    state: State,
    version: Annotated[int | None, Query(ge=1)] = None,
) -> Keyring:
    return await state.db.read(lambda: _get_keyring(vault_id, caller, state, version))


def _get_keyring(vault_id: str, caller: Caller, state: AppState, version: int | None) -> Keyring:
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
    def store() -> None:
        require_member(state, caller, vault_id)
        data = _check_keyring(caller, body)
        with state.db.transaction() as db:
            _insert_next_keyring(db, state, vault_id, caller, body, data, by_recovery=False)

    await state.db.run(store)
    await state.notifier.notify(vault_id)
    return await state.db.read(lambda: _keyring_model(_keyring_row(state, vault_id, body.version)))


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
    _own_vault(state, caller, vault_id)


def _no_recovery() -> ApiError:
    return ApiError(404, "no_recovery", "This vault has no recovery key.")


@router.get("/{vault_id}/recovery")
async def get_recovery_keyring(vault_id: str, caller: AnyCaller, state: State) -> Keyring:
    """The current keyring, for a device that recovers the vault (crypto.md 9)."""
    return await state.db.read(lambda: _get_recovery_keyring(vault_id, caller, state))


def _get_recovery_keyring(vault_id: str, caller: Caller, state: AppState) -> Keyring:
    _require_membership(state, caller, vault_id)
    row = _current_keyring(state.db.conn, vault_id)
    if row["recovery_signer"] is None:
        raise _no_recovery()
    return _keyring_model(row)


@router.post("/{vault_id}/recover", status_code=201)
async def recover(vault_id: str, body: KeyringUpload, caller: AnyCaller, state: State) -> Keyring:
    """Upload the next keyring signed by the recovery key, and become an active device."""
    await state.db.read(lambda: _require_membership(state, caller, vault_id))
    state.limiter.check(f"recover:{caller.device_id}", *RECOVER_LIMIT)

    # One unit: the recovery signer checked is the one of the version the insert follows.
    def store() -> None:
        _require_membership(state, caller, vault_id)
        current = _current_keyring(state.db.conn, vault_id)
        if current["recovery_signer"] is None:
            raise _no_recovery()
        data = _check_keyring(caller, body, signed_by=current["recovery_signer"])
        if body.recoverySigner != current["recovery_signer"]:
            # crypto.md 6.4: only a device can change the recovery key.
            raise bad_request("A recovery upload must keep the recovery key.")
        with state.db.transaction() as db:
            # Checked against `current`: a newer version (maybe another recovery key) fails.
            _insert_next_keyring(db, state, vault_id, caller, body, data, by_recovery=True)
            db.execute(
                "UPDATE devices SET status = 'active' WHERE id = ? AND status = 'pending'",
                (caller.device_id,),
            )

    await state.db.run(store)
    await state.notifier.notify(vault_id)
    return await state.db.read(lambda: _keyring_model(_keyring_row(state, vault_id, body.version)))
