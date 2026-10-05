"""Recovering a vault with its recovery key (docs/protocol.md 7.4, crypto.md 9)."""

import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from syncryption_server.sshkeys import public_key_text
from tests.helpers import SECRET, Device


def recovery_key() -> tuple[bytes, str]:
    seed = secrets.token_bytes(32)
    pk = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return seed, public_key_text(pk.public_bytes(Encoding.Raw, PublicFormat.Raw))


def vault_with_recovery(client, alice) -> tuple[str, bytes, str]:
    seed, signer = recovery_key()
    vault_id = alice.create_vault()
    r = alice.put(
        f"/api/v1/vaults/{vault_id}/keyring", json=alice.keyring(2, recovery_signer=signer)
    )
    assert r.status_code == 201, r.text
    assert r.json()["recoverySigner"] == signer
    assert r.json()["byRecovery"] is False
    return vault_id, seed, signer


def new_pending(client, vault_id: str) -> Device:
    phone = Device(client, "alice", name="New phone")
    phone.login(SECRET)
    assert phone.post("/api/v1/vaults/open", json={"name": "Personal"}).json()["vault"]["id"] == (
        vault_id
    )
    return phone


def test_recover_activates_the_device(client, alice):
    vault_id, seed, signer = vault_with_recovery(client, alice)
    phone = new_pending(client, vault_id)

    r = phone.get(f"/api/v1/vaults/{vault_id}/recovery")
    assert r.status_code == 200
    assert (r.json()["version"], r.json()["recoverySigner"]) == (2, signer)

    upload = phone.keyring(3, recovery_signer=signer, signing_seed=seed)
    r = phone.post(f"/api/v1/vaults/{vault_id}/recover", json=upload)
    assert r.status_code == 201, r.text
    assert r.json()["byRecovery"] is True
    assert r.json()["signer"] == phone.device_id

    assert phone.get("/api/v1/devices/self").json()["status"] == "active"
    assert phone.post("/api/v1/vaults/open", json={"name": "Personal"}).json()["membership"] == (
        "active"
    )
    latest = phone.get(f"/api/v1/vaults/{vault_id}/keyring").json()
    assert (latest["version"], latest["byRecovery"]) == (3, True)
    # Normal uploads go on from there, signed by the device again.
    r = phone.put(
        f"/api/v1/vaults/{vault_id}/keyring", json=phone.keyring(4, recovery_signer=signer)
    )
    assert r.status_code == 201


def test_recover_needs_the_recovery_signature(client, alice):
    vault_id, _, signer = vault_with_recovery(client, alice)
    phone = new_pending(client, vault_id)
    r = phone.post(
        f"/api/v1/vaults/{vault_id}/recover", json=phone.keyring(3, recovery_signer=signer)
    )
    assert (r.status_code, r.json()["error"]) == (400, "bad_signature_format")
    other, _ = recovery_key()
    r = phone.post(f"/api/v1/vaults/{vault_id}/recover", json=phone.keyring(3, signing_seed=other))
    assert (r.status_code, r.json()["error"]) == (400, "bad_signature_format")
    assert phone.get("/api/v1/devices/self").json()["status"] == "pending"


def test_recover_keeps_the_recovery_key(client, alice):
    vault_id, seed, _ = vault_with_recovery(client, alice)
    phone = new_pending(client, vault_id)
    _, other = recovery_key()
    for signer in (None, other):
        upload = phone.keyring(3, recovery_signer=signer, signing_seed=seed)
        r = phone.post(f"/api/v1/vaults/{vault_id}/recover", json=upload)
        assert (r.status_code, r.json()["error"]) == (400, "bad_request")
    assert phone.get("/api/v1/devices/self").json()["status"] == "pending"


def test_recover_checks_the_version(client, alice):
    vault_id, seed, signer = vault_with_recovery(client, alice)
    phone = new_pending(client, vault_id)
    for version in (2, 4):
        upload = phone.keyring(version, recovery_signer=signer, signing_seed=seed)
        r = phone.post(f"/api/v1/vaults/{vault_id}/recover", json=upload)
        assert (r.status_code, r.json()["error"]) == (409, "keyring_version")
        assert r.json()["details"] == {"current": 2}


def test_a_replaced_recovery_key_no_longer_works(client, alice):
    vault_id, old_seed, _ = vault_with_recovery(client, alice)
    _, new_signer = recovery_key()
    alice.put(
        f"/api/v1/vaults/{vault_id}/keyring", json=alice.keyring(3, recovery_signer=new_signer)
    )
    phone = new_pending(client, vault_id)
    r = phone.post(
        f"/api/v1/vaults/{vault_id}/recover", json=phone.keyring(4, signing_seed=old_seed)
    )
    assert (r.status_code, r.json()["error"]) == (400, "bad_signature_format")


def test_no_recovery_key(client, alice):
    vault_id = alice.create_vault()
    phone = new_pending(client, vault_id)
    for r in (
        phone.get(f"/api/v1/vaults/{vault_id}/recovery"),
        phone.post(f"/api/v1/vaults/{vault_id}/recover", json=phone.keyring(2)),
    ):
        assert (r.status_code, r.json()["error"]) == (404, "no_recovery")


def test_recovery_needs_a_membership(client, alice):
    vault_id, seed, signer = vault_with_recovery(client, alice)
    phone = Device(client, "alice", name="New phone")
    phone.login(SECRET)
    bob = Device(client, "bob")
    bob.login(SECRET)
    for who in (phone, bob):
        assert who.get(f"/api/v1/vaults/{vault_id}/recovery").json()["error"] == "forbidden"
        upload = who.keyring(3, recovery_signer=signer, signing_seed=seed)
        assert who.post(f"/api/v1/vaults/{vault_id}/recover", json=upload).status_code == 403


def test_recovery_signer_must_be_an_ed25519_key(client, alice):
    vault_id = alice.create_vault()
    r = alice.put(
        f"/api/v1/vaults/{vault_id}/keyring", json=alice.keyring(2, recovery_signer="ssh-rsa AAAA")
    )
    assert (r.status_code, r.json()["error"]) == (400, "bad_request")
