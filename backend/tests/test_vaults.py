import secrets
import uuid

from syncryption_server.sshkeys import NAMESPACE_AUTH
from tests.helpers import SECRET, Device, sign_sshsig


def pending_phone(client) -> Device:
    phone = Device(client, "alice", name="Pixel")
    phone.login(SECRET)
    return phone


def test_create_and_open(client, alice):
    r = alice.post("/api/v1/vaults/open", json={"name": "Personal"})
    assert (r.status_code, r.json()["error"]) == (404, "not_found")
    vault_id = alice.create_vault()
    r = alice.post("/api/v1/vaults/open", json={"name": " Personal "})
    assert r.status_code == 200
    body = r.json()
    assert body["membership"] == "active"
    assert body["vault"] == {
        "id": vault_id,
        "name": "Personal",
        "keyringVersion": 1,
        "seq": 0,
        "createdAt": body["vault"]["createdAt"],
    }
    vaults = alice.get("/api/v1/vaults").json()["vaults"]
    assert [(v["vault"]["id"], v["membership"]) for v in vaults] == [(vault_id, "active")]


def test_names_are_unique_per_user(client, alice):
    alice.create_vault("Personal")
    r = alice.post(
        "/api/v1/vaults",
        json={"id": str(uuid.uuid4()), "name": "Personal", "keyring": alice.keyring(1)},
    )
    assert (r.status_code, r.json()["error"]) == (409, "exists")
    bob = Device(client, "bob")
    bob.login(SECRET)
    bob.create_vault("Personal")
    r = bob.post("/api/v1/vaults/open", json={"name": "Personal"})
    assert r.json()["membership"] == "active"


def test_vault_names_are_nfc(client, alice):
    alice.create_vault("Café")
    r = alice.post("/api/v1/vaults/open", json={"name": "Café"})
    assert r.status_code == 200


def test_create_validation(client, alice):
    kr = alice.keyring(1)
    cases = [
        ({"id": "not-a-uuid", "name": "A", "keyring": kr}, 400, "bad_request"),
        ({"id": str(uuid.uuid4()), "name": "", "keyring": kr}, 400, "bad_request"),
        (
            {"id": str(uuid.uuid4()), "name": "A", "keyring": alice.keyring(2)},
            409,
            "keyring_version",
        ),
        (
            {"id": str(uuid.uuid4()), "name": "A", "keyring": {**kr, "signer": "d_x"}},
            403,
            "forbidden",
        ),
        (
            {"id": str(uuid.uuid4()), "name": "A", "keyring": {**kr, "keyring": "AAAA"}},
            400,
            "bad_signature_format",
        ),
    ]
    for body, status, error in cases:
        r = alice.post("/api/v1/vaults", json=body)
        assert (r.status_code, r.json()["error"]) == (status, error), body


def test_keyring_signed_in_auth_namespace_is_rejected(client, alice):
    data = secrets.token_bytes(64)
    kr = {**alice.keyring(1, data), "signature": sign_sshsig(alice.seed, NAMESPACE_AUTH, data)}
    r = alice.post("/api/v1/vaults", json={"id": str(uuid.uuid4()), "name": "A", "keyring": kr})
    assert r.json()["error"] == "bad_signature_format"


def test_keyring_signed_by_another_key_is_rejected(client, alice):
    other = Device(client, "alice")
    other.device_id = alice.device_id
    r = alice.post(
        "/api/v1/vaults", json={"id": str(uuid.uuid4()), "name": "A", "keyring": other.keyring(1)}
    )
    assert r.json()["error"] == "bad_signature_format"


def test_pairing_flow(client, alice):
    vault_id = alice.create_vault()
    phone = pending_phone(client)

    r = phone.post("/api/v1/vaults/open", json={"name": "Personal"})
    assert r.json()["membership"] == "pending"
    assert phone.get(f"/api/v1/vaults/{vault_id}/keyring").json()["error"] == "device_pending"

    members = alice.get(f"/api/v1/vaults/{vault_id}/members").json()["members"]
    pending = [m for m in members if m["status"] == "pending"]
    assert [m["device"]["id"] for m in pending] == [phone.device_id]
    assert pending[0]["device"]["pairingCode"]

    assert alice.put(f"/api/v1/vaults/{vault_id}/keyring", json=alice.keyring(2)).status_code == 201
    r = alice.post(f"/api/v1/vaults/{vault_id}/members/{phone.device_id}/approve")
    assert r.status_code == 200 and r.json()["status"] == "active"

    assert phone.post("/api/v1/vaults/open", json={"name": "Personal"}).json()["membership"] == (
        "active"
    )
    assert phone.get("/api/v1/devices/self").json()["status"] == "active"
    assert phone.get(f"/api/v1/vaults/{vault_id}/keyring").json()["version"] == 2


def test_known_key_opening_another_vault_needs_pairing(client, alice):
    alice.create_vault("Personal")
    laptop = Device(client, "alice")
    laptop.login(SECRET)
    alice.post(f"/api/v1/devices/{laptop.device_id}/approve")
    laptop.create_vault("Work")
    work = alice.post("/api/v1/vaults/open", json={"name": "Work"}).json()
    assert work["membership"] == "pending"
    r = alice.get(f"/api/v1/vaults/{work['vault']['id']}/keyring")
    assert (r.status_code, r.json()["error"]) == (403, "forbidden")


def test_other_users_cannot_see_a_vault(client, alice):
    vault_id = alice.create_vault()
    bob = Device(client, "bob")
    bob.login(SECRET)
    assert bob.post("/api/v1/vaults/open", json={"name": "Personal"}).status_code == 404
    for path in ("keyring", "members", "changes"):
        r = bob.get(f"/api/v1/vaults/{vault_id}/{path}")
        assert (r.status_code, r.json()["error"]) == (403, "forbidden")


def test_keyring_versions(client, alice):
    vault_id = alice.create_vault()
    first = alice.get(f"/api/v1/vaults/{vault_id}/keyring").json()
    assert first["version"] == 1 and first["signer"] == alice.device_id

    for bad in (1, 3):
        r = alice.put(f"/api/v1/vaults/{vault_id}/keyring", json=alice.keyring(bad))
        assert (r.status_code, r.json()["error"]) == (409, "keyring_version")
        assert r.json()["details"] == {"current": 1}

    data = secrets.token_bytes(500)
    r = alice.put(f"/api/v1/vaults/{vault_id}/keyring", json=alice.keyring(2, data))
    assert r.status_code == 201
    latest = alice.get(f"/api/v1/vaults/{vault_id}/keyring").json()
    assert latest["version"] == 2
    assert alice.get(f"/api/v1/vaults/{vault_id}/keyring?version=1").json() == first
    assert alice.get(f"/api/v1/vaults/{vault_id}/keyring?version=9").status_code == 404
    assert (
        alice.post("/api/v1/vaults/open", json={"name": "Personal"}).json()["vault"][
            "keyringVersion"
        ]
        == 2
    )


def test_keyring_size_limit(client, alice):
    vault_id = alice.create_vault()
    r = alice.put(
        f"/api/v1/vaults/{vault_id}/keyring", json=alice.keyring(2, b"\0" * (1024 * 1024 + 1))
    )
    assert (r.status_code, r.json()["error"]) == (413, "too_large")


def test_remove_member(client, alice):
    vault_id = alice.create_vault()
    phone = pending_phone(client)
    phone.post("/api/v1/vaults/open", json={"name": "Personal"})
    alice.post(f"/api/v1/vaults/{vault_id}/members/{phone.device_id}/approve")

    r = alice.delete(f"/api/v1/vaults/{vault_id}/members/{phone.device_id}")
    assert r.status_code == 204
    assert phone.get(f"/api/v1/vaults/{vault_id}/keyring").status_code == 403
    r = alice.delete(f"/api/v1/vaults/{vault_id}/members/{alice.device_id}")
    assert (r.status_code, r.json()["error"]) == (409, "exists")
    assert alice.delete(f"/api/v1/vaults/{vault_id}/members/{phone.device_id}").status_code == 404
