import secrets
import uuid

from syncryption_server.sshkeys import NAMESPACE_AUTH
from tests.helpers import SECRET, Device, sign_sshsig


def creator(client, vault_name: str = "A", username: str = "alice") -> Device:
    """A key that has registered to create `vault_name` and hasn't yet."""
    d = Device(client, username, vault_name=vault_name)
    d.login(SECRET)
    return d


def test_create_and_open(client):
    d = creator(client, "Personal")
    r = d.post("/api/v1/vaults/open", json={"name": "Personal"})
    assert (r.status_code, r.json()["error"]) == (404, "not_found")
    vault_id = d.create_vault()
    r = d.post("/api/v1/vaults/open", json={"name": " Personal "})
    assert r.status_code == 200
    body = r.json()
    assert (body["status"], body["membership"]) == ("active", "active")
    assert body["vault"] == {
        "id": vault_id,
        "name": "Personal",
        "keyringVersion": 1,
        "seq": 0,
        "createdAt": body["vault"]["createdAt"],
    }
    assert d.get("/api/v1/devices/self").json()["vaultId"] == vault_id


def test_open_only_the_devices_vault(client, alice):
    work = creator(client, "Work")
    work.create_vault()
    for name in ("Work", "personal", "Other"):
        r = alice.post("/api/v1/vaults/open", json={"name": name})
        assert (r.status_code, r.json()["error"]) == (403, "forbidden"), name


def test_names_are_per_user(client, alice):
    bob = creator(client, "Personal", "bob")
    bob.create_vault()
    r = bob.post("/api/v1/vaults/open", json={"name": "Personal"})
    assert r.json()["vault"]["id"] == bob.vault_id != alice.vault_id


def test_vault_names_are_nfc(client):
    d = creator(client, "Café")
    d.create_vault()
    r = d.post("/api/v1/vaults/open", json={"name": "Café"})
    assert r.status_code == 200
    assert r.json()["vault"]["name"] == "Café"


def test_create_validation(client):
    d = creator(client, "A")
    kr = d.keyring(1)
    cases = [
        ({"id": "not-a-uuid", "name": "A", "keyring": kr}, 400, "bad_request"),
        ({"id": str(uuid.uuid4()), "name": "", "keyring": kr}, 400, "bad_request"),
        ({"id": str(uuid.uuid4()), "name": "B", "keyring": kr}, 403, "forbidden"),
        (
            {"id": str(uuid.uuid4()), "name": "A", "keyring": d.keyring(2)},
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
        r = d.post("/api/v1/vaults", json=body)
        assert (r.status_code, r.json()["error"]) == (status, error), body


def test_a_vaults_device_cant_create_another(client, alice):
    body = {"id": str(uuid.uuid4()), "name": "Personal", "keyring": alice.keyring(1)}
    r = alice.post("/api/v1/vaults", json=body)
    assert (r.status_code, r.json()["error"]) == (409, "exists")


def test_vault_ids_are_unique(client, alice):
    d = creator(client, "Other")
    body = {"id": alice.vault_id, "name": "Other", "keyring": d.keyring(1)}
    r = d.post("/api/v1/vaults", json=body)
    assert (r.status_code, r.json()["error"]) == (409, "exists")


def test_keyring_signed_in_auth_namespace_is_rejected(client):
    d = creator(client)
    data = secrets.token_bytes(64)
    kr = {**d.keyring(1, data), "signature": sign_sshsig(d.seed, NAMESPACE_AUTH, data)}
    r = d.post("/api/v1/vaults", json={"id": str(uuid.uuid4()), "name": "A", "keyring": kr})
    assert r.json()["error"] == "bad_signature_format"


def test_keyring_signed_by_another_key_is_rejected(client):
    d = creator(client)
    other = Device(client, "alice")
    other.device_id = d.device_id
    r = d.post(
        "/api/v1/vaults", json={"id": str(uuid.uuid4()), "name": "A", "keyring": other.keyring(1)}
    )
    assert r.json()["error"] == "bad_signature_format"


def test_pairing_flow(client, alice):
    vault_id = alice.vault_id
    phone = Device(client, "alice", name="Pixel")
    phone.login()

    r = phone.post("/api/v1/vaults/open", json={"name": "Personal"})
    assert (r.json()["vault"]["id"], r.json()["status"]) == (vault_id, "pending")
    assert phone.get(f"/api/v1/vaults/{vault_id}/keyring").json()["error"] == "device_pending"

    listed = alice.get(f"/api/v1/vaults/{vault_id}/devices").json()["devices"]
    pending = [d for d in listed if d["status"] == "pending"]
    assert [d["id"] for d in pending] == [phone.device_id]
    assert pending[0]["pairingCode"]

    assert alice.put(f"/api/v1/vaults/{vault_id}/keyring", json=alice.keyring(2)).status_code == 201
    r = alice.post(f"/api/v1/vaults/{vault_id}/devices/{phone.device_id}/approve")
    assert r.status_code == 200 and r.json()["status"] == "active"

    assert phone.post("/api/v1/vaults/open", json={"name": "Personal"}).json()["status"] == (
        "active"
    )
    assert phone.get("/api/v1/devices/self").json()["status"] == "active"
    assert phone.get(f"/api/v1/vaults/{vault_id}/keyring").json()["version"] == 2


def test_other_users_cannot_see_a_vault(client, alice):
    bob = creator(client, "Personal", "bob")
    bob.create_vault()
    for path in ("keyring", "devices", "changes", "locks", "recovery"):
        r = bob.get(f"/api/v1/vaults/{alice.vault_id}/{path}")
        assert (r.status_code, r.json()["error"]) == (403, "forbidden"), path


def test_creating_key_has_no_vault_access(client, alice):
    d = creator(client, "Work")
    r = d.get(f"/api/v1/vaults/{alice.vault_id}/keyring")
    assert (r.status_code, r.json()["error"]) == (403, "forbidden")


def test_keyring_versions(client, alice):
    vault_id = alice.vault_id
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
    r = alice.put(
        f"/api/v1/vaults/{alice.vault_id}/keyring",
        json=alice.keyring(2, b"\0" * (1024 * 1024 + 1)),
    )
    assert (r.status_code, r.json()["error"]) == (413, "too_large")


def test_removed_device_loses_access(client, alice):
    vault_id = alice.vault_id
    phone = Device(client, "alice", name="Pixel")
    phone.join(alice)
    assert phone.get(f"/api/v1/vaults/{vault_id}/keyring").status_code == 200
    r = alice.delete(f"/api/v1/vaults/{vault_id}/devices/{phone.device_id}")
    assert r.status_code == 200
    assert phone.get(f"/api/v1/vaults/{vault_id}/keyring").status_code == 401
    r = alice.delete(f"/api/v1/vaults/{vault_id}/devices/{alice.device_id}")
    assert (r.status_code, r.json()["error"]) == (409, "exists")


def test_removed_endpoints_are_gone(client, alice):
    vault_id = alice.vault_id
    assert alice.get("/api/v1/vaults").status_code == 405
    assert alice.get("/api/v1/devices").status_code == 404
    assert alice.get(f"/api/v1/vaults/{vault_id}/members").status_code == 404
