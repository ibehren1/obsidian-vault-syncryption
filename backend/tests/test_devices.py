from tests.helpers import SECRET, Device


def test_device_list_and_object(client, alice):
    phone = Device(client, "alice", name="Pixel")
    phone.login(SECRET)
    devices = alice.get("/api/v1/devices").json()["devices"]
    assert [d["name"] for d in devices] == ["MacBook", "Pixel"]
    me = devices[0]
    assert me["publicKey"] == alice.public_key_text
    assert me["fingerprint"].startswith("SHA256:")
    assert len(me["pairingCode"]) == 11 and me["pairingCode"][5] == "-"
    assert me["createdAt"].endswith("Z")


def test_users_are_separate(client, alice):
    bob = Device(client, "bob")
    bob.login(SECRET)
    assert [d["id"] for d in bob.get("/api/v1/devices").json()["devices"]] == [bob.device_id]
    assert bob.post(f"/api/v1/devices/{alice.device_id}/approve").status_code == 404
    assert bob.delete(f"/api/v1/devices/{alice.device_id}").status_code == 404


def test_same_key_under_two_usernames_is_two_devices(client, alice):
    other = Device(client, "work", seed=alice.seed)
    data = other.login(SECRET)
    assert data["status"] == "active"
    assert data["deviceId"] != alice.device_id


def test_last_active_device_cannot_be_revoked(client, alice):
    r = alice.delete(f"/api/v1/devices/{alice.device_id}")
    assert (r.status_code, r.json()["error"]) == (409, "exists")


def test_revoke_removes_memberships(client, alice):
    vault_id = alice.create_vault()
    phone = Device(client, "alice")
    phone.login(SECRET)
    phone.post("/api/v1/vaults/open", json={"name": "Personal"})
    alice.post(f"/api/v1/vaults/{vault_id}/members/{phone.device_id}/approve")
    assert len(alice.get(f"/api/v1/vaults/{vault_id}/members").json()["members"]) == 2

    r = alice.delete(f"/api/v1/devices/{phone.device_id}")
    assert r.json()["status"] == "revoked"
    assert len(alice.get(f"/api/v1/vaults/{vault_id}/members").json()["members"]) == 1
    assert alice.post(f"/api/v1/devices/{phone.device_id}/approve").status_code == 400
