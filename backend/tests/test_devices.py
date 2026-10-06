from tests.helpers import META, SECRET, Device, blob, file_id


def devices(d: Device, vault_id: str | None = None) -> list[dict]:
    r = d.get(f"/api/v1/vaults/{vault_id or d.vault_id}/devices")
    assert r.status_code == 200, r.text
    return r.json()["devices"]


def test_device_list_and_object(client, alice):
    phone = Device(client, "alice", name="Pixel")
    phone.login()
    listed = devices(alice)
    assert [(d["name"], d["status"]) for d in listed] == [
        ("MacBook", "active"),
        ("Pixel", "pending"),
    ]
    me = listed[0]
    assert me["id"] == alice.device_id
    assert me["publicKey"] == alice.public_key_text
    assert me["fingerprint"].startswith("SHA256:")
    assert len(me["pairingCode"]) == 11 and me["pairingCode"][5] == "-"
    assert me["createdAt"].endswith("Z") and me["lastSeenAt"].endswith("Z")


def test_self_device(client, alice):
    me = alice.get("/api/v1/devices/self").json()
    assert (me["id"], me["vaultId"], me["vaultName"], me["username"], me["status"]) == (
        alice.device_id,
        alice.vault_id,
        "Personal",
        "alice",
        "active",
    )


def test_vaults_are_separate(client, alice):
    work = Device(client, "alice", vault_name="Work")
    work.login(SECRET)
    work.create_vault()
    bob = Device(client, "bob")
    bob.login(SECRET)
    bob.create_vault()
    for other in (work, bob):
        assert [d["id"] for d in devices(other)] == [other.device_id]
        base = f"/api/v1/vaults/{alice.vault_id}/devices"
        assert other.get(base).status_code == 403
        assert other.post(f"{base}/{alice.device_id}/approve").status_code == 403
        assert other.delete(f"{base}/{alice.device_id}").status_code == 403
        # A device of another vault is unknown here.
        mine = f"/api/v1/vaults/{other.vault_id}/devices/{alice.device_id}"
        assert other.post(f"{mine}/approve").status_code == 404
        assert other.delete(mine).status_code == 404


def test_approve(client, alice):
    phone = Device(client, "alice", name="Pixel")
    phone.join(alice)
    assert [d["status"] for d in devices(alice)] == ["active", "active"]
    r = alice.post(f"/api/v1/vaults/{alice.vault_id}/devices/d_unknown/approve")
    assert r.status_code == 404


def test_remove_another_device(client, alice):
    phone = Device(client, "alice", name="Pixel")
    phone.join(alice)
    vault = alice.vault_id
    r = phone.post(f"/api/v1/vaults/{vault}/locks/{file_id()}", json={"clientId": "A" * 22})
    assert r.status_code == 200, r.text
    seq = alice.get(f"/api/v1/vaults/{vault}/locks").json()["locksSeq"]

    r = phone.delete(f"/api/v1/vaults/{vault}/devices/{alice.device_id}")  # any device can
    assert (r.status_code, r.json()["status"]) == (200, "revoked")
    assert alice.get("/api/v1/devices/self").status_code == 401  # sessions deleted
    r = alice.delete(f"/api/v1/vaults/{vault}/devices/{phone.device_id}")
    assert r.status_code == 401
    # Listed as revoked; the other device's lock stays.
    assert [(d["id"], d["status"]) for d in devices(phone)] == [
        (alice.device_id, "revoked"),
        (phone.device_id, "active"),
    ]
    assert phone.get(f"/api/v1/vaults/{vault}/locks").json()["locksSeq"] == seq
    r = phone.post(f"/api/v1/vaults/{vault}/devices/{alice.device_id}/approve")
    assert r.status_code == 400


def test_remove_releases_locks(client, alice):
    phone = Device(client, "alice", name="Pixel")
    phone.join(alice)
    vault = alice.vault_id
    r = phone.post(f"/api/v1/vaults/{vault}/locks/{file_id()}", json={"clientId": "A" * 22})
    assert r.status_code == 200, r.text
    seq = alice.get(f"/api/v1/vaults/{vault}/locks").json()["locksSeq"]
    assert alice.delete(f"/api/v1/vaults/{vault}/devices/{phone.device_id}").status_code == 200
    locks = alice.get(f"/api/v1/vaults/{vault}/locks").json()
    assert (locks["locks"], locks["locksSeq"]) == ([], seq + 1)


def test_remove_self_and_last_active(client, alice):
    vault = alice.vault_id
    r = alice.delete(f"/api/v1/vaults/{vault}/devices/{alice.device_id}")
    assert (r.status_code, r.json()["error"]) == (409, "exists")
    # A pending device doesn't count as active.
    pending = Device(client, "alice", name="Pending")
    pending.login()
    r = alice.delete(f"/api/v1/vaults/{vault}/devices/{alice.device_id}")
    assert r.status_code == 409
    # Rejecting a pending device is removing it.
    r = alice.delete(f"/api/v1/vaults/{vault}/devices/{pending.device_id}")
    assert (r.status_code, r.json()["status"]) == (200, "revoked")
    assert pending.login(expect=403)["error"] == "device_revoked"

    # With another active device, a device can remove itself (to replace its key).
    phone = Device(client, "alice", name="Pixel")
    phone.join(alice)
    r = alice.delete(f"/api/v1/vaults/{vault}/devices/{alice.device_id}")
    assert (r.status_code, r.json()["status"]) == (200, "revoked")
    assert alice.login(expect=403)["error"] == "device_revoked"
    r = phone.delete(f"/api/v1/vaults/{vault}/devices/{phone.device_id}")
    assert r.status_code == 409


def test_removed_device_keeps_its_history(client, alice):
    phone = Device(client, "alice", name="Pixel")
    phone.join(alice)
    vault = alice.vault_id
    blob_id, data = blob(b"x")
    assert phone.put(f"/api/v1/vaults/{vault}/blobs/{blob_id}", content=data).status_code == 201
    body = {"parentRev": None, "deleted": False, "meta": META, "blobs": [blob_id]}
    assert phone.put(f"/api/v1/vaults/{vault}/files/{file_id()}", json=body).status_code == 201
    assert alice.delete(f"/api/v1/vaults/{vault}/devices/{phone.device_id}").status_code == 200
    changes = alice.get(f"/api/v1/vaults/{vault}/changes").json()["changes"]
    assert [c["device"] for c in changes] == [phone.device_id]
