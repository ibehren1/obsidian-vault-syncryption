import threading

import pytest

from tests.helpers import SECRET, Device, file_id

CLIENT = "A" * 22
OTHER = "B" * 22


@pytest.fixture
def vault(alice) -> str:
    return alice.vault_id


@pytest.fixture
def phone(client, alice, vault) -> Device:
    phone = Device(client, "alice", name="Pixel")
    phone.join(alice)
    return phone


def lock(dev: Device, vault: str, client_id: str = CLIENT, fid: str | None = None, **body):
    return dev.post(
        f"/api/v1/vaults/{vault}/locks/{fid or file_id()}", json={"clientId": client_id, **body}
    )


def locks(dev: Device, vault: str) -> dict:
    return dev.get(f"/api/v1/vaults/{vault}/locks").json()


def test_acquire_renew_and_release(alice, phone, vault, clock):
    r = lock(alice, vault, ttl=60)
    assert r.status_code == 200
    held = r.json()
    assert held == {
        "fileId": file_id(),
        "device": alice.device_id,
        "clientId": CLIENT,
        "deviceName": "MacBook",
        "expiresAt": "2026-09-21T14:14:20Z",
    }
    listed = locks(phone, vault)
    assert listed["locks"] == [held]
    seq = listed["locksSeq"]

    clock.advance(30)
    renewed = lock(alice, vault, ttl=60).json()
    assert renewed["expiresAt"] == "2026-09-21T14:14:50Z"
    assert locks(phone, vault)["locksSeq"] == seq  # renewals don't count as changes

    r = phone.delete(f"/api/v1/vaults/{vault}/locks/{file_id()}?clientId={CLIENT}")
    assert r.status_code == 204
    assert locks(phone, vault)["locks"] == [renewed]  # only the holder can release

    r = alice.delete(f"/api/v1/vaults/{vault}/locks/{file_id()}?clientId={CLIENT}")
    assert r.status_code == 204
    after = locks(phone, vault)
    assert after == {"locks": [], "locksSeq": seq + 1}
    r = alice.delete(f"/api/v1/vaults/{vault}/locks/{file_id()}?clientId={CLIENT}")
    assert r.status_code == 204


def test_someone_else_holds_it(alice, phone, vault):
    lock(alice, vault)
    r = lock(phone, vault)
    assert r.status_code == 423
    body = r.json()
    assert body["error"] == "locked"
    assert body["details"]["lock"]["device"] == alice.device_id
    assert body["details"]["lock"]["deviceName"] == "MacBook"
    # Another installation of the same key is another holder.
    assert lock(alice, vault, OTHER).status_code == 423
    assert lock(alice, vault, fid=file_id(1)).status_code == 200


def test_expired_locks_are_free(alice, phone, vault, clock):
    lock(alice, vault, ttl=30)
    seq = locks(phone, vault)["locksSeq"]
    clock.advance(31)
    assert locks(phone, vault) == {"locks": [], "locksSeq": seq + 1}
    lock(alice, vault, ttl=30)
    clock.advance(31)
    r = lock(phone, vault)
    assert r.status_code == 200
    assert r.json()["device"] == phone.device_id


def test_bad_requests(alice, vault):
    assert lock(alice, vault, ttl=29).status_code == 400
    assert lock(alice, vault, ttl=301).status_code == 400
    assert lock(alice, vault, "short").status_code == 400
    r = alice.post(f"/api/v1/vaults/{vault}/locks/nope", json={"clientId": CLIENT})
    assert r.status_code == 400
    assert alice.delete(f"/api/v1/vaults/{vault}/locks/{file_id()}").status_code == 400


def test_outsiders_see_nothing(client, alice, vault):
    bob = Device(client, "bob")
    bob.login(SECRET)
    bob.create_vault()
    assert bob.get(f"/api/v1/vaults/{vault}/locks").status_code == 403
    assert lock(bob, vault).status_code == 403


def test_wait_wakes_on_lock_changes(alice, phone, vault):
    seq = locks(phone, vault)["locksSeq"]
    out = {}

    def waiter():
        out["body"] = phone.get(
            f"/api/v1/vaults/{vault}/wait?since=0&locksSince={seq}&timeout=10"
        ).json()

    t = threading.Thread(target=waiter)
    t.start()
    lock(alice, vault)
    t.join(5)
    assert not t.is_alive()
    assert out["body"]["changed"] is True
    assert out["body"]["locksSeq"] == seq + 1


def test_removing_a_device_releases_its_locks(alice, phone, vault):
    lock(phone, vault)
    seq = locks(alice, vault)["locksSeq"]
    assert alice.delete(f"/api/v1/vaults/{vault}/devices/{phone.device_id}").status_code == 200
    assert locks(alice, vault) == {"locks": [], "locksSeq": seq + 1}
