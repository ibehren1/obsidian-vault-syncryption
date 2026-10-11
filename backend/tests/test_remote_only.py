"""Remote-only devices (docs/remote-only.md 4 and 5)."""

import re
import threading
import time

from syncryption_server.auth import REMOTE_ONLY_GRACE, REMOTE_ONLY_SESSION_TTL, SESSION_TTL
from syncryption_server.encoding import rfc3339
from tests.helpers import ADMIN_TOKEN, Device

BEARER = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def approve(approver: Device, device: Device, remote: bool | None):
    path = f"/api/v1/vaults/{approver.vault_id}/devices/{device.device_id}/approve"
    if remote is None:
        return approver.post(path)
    return approver.post(path, json={"remoteOnly": remote})


def remote_phone(client, alice: Device) -> Device:
    phone = Device(client, "alice", name="Phone")
    assert phone.login()["status"] == "pending"
    r = approve(alice, phone, True)
    assert r.status_code == 200, r.text
    assert r.json()["remoteOnly"] is True
    return phone


def test_approve_without_a_body_is_a_full_device(client, alice):
    phone = Device(client, "alice", name="Phone")
    phone.login()
    r = approve(alice, phone, None)
    assert r.status_code == 200 and r.json()["remoteOnly"] is False
    data = phone.login()
    assert data["remoteOnly"] is False
    assert data["graceSeconds"] == REMOTE_ONLY_GRACE


def test_remote_only_sessions_are_short(client, clock, alice):
    phone = Device(client, "alice", name="Phone")
    pending = phone.login()
    assert pending["expiresAt"] == rfc3339(int(clock()) + SESSION_TTL)
    approve(alice, phone, True)
    # The pending session is cut to the remote-only lifetime.
    clock.advance(REMOTE_ONLY_SESSION_TTL + 1)
    assert phone.get("/api/v1/devices/self").status_code == 401
    data = phone.login()
    assert data["remoteOnly"] is True and data["graceSeconds"] == REMOTE_ONLY_GRACE
    assert data["expiresAt"] == rfc3339(int(clock()) + REMOTE_ONLY_SESSION_TTL)
    me = phone.get("/api/v1/devices/self").json()
    assert me["remoteOnly"] is True
    listed = alice.get(f"/api/v1/vaults/{alice.vault_id}/devices").json()["devices"]
    assert [d["remoteOnly"] for d in listed] == [False, True]


def test_remote_only_devices_cannot_manage_the_vault(client, alice):
    phone = remote_phone(client, alice)
    phone.login()
    tablet = Device(client, "alice", name="Tablet")
    tablet.login()
    base = f"/api/v1/vaults/{alice.vault_id}"
    for r in (
        approve(phone, tablet, False),
        phone.delete(f"{base}/devices/{tablet.device_id}"),
        phone.delete(f"{base}/devices/{alice.device_id}"),
        phone.delete(f"{base}/devices/{phone.device_id}"),
        phone.put(f"{base}/keyring", json=phone.keyring(2)),
    ):
        assert r.status_code == 403, r.text
        assert r.json()["error"] == "remote_only"
    # It still syncs: it reads the keyring.
    assert phone.get(f"{base}/keyring").status_code == 200
    # A full device can remove it.
    assert alice.delete(f"{base}/devices/{phone.device_id}").status_code == 200
    assert phone.login(expect=403)["error"] == "device_revoked"


def test_long_poll_ends_when_the_device_is_removed(client, alice):
    phone = remote_phone(client, alice)
    phone.login()
    out = {}

    def waiter():
        start = time.monotonic()
        out["r"] = phone.get(f"/api/v1/vaults/{alice.vault_id}/wait?since=0&timeout=10")
        out["took"] = time.monotonic() - start

    t = threading.Thread(target=waiter)
    t.start()
    time.sleep(0.2)
    assert (
        alice.delete(f"/api/v1/vaults/{alice.vault_id}/devices/{phone.device_id}").status_code
        == 200
    )
    t.join(5)
    assert out["took"] < 5
    assert out["r"].status_code in (401, 403)


def test_admin_sets_the_grace_period(client, alice):
    phone = remote_phone(client, alice)
    path = f"/admin/api/vaults/{alice.vault_id}/grace"
    assert client.post(path, json={"graceSeconds": 7200}).status_code == 401
    for bad in (60, 10**9):
        assert client.post(path, headers=BEARER, json={"graceSeconds": bad}).status_code == 400
    assert client.post(path, headers=BEARER, json={"graceSeconds": 7200}).status_code == 204
    assert phone.login()["graceSeconds"] == 7200
    users = client.get("/admin/api/users", headers=BEARER).json()["users"]
    vault = users[0]["vaults"][0]
    assert vault["remoteOnlyGrace"] == 7200
    assert [d["remoteOnly"] for d in vault["devices"]] == [False, True]
    page = client.get("/admin", headers=BEARER).text
    assert 'name="hours"' in page and 'value="2"' in page and "remote-only" in page
    assert client.post(path, headers=BEARER, json={"graceSeconds": None}).status_code == 204
    assert phone.login()["graceSeconds"] == REMOTE_ONLY_GRACE
    r = client.post("/admin/api/vaults/nope/grace", headers=BEARER, json={"graceSeconds": None})
    assert r.status_code == 404


def test_admin_grace_form(client, alice):
    r = client.post("/admin/login", data={"token": ADMIN_TOKEN}, follow_redirects=False)
    cookie = {"cookie": r.headers["set-cookie"].split(";")[0]}
    page = client.get("/admin", headers=cookie).text

    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    path = f"/admin/vaults/{alice.vault_id}/grace"
    r = client.post(
        path, headers=cookie, data={"csrf": csrf, "hours": "48"}, follow_redirects=False
    )
    assert r.headers["location"] == "/admin?done=grace_set"
    assert alice.login()["graceSeconds"] == 48 * 3600
    for bad in ("0", "x", "-1"):
        r = client.post(
            path, headers=cookie, data={"csrf": csrf, "hours": bad}, follow_redirects=False
        )
        assert r.headers["location"] == "/admin?done=bad_grace"
    r = client.post(path, headers=cookie, data={"csrf": csrf, "hours": ""}, follow_redirects=False)
    assert r.headers["location"] == "/admin?done=grace_set"
    assert alice.login()["graceSeconds"] == REMOTE_ONLY_GRACE
    r = client.post(path, headers=cookie, data={"hours": "5"}, follow_redirects=False)
    assert r.headers["location"] == "/admin?done=csrf"


def test_a_full_device_changes_another_devices_policy(client, clock, alice):
    phone = Device(client, "alice", name="Phone")
    phone.login()
    approve(alice, phone, False)
    assert phone.login()["remoteOnly"] is False
    base = f"/api/v1/vaults/{alice.vault_id}/devices"
    r = alice.put(f"{base}/{phone.device_id}/policy", json={"remoteOnly": True})
    assert r.status_code == 200 and r.json()["remoteOnly"] is True
    # Its session is cut to the remote-only lifetime, and it can't manage the vault.
    clock.advance(REMOTE_ONLY_SESSION_TTL + 1)
    assert phone.get("/api/v1/devices/self").status_code == 401
    assert phone.login()["remoteOnly"] is True
    r = phone.put(f"{base}/{alice.device_id}/policy", json={"remoteOnly": True})
    assert r.json()["error"] == "remote_only"
    # Back to a full device.
    r = alice.put(f"{base}/{phone.device_id}/policy", json={"remoteOnly": False})
    assert r.status_code == 200 and r.json()["remoteOnly"] is False
    assert phone.login()["remoteOnly"] is False


def test_policy_changes_need_another_active_device(client, alice):
    base = f"/api/v1/vaults/{alice.vault_id}/devices"
    assert (
        alice.put(f"{base}/{alice.device_id}/policy", json={"remoteOnly": True}).status_code == 400
    )
    tablet = Device(client, "alice", name="Tablet")
    tablet.login()
    assert (
        alice.put(f"{base}/{tablet.device_id}/policy", json={"remoteOnly": True}).status_code == 400
    )
    assert alice.put(f"{base}/nope/policy", json={"remoteOnly": True}).status_code == 404


def test_locking_a_remote_only_device(client, clock, alice):
    phone = remote_phone(client, alice)
    phone.login()
    base = f"/api/v1/vaults/{alice.vault_id}/devices"
    r = alice.put(f"{base}/{phone.device_id}/lock", json={"locked": True})
    assert r.status_code == 200 and r.json()["locked"] is True
    # Its session ends and it can't log in.
    assert phone.get("/api/v1/devices/self").status_code == 401
    assert phone.login(expect=403)["error"] == "device_locked"
    listed = alice.get(base).json()["devices"]
    assert [d["locked"] for d in listed] == [False, True]
    clock.advance(61)  # the login rate limit
    r = alice.put(f"{base}/{phone.device_id}/lock", json={"locked": False})
    assert r.status_code == 200 and r.json()["locked"] is False
    assert phone.login()["status"] == "active"
    # Locked again, then made a full device: that unlocks it.
    alice.put(f"{base}/{phone.device_id}/lock", json={"locked": True})
    r = alice.put(f"{base}/{phone.device_id}/policy", json={"remoteOnly": False})
    assert r.json()["locked"] is False
    assert phone.login()["remoteOnly"] is False


def test_only_remote_only_devices_lock(client, alice):
    phone = Device(client, "alice", name="Phone")
    phone.login()
    approve(alice, phone, False)
    phone.login()
    base = f"/api/v1/vaults/{alice.vault_id}/devices"
    r = alice.put(f"{base}/{phone.device_id}/lock", json={"locked": True})
    assert r.status_code == 400
    r = phone.put(f"{base}/{alice.device_id}/lock", json={"locked": True})
    assert r.status_code == 400
