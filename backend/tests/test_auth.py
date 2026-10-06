import uuid

import pytest

from syncryption_server.sshkeys import NAMESPACE_KEYRING
from tests.helpers import SECRET, Device, sign_sshsig


def verify(client, ch, seed, **extra):
    from syncryption_server.sshkeys import NAMESPACE_AUTH

    body = {
        "challengeId": ch["challengeId"],
        "signature": sign_sshsig(seed, NAMESPACE_AUTH, ch["message"].encode()),
        **extra,
    }
    return client.post("/api/v1/auth/verify", json=body)


def test_challenge_message_format(client):
    d = Device(client, "alice", vault_name=" Café ")  # normalised: NFC, trimmed
    ch = d.challenge()
    lines = ch["message"].split("\n")
    assert lines[0] == "syncryption-auth@v1"
    assert lines[1] == "origin: https://notes.example.com"
    assert lines[2] == "username: alice"
    assert lines[3] == "vault: Café"
    assert lines[4].startswith("key: SHA256:")
    assert lines[5].startswith("nonce: ")
    assert lines[6] == f"expires: {ch['expiresAt']}"
    assert lines[7] == ""


@pytest.mark.parametrize(
    "body",
    [
        {"username": "Alice", "vaultName": "V", "publicKey": "x"},
        {"username": "", "vaultName": "V", "publicKey": "x"},
        {"username": "a" * 33, "vaultName": "V", "publicKey": "x"},
        {"username": "alice", "vaultName": "V", "publicKey": "ssh-rsa AAAAB3NzaC1yc2E="},
        {"username": "alice", "vaultName": " ", "publicKey": "x"},
        {"username": "alice", "vaultName": "a\x00b", "publicKey": "x"},
        {"username": "alice", "vaultName": "v" * 65, "publicKey": "x"},
        {"username": "alice", "publicKey": "x"},
    ],
)
def test_challenge_rejects_bad_input(client, body):
    if body["publicKey"] == "x":
        body["publicKey"] = Device(client, "x").public_key_text
    r = client.post("/api/v1/auth/challenge", json=body)
    assert r.status_code == 400
    assert r.json()["error"] == "bad_request"


def test_first_key_of_new_vault_is_active_until_it_creates_the_vault(client):
    d = Device(client, "alice")
    data = d.login(SECRET)
    assert (data["status"], data["created"], data["vaultId"]) == ("active", True, None)
    assert data["deviceId"].startswith("d_") and len(data["deviceId"]) == 24
    me = d.get("/api/v1/devices/self").json()
    assert (me["status"], me["vaultId"], me["vaultName"], me["username"]) == (
        "active",
        None,
        "Personal",
        "alice",
    )
    vault = d.create_vault()

    again = d.login()
    assert (again["created"], again["deviceId"], again["vaultId"]) == (
        False,
        data["deviceId"],
        vault,
    )
    assert d.get("/api/v1/devices/self").json()["vaultId"] == vault


def test_creating_a_vault_needs_the_shared_secret(client):
    d = Device(client, "alice")
    for secret in (None, "wrong"):
        r = d.login(secret, expect=403)
        assert r["error"] == "join_required"
        assert "administrator" in r["message"]


def test_new_key_joins_an_existing_vault_pending_without_the_secret(client, alice):
    phone = Device(client, "alice", vault_name=" Personal ", name="Pixel")
    data = phone.login()
    assert (data["status"], data["created"], data["vaultId"]) == ("pending", True, alice.vault_id)
    db = client.app.state.ctx.db
    assert db.one("SELECT COUNT(*) FROM join_attempts")[0] == 0
    assert phone.get("/api/v1/devices/self").json()["status"] == "pending"
    r = phone.get(f"/api/v1/vaults/{alice.vault_id}/devices")
    assert (r.status_code, r.json()["error"]) == (403, "device_pending")

    r = alice.post(f"/api/v1/vaults/{alice.vault_id}/devices/{phone.device_id}/approve")
    assert (r.status_code, r.json()["status"]) == (200, "active")
    # Same token, now active.
    assert phone.get(f"/api/v1/vaults/{alice.vault_id}/devices").status_code == 200
    assert phone.login()["status"] == "active"


def test_a_sent_secret_doesnt_matter_for_an_existing_vault(client, alice):
    assert Device(client, "alice").login("wrong")["status"] == "pending"
    assert Device(client, "alice").login(SECRET)["status"] == "pending"


def test_two_vaults_on_one_device_need_two_keys(client, alice):
    work = Device(client, "alice", vault_name="Work", name="MacBook")
    assert work.seed != alice.seed
    assert work.login(SECRET)["status"] == "active"
    work_id = work.create_vault()
    assert work_id != alice.vault_id
    # Each key sees only its own vault.
    assert work.get(f"/api/v1/vaults/{alice.vault_id}/keyring").status_code == 403
    assert alice.get(f"/api/v1/vaults/{work_id}/keyring").status_code == 403


def test_a_key_can_join_only_one_vault(client, alice):
    for other in (
        Device(client, "alice", vault_name="Work", seed=alice.seed),
        Device(client, "bob", seed=alice.seed),
        Device(client, "bob", vault_name="Work", seed=alice.seed),
    ):
        r = other.login(SECRET, expect=401)
        assert r["error"] == "challenge_invalid"
    db = client.app.state.ctx.db
    assert db.one("SELECT COUNT(*) FROM devices")[0] == 1
    assert db.one("SELECT COUNT(*) FROM users")[0] == 1
    assert alice.login()["deviceId"] == alice.device_id


def test_a_new_key_cant_create_an_existing_vault(client, alice):
    phone = Device(client, "alice", name="Pixel")
    assert phone.login(SECRET)["status"] == "pending"
    vault = {"id": str(uuid.uuid4()), "name": "Personal", "keyring": phone.keyring(1)}
    r = phone.post("/api/v1/vaults", json=vault)
    assert (r.status_code, r.json()["error"]) == (403, "device_pending")


def test_a_vault_being_created(client, clock):
    first = Device(client, "alice")
    first.login(SECRET)
    second = Device(client, "alice")
    for secret in (None, SECRET):
        r = second.login(secret, expect=409)
        assert r["error"] == "vault_being_created"
    # Another vault name of the same user is fine.
    assert Device(client, "alice", vault_name="Work").login(SECRET)["status"] == "active"

    first.create_vault()
    assert second.login()["status"] == "pending"


def test_a_vault_that_is_never_created_is_freed_after_a_day(client, clock):
    first = Device(client, "alice")
    first.login(SECRET)
    clock.advance(24 * 3600 + 1)
    second = Device(client, "alice")
    assert second.login(SECRET)["status"] == "active"
    # The first key is unknown again, and the second now creates the vault.
    assert first.login(SECRET, expect=409)["error"] == "vault_being_created"
    db = client.app.state.ctx.db
    assert db.one("SELECT COUNT(*) FROM devices")[0] == 1


def test_creating_key_must_create_its_own_vault(client):
    d = Device(client, "alice")
    d.login(SECRET)
    body = {"id": str(uuid.uuid4()), "name": "Other", "keyring": d.keyring(1)}
    r = d.post("/api/v1/vaults", json=body)
    assert (r.status_code, r.json()["error"]) == (403, "forbidden")
    d.create_vault()
    body = {"id": str(uuid.uuid4()), "name": "Personal", "keyring": d.keyring(1)}
    r = d.post("/api/v1/vaults", json=body)
    assert (r.status_code, r.json()["error"]) == (409, "exists")


def test_challenge_is_single_use(client, alice):
    ch = alice.challenge()
    assert verify(client, ch, alice.seed).status_code == 200
    r = verify(client, ch, alice.seed)
    assert (r.status_code, r.json()["error"]) == (401, "challenge_invalid")


def test_failed_verify_still_burns_the_challenge(client, alice):
    ch = alice.challenge()
    assert verify(client, ch, Device(client, "x").seed).status_code == 401
    assert verify(client, ch, alice.seed).status_code == 401


def test_challenge_expires(client, clock, alice):
    ch = alice.challenge()
    clock.advance(61)
    assert verify(client, ch, alice.seed).status_code == 401


def test_signature_in_keyring_namespace_is_rejected(client, alice):
    ch = alice.challenge()
    sig = sign_sshsig(alice.seed, NAMESPACE_KEYRING, ch["message"].encode())
    r = client.post(
        "/api/v1/auth/verify", json={"challengeId": ch["challengeId"], "signature": sig}
    )
    assert r.status_code == 401


def test_tokens_expire_after_an_hour(client, clock, alice):
    clock.advance(3601)
    r = alice.get("/api/v1/devices/self")
    assert (r.status_code, r.json()["error"]) == (401, "token_expired")
    alice.login()
    assert alice.get("/api/v1/devices/self").status_code == 200


def test_missing_or_unknown_token(client):
    assert client.get("/api/v1/devices/self").json()["error"] == "unauthenticated"
    r = client.get("/api/v1/devices/self", headers={"Authorization": "Bearer nope"})
    assert (r.status_code, r.json()["error"]) == (401, "unauthenticated")


def test_revoked_device_cannot_log_in(client, alice):
    phone = Device(client, "alice")
    phone.join(alice)
    r = alice.delete(f"/api/v1/vaults/{alice.vault_id}/devices/{phone.device_id}")
    assert r.status_code == 200
    assert phone.get("/api/v1/devices/self").status_code == 401  # sessions deleted
    for secret in (None, SECRET):
        assert phone.login(secret, expect=403)["error"] == "device_revoked"


def test_wrong_secrets_are_rate_limited(client, clock):
    for i in range(5):
        Device(client, f"user{i}").login("wrong", expect=403)
        clock.advance(30)  # stay under the per-minute auth limit
    r = Device(client, "late").login(SECRET, expect=429)
    assert r["error"] == "rate_limited"
    clock.advance(3600)
    Device(client, "late").login(SECRET)


def test_auth_is_rate_limited_per_ip(client):
    d = Device(client, "alice")
    for _ in range(10):
        d.client.post(
            "/api/v1/auth/challenge",
            json={"username": "alice", "vaultName": "V", "publicKey": d.public_key_text},
        )
    r = client.post(
        "/api/v1/auth/challenge",
        json={"username": "bob", "vaultName": "V", "publicKey": d.public_key_text},
    )
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1


def test_at_most_five_pending_devices_per_vault(client, clock, alice):
    for _ in range(5):
        Device(client, "alice").login()
        clock.advance(30)
    r = Device(client, "alice").login(expect=429)
    assert r["error"] == "rate_limited"
    # Another vault has its own limit.
    work = Device(client, "alice", vault_name="Work")
    work.login(SECRET)
    work.create_vault()
    clock.advance(60)
    assert Device(client, "alice", vault_name="Work").login()["status"] == "pending"


def test_pending_devices_expire_after_a_day(client, clock, alice):
    phone = Device(client, "alice")
    first = phone.login()["deviceId"]
    clock.advance(24 * 3600 + 1)
    alice.login()
    devices = alice.get(f"/api/v1/vaults/{alice.vault_id}/devices").json()["devices"]
    assert first not in [d["id"] for d in devices]
    again = phone.login()  # a new pending device
    assert (again["status"], again["created"]) == ("pending", True)
    assert again["deviceId"] != first


def test_secret_is_not_echoed_on_validation_errors(client):
    r = client.post(
        "/api/v1/auth/verify", json={"challengeId": 5, "signature": "x", "sharedSecret": SECRET}
    )
    assert r.status_code == 400
    assert SECRET not in r.text


def test_origin_from_proxy_headers(tmp_path, clock):
    from fastapi.testclient import TestClient

    from syncryption_server.app import create_app
    from syncryption_server.config import Settings

    settings = Settings(shared_secret=SECRET, behind_proxy=True, data_dir=tmp_path)
    with TestClient(create_app(settings, clock=clock)) as c:
        d = Device(c, "alice")
        r = c.post(
            "/api/v1/auth/challenge",
            json={"username": "alice", "vaultName": "V", "publicKey": d.public_key_text},
            headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "Sync.Example.org"},
        )
        assert "origin: https://sync.example.org\n" in r.json()["message"]


def test_joining_a_disabled_vault(client, alice):
    from tests.helpers import ADMIN_TOKEN

    bearer = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    r = client.post(f"/admin/api/vaults/{alice.vault_id}/disable", headers=bearer)
    assert r.status_code == 204
    phone = Device(client, "alice")
    for secret in (None, SECRET):
        assert phone.login(secret, expect=403)["error"] == "vault_disabled"
