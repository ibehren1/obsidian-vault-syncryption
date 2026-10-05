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
    d = Device(client, "alice")
    ch = d.challenge()
    lines = ch["message"].split("\n")
    assert lines[0] == "syncryption-auth@v1"
    assert lines[1] == "origin: https://notes.example.com"
    assert lines[2] == "username: alice"
    assert lines[3].startswith("key: SHA256:")
    assert lines[4].startswith("nonce: ")
    assert lines[5] == f"expires: {ch['expiresAt']}"
    assert lines[6] == ""


@pytest.mark.parametrize(
    "body",
    [
        {"username": "Alice", "publicKey": "x"},
        {"username": "", "publicKey": "x"},
        {"username": "a" * 33, "publicKey": "x"},
        {"username": "alice", "publicKey": "ssh-rsa AAAAB3NzaC1yc2E="},
    ],
)
def test_challenge_rejects_bad_input(client, body):
    if body["publicKey"] == "x":
        body["publicKey"] = Device(client, "x").public_key_text
    r = client.post("/api/v1/auth/challenge", json=body)
    assert r.status_code == 400
    assert r.json()["error"] == "bad_request"


def test_first_key_of_new_user_joins_active(client):
    d = Device(client, "alice")
    data = d.login(SECRET)
    assert data["status"] == "active"
    assert data["created"] is True
    assert data["deviceId"].startswith("d_") and len(data["deviceId"]) == 24
    assert d.get("/api/v1/devices/self").json()["status"] == "active"

    again = d.login()
    assert again["created"] is False
    assert again["deviceId"] == data["deviceId"]


def test_join_needs_the_shared_secret(client):
    d = Device(client, "alice")
    for secret in (None, "wrong"):
        r = d.login(secret, expect=403)
        assert r["error"] == "join_required"
        assert "administrator" in r["message"]


def test_new_key_for_existing_user_is_pending(client, alice):
    phone = Device(client, "alice", name="Pixel")
    phone.login(expect=403)
    data = phone.login(SECRET)
    assert data["status"] == "pending"
    assert phone.get("/api/v1/devices/self").json()["status"] == "pending"
    r = phone.get("/api/v1/devices")
    assert (r.status_code, r.json()["error"]) == (403, "device_pending")

    assert alice.post(f"/api/v1/devices/{phone.device_id}/approve").status_code == 200
    # Same token, now active.
    assert phone.get("/api/v1/devices").status_code == 200


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
    phone.login(SECRET)
    assert alice.delete(f"/api/v1/devices/{phone.device_id}").status_code == 200
    assert phone.get("/api/v1/devices/self").status_code == 401  # sessions deleted
    r = phone.login(SECRET, expect=403)
    assert r["error"] == "device_revoked"


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
            "/api/v1/auth/challenge", json={"username": "alice", "publicKey": d.public_key_text}
        )
    r = client.post(
        "/api/v1/auth/challenge", json={"username": "bob", "publicKey": d.public_key_text}
    )
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1


def test_at_most_five_pending_devices(client, clock, alice):
    for _ in range(5):
        Device(client, "alice").login(SECRET)
        clock.advance(30)
    r = Device(client, "alice").login(SECRET, expect=429)
    assert r["error"] == "rate_limited"


def test_pending_devices_expire_after_a_day(client, clock, alice):
    phone = Device(client, "alice")
    phone.login(SECRET)
    clock.advance(24 * 3600 + 1)
    alice.login()
    ids = [d["id"] for d in alice.get("/api/v1/devices").json()["devices"]]
    assert phone.device_id not in ids
    phone.login(expect=403)  # unknown again, so the secret is needed


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
            json={"username": "alice", "publicKey": d.public_key_text},
            headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "Sync.Example.org"},
        )
        assert "origin: https://sync.example.org\n" in r.json()["message"]
