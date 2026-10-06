"""Rate limits and request size limits (docs/protocol.md 12)."""

import dataclasses

import pytest
from fastapi.testclient import TestClient

from syncryption_server.app import MAX_BODY_SIZE, create_app
from syncryption_server.auth import limit_key
from syncryption_server.state import RateLimiter
from tests.helpers import SECRET, Device
from tests.test_recovery import new_pending


@pytest.fixture
def proxied(settings, clock):
    """A server behind a proxy, so each request can come from the address it names."""
    app = create_app(dataclasses.replace(settings, behind_proxy=True, url=None), clock=clock)
    with TestClient(app) as c:
        yield c


def from_ip(client: TestClient, ip: str) -> TestClient:
    client.headers["X-Forwarded-For"] = ip
    return client


def challenge(client: TestClient, username: str, device: Device) -> int:
    r = client.post(
        "/api/v1/auth/challenge",
        json={"username": username, "vaultName": "V", "publicKey": device.public_key_text},
    )
    return r.status_code


def test_a_known_username_cannot_be_locked_out(proxied):
    alice = Device(from_ip(proxied, "198.51.100.1"), "alice")
    alice.login(SECRET)
    attacker = Device(proxied, "alice")
    from_ip(proxied, "203.0.113.9")
    statuses = [challenge(proxied, "alice", attacker) for _ in range(11)]
    assert statuses[-1] == 429
    from_ip(proxied, "198.51.100.1")
    alice.login()


def test_ipv6_clients_are_counted_by_their_64(proxied):
    d = Device(proxied, "alice")
    from_ip(proxied, "2001:db8::1")
    assert {challenge(proxied, "alice", d) for _ in range(10)} == {200}
    from_ip(proxied, "2001:db8::ffff:2")
    assert challenge(proxied, "alice", d) == 429
    from_ip(proxied, "2001:db8:0:1::1")
    assert challenge(proxied, "alice", d) == 200


def test_limit_keys():
    assert limit_key("192.0.2.7") == "192.0.2.7"
    assert limit_key("::ffff:192.0.2.7") == "192.0.2.7"
    assert limit_key("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2::/64"
    assert limit_key("testclient") == "testclient"


def test_wrong_secrets_from_many_addresses_pause_joining(proxied, clock):
    for i in range(10):
        from_ip(proxied, f"203.0.113.{i}")
        for j in range(5):
            Device(proxied, f"user{i}x{j}").login("wrong", expect=403)
    from_ip(proxied, "198.51.100.1")
    r = Device(proxied, "late").login(SECRET, expect=429)
    assert r["error"] == "rate_limited"
    clock.advance(3600)
    Device(proxied, "late").login(SECRET)


def test_recover_is_rate_limited(client, alice):
    vault_id = alice.vault_id
    phone = new_pending(client, vault_id)
    path = f"/api/v1/vaults/{vault_id}/recover"
    statuses = [phone.post(path, json=phone.keyring(2)).status_code for _ in range(11)]
    assert statuses == [404] * 10 + [429]


def test_large_bodies_are_refused(client):
    big = b"{" + b" " * MAX_BODY_SIZE + b"}"
    r = client.post(
        "/api/v1/auth/challenge", content=big, headers={"Content-Type": "application/json"}
    )
    assert (r.status_code, r.json()["error"]) == (413, "too_large")

    def chunks():
        for _ in range(3):
            yield b" " * (MAX_BODY_SIZE // 2)

    r = client.post(
        "/api/v1/auth/challenge", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert (r.status_code, r.json()["error"]) == (413, "too_large")


def test_bodies_under_the_limit_still_work(client):
    d = Device(client, "alice")
    d.login(SECRET)
    assert d.get("/api/v1/devices/self").status_code == 200


def test_idle_limiter_keys_are_dropped(clock):
    limiter = RateLimiter(clock)
    limiter.check("a", 10, 60)
    limiter.check("b", 10, 3600)
    clock.advance(61)
    limiter.prune()
    assert set(limiter.hits) == {"b"}
