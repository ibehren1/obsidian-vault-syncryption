"""Rate limits and request size limits (docs/protocol.md 12)."""

import dataclasses
import ipaddress

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
    # The proxy connects from a Docker network address, inside the default TRUSTED_PROXIES.
    with TestClient(app, client=("172.18.0.2", 50000)) as c:
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


def test_forwarded_for_from_an_untrusted_peer_is_ignored(settings, clock):
    """Someone reaching :8080 directly can't pick a new address for every request."""
    app = create_app(dataclasses.replace(settings, behind_proxy=True, url=None), clock=clock)
    with TestClient(app, client=("203.0.113.50", 50000)) as c:
        d = Device(c, "alice")
        statuses = []
        for i in range(11):
            from_ip(c, f"198.51.100.{i}")
            statuses.append(challenge(c, "alice", d))
    assert statuses == [200] * 10 + [429]


def test_trusted_proxies_can_be_narrowed(settings, clock):
    narrowed = dataclasses.replace(
        settings,
        behind_proxy=True,
        url=None,
        trusted_proxies=(ipaddress.ip_network("10.1.2.3/32"),),
    )
    with TestClient(create_app(narrowed, clock=clock), client=("10.1.2.4", 1)) as c:
        d = Device(c, "alice")
        from_ip(c, "198.51.100.1")
        assert {challenge(c, "alice", d) for _ in range(10)} == {200}
        from_ip(c, "198.51.100.2")
        assert challenge(c, "alice", d) == 429
    with TestClient(create_app(narrowed, clock=clock), client=("10.1.2.3", 1)) as c:
        d = Device(c, "alice")
        from_ip(c, "198.51.100.1")
        assert {challenge(c, "alice", d) for _ in range(10)} == {200}
        from_ip(c, "198.51.100.2")
        assert challenge(c, "alice", d) == 200


def test_forwarded_for_is_ignored_without_behind_proxy(settings, clock):
    with TestClient(create_app(settings, clock=clock), client=("127.0.0.1", 1)) as c:
        d = Device(c, "alice")
        statuses = []
        for i in range(11):
            from_ip(c, f"198.51.100.{i}")
            statuses.append(challenge(c, "alice", d))
    assert statuses[-1] == 429


def test_limit_keys():
    assert limit_key("192.0.2.7") == "192.0.2.7"
    assert limit_key("::ffff:192.0.2.7") == "192.0.2.7"
    assert limit_key("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2::/64"
    assert limit_key("testclient") == "testclient"


def test_wrong_secrets_from_many_addresses_dont_block_the_right_one(proxied, clock):
    for i in range(10):
        from_ip(proxied, f"203.0.113.{i}")
        for j in range(5):
            Device(proxied, f"user{i}x{j}").login("wrong", expect=403)
    from_ip(proxied, "198.51.100.1")
    r = Device(proxied, "guess").login("wrong", expect=429)
    assert r["error"] == "rate_limited"
    assert Device(proxied, "late").login(SECRET)["status"] == "active"
    clock.advance(3600)
    Device(proxied, "later").login("wrong", expect=403)


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


def proxied_vault(proxied: TestClient) -> Device:
    alice = Device(from_ip(proxied, "198.51.100.1"), "alice", name="MacBook")
    alice.login(SECRET)
    alice.create_vault()
    return alice


def pending_ids(alice: Device) -> list[str]:
    from_ip(alice.client, "198.51.100.1")
    devices = alice.get(f"/api/v1/vaults/{alice.vault_id}/devices").json()["devices"]
    return [d["id"] for d in devices if d["status"] == "pending"]


def test_new_pending_devices_are_limited_per_address(proxied, clock):
    proxied_vault(proxied)
    from_ip(proxied, "203.0.113.1")
    for _ in range(3):
        assert Device(proxied, "alice").login()["status"] == "pending"
    assert Device(proxied, "alice").login(expect=429)["error"] == "rate_limited"
    # Another address isn't affected, and this one may add another an hour later.
    from_ip(proxied, "203.0.113.2")
    assert Device(proxied, "alice").login()["status"] == "pending"
    clock.advance(3600)
    from_ip(proxied, "203.0.113.1")
    assert Device(proxied, "alice").login()["status"] == "pending"


def test_a_pending_device_logging_in_again_is_not_a_new_one(proxied, clock):
    proxied_vault(proxied)
    from_ip(proxied, "203.0.113.1")
    phone = Device(proxied, "alice")
    first = phone.login()["deviceId"]
    for _ in range(4):
        clock.advance(30)  # stay under the per-minute auth limit
        again = phone.login()
        assert (again["deviceId"], again["created"]) == (first, False)
    assert Device(proxied, "alice").login()["status"] == "pending"


def test_new_pending_devices_are_limited_per_vault(proxied, clock):
    alice = proxied_vault(proxied)
    for i in range(10):
        from_ip(proxied, f"203.0.113.{i}")
        Device(proxied, "alice").login()
    from_ip(proxied, "203.0.113.200")
    assert Device(proxied, "alice").login(expect=429)["error"] == "rate_limited"
    # Another vault has its own limit, and active devices still log in.
    from_ip(proxied, "198.51.100.1")
    work = Device(proxied, "alice", vault_name="Work")
    work.login(SECRET)
    work.create_vault()
    from_ip(proxied, "203.0.113.201")
    assert Device(proxied, "alice", vault_name="Work").login()["status"] == "pending"
    from_ip(proxied, "198.51.100.1")
    assert alice.login()["status"] == "active"
    clock.advance(3600)
    from_ip(proxied, "203.0.113.200")
    assert Device(proxied, "alice").login()["status"] == "pending"


def test_a_full_vault_replaces_the_least_recently_seen_pending_device(proxied, clock):
    alice = proxied_vault(proxied)
    from_ip(proxied, "192.0.2.50")
    phone = Device(proxied, "alice", name="New phone")
    phone.login()
    others = []
    for i in range(6):
        clock.advance(61)
        # The real device polls while it waits, so it stays recently seen.
        from_ip(proxied, "192.0.2.50")
        assert phone.post("/api/v1/vaults/open", json={"name": "Personal"}).status_code == 200
        from_ip(proxied, f"203.0.113.{i}")
        others.append(Device(proxied, "alice").login()["deviceId"])
    pending = pending_ids(alice)
    # Never more than 5: the polling device stays, the stalest others were replaced.
    assert len(pending) == 5
    assert set(pending) == {phone.device_id, *others[2:]}
    r = alice.post(f"/api/v1/vaults/{alice.vault_id}/devices/{phone.device_id}/approve")
    assert r.status_code == 200, r.text


def test_a_replaced_pending_device_loses_its_session(proxied, clock):
    proxied_vault(proxied)
    from_ip(proxied, "192.0.2.50")
    stale = Device(proxied, "alice")
    stale.login()
    for i in range(5):
        clock.advance(61)
        from_ip(proxied, f"203.0.113.{i}")
        Device(proxied, "alice").login()
    r = stale.get("/api/v1/devices/self")
    assert (r.status_code, r.json()["error"]) == (401, "unauthenticated")
