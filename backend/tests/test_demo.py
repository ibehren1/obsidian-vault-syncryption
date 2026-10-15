"""Demo mode (`DEMO_MODE=TRUE`): small quotas, no history, users purged after a day, and a
public, read-only admin page."""

import dataclasses

import pytest

from syncryption_server.app import gc_pass
from syncryption_server.config import DEMO_QUOTA, DEMO_TTL, ConfigError, load_settings
from tests.helpers import ADMIN_TOKEN, SECRET, Device, blob, file_id
from tests.test_retention import history, versions

ENV = {
    "URL": "https://notes.example.com",
    "SHARED_SECRET": "s" * 16,
    "ADMIN_TOKEN": ADMIN_TOKEN,
}
# Blobs are capped well below the quota, so it is filled in chunks.
CHUNK = 2**20


@pytest.fixture
def settings(settings):
    return dataclasses.replace(settings, demo_mode=True)


@pytest.fixture
def run_gc(client):
    state = client.app.state.ctx
    return lambda: client.portal.call(gc_pass, state)


def fill(device, total: int) -> None:
    for i in range(total // CHUNK):
        assert put(device, bytes([i]) * CHUNK).status_code == 201
    if total % CHUNK:
        assert put(device, b"x" * (total % CHUNK)).status_code == 201


def put(device, data: bytes):
    blob_id, body = blob(data)
    return device.put(f"/api/v1/vaults/{device.vault_id}/blobs/{blob_id}", content=body)


def users(client) -> list[dict]:
    return client.get("/admin/api/users").json()["users"]


def test_demo_mode_is_read_from_the_environment():
    assert load_settings(ENV).demo_mode is False
    assert load_settings({**ENV, "DEMO_MODE": "FALSE"}).demo_mode is False
    assert load_settings({**ENV, "DEMO_MODE": "true"}).demo_mode is True
    with pytest.raises(ConfigError, match="DEMO_MODE"):
        load_settings({**ENV, "DEMO_MODE": "yes"})


def test_new_vaults_get_the_demo_quota(client, alice):
    assert users(client)[0]["vaults"][0]["quota"] == DEMO_QUOTA
    fill(alice, DEMO_QUOTA - 10)
    r = put(alice, b"b" * 20)
    assert r.status_code == 507
    assert r.json()["error"] == "quota_exceeded"


def test_vaults_without_a_quota_are_capped(client, alice):
    state = client.app.state.ctx

    def clear() -> None:
        with state.db.transaction() as db:
            db.execute("UPDATE vaults SET blob_quota = NULL")

    client.portal.call(state.db.run, clear)
    fill(alice, DEMO_QUOTA)
    assert put(alice, b"y").status_code == 507


def test_only_head_revisions_are_kept(alice, run_gc):
    fid = file_id(1)
    revs = versions(alice, alice.vault_id, fid, n=3)
    assert history(alice, alice.vault_id, fid) == revs[::-1]
    run_gc()
    assert history(alice, alice.vault_id, fid) == [revs[-1]]


def test_users_are_purged_a_day_after_they_join(client, clock, alice, settings, run_gc):
    assert put(alice, b"note").status_code == 201
    clock.advance(DEMO_TTL - 60)
    bob = Device(client, "bob", name="Phone")
    bob.login(SECRET)
    bob.create_vault()
    run_gc()
    assert sorted(u["username"] for u in users(client)) == ["alice", "bob"]

    clock.advance(120)
    run_gc()
    assert [u["username"] for u in users(client)] == ["bob"]
    assert not list((settings.data_dir / "blobs").glob(f"*/{alice.vault_id}/*/*"))
    assert alice.get(f"/api/v1/vaults/{alice.vault_id}/changes").status_code == 401
    # The key can start over.
    alice.login(SECRET)
    alice.create_vault()
    assert sorted(u["username"] for u in users(client)) == ["alice", "bob"]


def test_admin_page_is_public_and_read_only(client, alice):
    r = client.get("/admin")
    assert r.status_code == 200
    assert "alice" in r.text
    assert "Demo server" in r.text
    assert "<form" not in r.text
    assert client.get("/admin/api/status").status_code == 200
    assert client.get("/admin/performance.json").status_code == 200


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/admin/api/vaults/{vault}/quota", {"quotaBytes": 2**30}),
        ("/admin/api/vaults/{vault}/grace", {"graceSeconds": 7200}),
        ("/admin/api/maintenance/on", None),
        ("/admin/api/vaults/{vault}/disable", None),
    ],
)
def test_admin_api_refuses_changes(client, alice, path, body):
    r = client.post(path.format(vault=alice.vault_id), json=body)
    assert r.status_code == 403
    assert r.json()["error"] == "demo"
    assert users(client)[0]["vaults"][0]["quota"] == DEMO_QUOTA
    assert users(client)[0]["disabled"] is False


def test_admin_forms_refuse_changes(client, alice):
    r = client.post(
        f"/admin/vaults/{alice.vault_id}/quota", data={"gb": "10"}, follow_redirects=False
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/admin?done=demo"
    assert users(client)[0]["vaults"][0]["quota"] == DEMO_QUOTA
    r = client.post("/admin/login", data={"token": ADMIN_TOKEN}, follow_redirects=False)
    assert r.headers["location"] == "/admin"


def test_home_page_warns_visitors(client):
    assert "Demo server" in client.get("/").text
