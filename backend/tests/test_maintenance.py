import dataclasses
import threading
import time

import pytest
from fastapi.testclient import TestClient

from syncryption_server import PROTOCOL_VERSION, __version__
from syncryption_server.app import PROTOCOL_HEADER, VERSION_HEADER, create_app
from syncryption_server.encoding import rfc3339
from tests.helpers import SECRET, Device
from tests.test_admin import BEARER, act, login, users

CONTACT = "ops@example.com or #help on Slack"
NOTE = "Moving to a new disk, back at 18:00 UTC"


@pytest.fixture
def settings(settings):
    return dataclasses.replace(settings, admin_contact=CONTACT)


def maintenance(client, switch: str, message: str | None = None):
    body = {"message": message} if message is not None else None
    return client.post(f"/admin/api/maintenance/{switch}", headers=BEARER, json=body)


def test_home_page(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/html; charset=utf-8"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers[PROTOCOL_HEADER] == str(PROTOCOL_VERSION)
    text = r.text
    assert f"Vault Syncryption server {__version__}" in text
    assert "https://notes.example.com" in text
    assert "encryption key" in text and "shared secret" in text
    assert f"Administrator: {CONTACT}" in text
    assert "Status: ok" in text
    assert "SSH" not in text and SECRET not in text
    assert "/" not in client.get("/openapi.json").json()["paths"]


def test_home_page_escapes(client):
    assert maintenance(client, "on", "<b>soon</b>").status_code == 204
    text = client.get("/").text
    assert "&lt;b&gt;soon&lt;/b&gt;" in text and "<b>soon</b>" not in text


def test_home_page_without_a_contact(tmp_path):
    from syncryption_server.config import Settings

    settings = Settings(shared_secret=SECRET, behind_proxy=True, data_dir=tmp_path)
    with TestClient(create_app(settings)) as c:
        text = c.get("/", headers={"x-forwarded-proto": "https", "host": "sync.lan"}).text
    assert "https://sync.lan" in text
    assert "contact the person who runs this server" in text


def test_maintenance_blocks_the_sync_api(client, alice, clock):
    vault = alice.create_vault()
    assert maintenance(client, "on", NOTE).status_code == 204

    for r in (
        alice.get(f"/api/v1/vaults/{vault}/changes"),
        alice.get("/api/v1/vaults"),
        client.post("/api/v1/auth/challenge", json={"username": "x", "publicKey": "y"}),
        client.get("/api/v1/nope"),
    ):
        assert r.status_code == 503
        assert r.headers["retry-after"] == "60"
        assert r.headers[VERSION_HEADER] == __version__
        assert r.headers[PROTOCOL_HEADER] == str(PROTOCOL_VERSION)
        assert r.json() == {
            "error": "maintenance",
            "message": "The server is in maintenance, so sync is paused. "
            "It resumes by itself when maintenance ends.",
            "details": {"adminContact": CONTACT, "note": NOTE, "since": rfc3339(int(clock.t))},
        }

    # The rest keeps working.
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "maintenance"
    assert health.json()["maintenance"] == {"since": rfc3339(int(clock.t)), "message": NOTE}
    assert health.json()["adminContact"] == CONTACT
    home = client.get("/")
    assert home.status_code == 200
    assert "Status: maintenance" in home.text and NOTE in home.text
    assert "Sync is paused until maintenance ends." in home.text
    assert users(client)[0]["username"] == "alice"
    status = client.get("/admin/api/status", headers=BEARER).json()
    assert status["maintenance"]["message"] == NOTE
    assert status["adminContact"] == CONTACT

    assert maintenance(client, "off").status_code == 204
    assert alice.get(f"/api/v1/vaults/{vault}/changes").status_code == 200
    assert client.get("/health").json()["maintenance"] is None
    assert "Status: ok" in client.get("/").text


def test_maintenance_without_a_message(client, alice):
    assert maintenance(client, "on").status_code == 204
    details = alice.get("/api/v1/vaults").json()["details"]
    assert details["note"] is None
    # Turning it on again updates the message and keeps the start time.
    since = details["since"]
    assert maintenance(client, "on", "later").status_code == 204
    assert alice.get("/api/v1/vaults").json()["details"] == {
        "adminContact": CONTACT,
        "note": "later",
        "since": since,
    }
    assert maintenance(client, "off").status_code == 204
    assert maintenance(client, "off").status_code == 204


def test_maintenance_message_is_checked(client):
    for message in ("x" * 501, "two\nlines"):
        r = maintenance(client, "on", message)
        assert (r.status_code, r.json()["error"]) == (400, "bad_request")
    assert client.get("/health").json()["status"] == "ok"
    assert client.post("/admin/api/maintenance/on").status_code == 401
    assert client.post("/admin/api/maintenance/maybe", headers=BEARER).status_code == 400


def test_maintenance_survives_a_restart(settings, clock):
    with TestClient(create_app(settings, clock=clock)) as c:
        assert maintenance(c, "on", NOTE).status_code == 204
    with TestClient(create_app(settings, clock=clock)) as c:
        assert c.get("/api/v1/vaults").status_code == 503
        assert c.get("/health").json()["maintenance"]["message"] == NOTE
        assert maintenance(c, "off").status_code == 204
    with TestClient(create_app(settings, clock=clock)) as c:
        assert c.get("/health").json()["status"] == "ok"


def test_maintenance_wakes_long_polls(client, alice):
    vault = alice.create_vault()
    out = {}

    def waiter():
        start = time.monotonic()
        out["response"] = alice.get(f"/api/v1/vaults/{vault}/wait?since=1&timeout=10")
        out["took"] = time.monotonic() - start

    t = threading.Thread(target=waiter)
    t.start()
    time.sleep(0.2)
    assert maintenance(client, "on").status_code == 204
    t.join(5)
    r = out["response"]
    assert (r.status_code, r.json()["error"]) == (503, "maintenance")
    assert r.headers[PROTOCOL_HEADER] == str(PROTOCOL_VERSION)
    assert out["took"] < 5


def test_maintenance_form(client, alice):
    cookie, csrf = login(client)
    page = client.get("/admin", headers=cookie).text
    assert "Start maintenance" in page

    r = client.post(
        "/admin/maintenance/on", headers=cookie, data={"message": NOTE}, follow_redirects=False
    )
    assert (r.status_code, r.headers["location"]) == (303, "/admin?done=csrf")
    assert client.get("/health").json()["status"] == "ok"

    r = client.post(
        "/admin/maintenance/on",
        headers=cookie,
        data={"csrf": csrf, "message": "<b>" + NOTE},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/admin?done=maintenance_on"
    assert alice.get("/api/v1/vaults").status_code == 503
    page = client.get("/admin?done=maintenance_on", headers=cookie).text
    assert "Maintenance started." in page and "End maintenance" in page
    assert "&lt;b&gt;" + NOTE in page and "<b>" + NOTE not in page

    r = client.post(
        "/admin/maintenance/off", headers=cookie, data={"csrf": csrf}, follow_redirects=False
    )
    assert r.headers["location"] == "/admin?done=maintenance_off"
    assert alice.get("/api/v1/vaults").status_code == 200
    assert "Maintenance ended." in client.get("/admin?done=maintenance_off", headers=cookie).text

    r = client.post(
        "/admin/maintenance/on",
        headers=cookie,
        data={"csrf": csrf, "message": "x" * 501},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/admin?done=bad_message"
    assert client.get("/health").json()["status"] == "ok"

    assert client.post("/admin/maintenance/on", data={}).status_code == 401


def test_disabled_errors_carry_the_admin_contact(client, alice):
    vault = alice.create_vault()
    act(client, "vaults", vault, "disable")
    r = alice.get(f"/api/v1/vaults/{vault}/changes")
    assert r.json()["details"] == {"adminContact": CONTACT}
    act(client, "users", users(client)[0]["id"], "disable")
    r = alice.get("/api/v1/vaults")
    assert (r.json()["error"], r.json()["details"]) == ("user_disabled", {"adminContact": CONTACT})
    assert Device(client, "alice", seed=alice.seed).login(expect=403)["details"] == {
        "adminContact": CONTACT
    }


def test_disabled_errors_without_a_contact(client, alice, settings):
    client.app.state.ctx.settings = dataclasses.replace(settings, admin_contact="")
    vault = alice.create_vault()
    act(client, "vaults", vault, "disable")
    assert alice.get(f"/api/v1/vaults/{vault}/changes").json()["details"] == {}
