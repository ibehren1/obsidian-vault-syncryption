import dataclasses
import json
import re

import pytest
from fastapi.testclient import TestClient

from syncryption_server.app import create_app
from tests.helpers import ADMIN_TOKEN, META, SECRET, Device, blob, file_id

BEARER = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture
def vault(alice) -> str:
    """Alice's vault "Personal", with a file."""
    vault_id = alice.vault_id
    blob_id, data = blob(b"ciphertext")
    assert alice.put(f"/api/v1/vaults/{vault_id}/blobs/{blob_id}", content=data).status_code == 201
    r = alice.put(
        f"/api/v1/vaults/{vault_id}/files/{file_id()}",
        json={"parentRev": None, "deleted": False, "meta": META, "blobs": [blob_id]},
    )
    assert r.status_code == 201, r.text
    return vault_id


def second_vault(client, name: str = "Other") -> Device:
    """Alice's key for another vault, which it creates."""
    d = Device(client, "alice", vault_name=name, name="MacBook")
    d.login(SECRET)
    d.create_vault()
    return d


def users(client) -> list[dict]:
    r = client.get("/admin/api/users", headers=BEARER)
    assert r.status_code == 200, r.text
    return r.json()["users"]


def act(client, kind: str, item_id: str, action: str, confirm: str | None = None):
    body = {"confirm": confirm} if confirm is not None else None
    return client.post(f"/admin/api/{kind}/{item_id}/{action}", headers=BEARER, json=body)


def login(client) -> tuple[dict[str, str], str]:
    """Log in through the form: the cookie header and the page's CSRF token."""
    r = client.post("/admin/login", data={"token": ADMIN_TOKEN}, follow_redirects=False)
    assert r.status_code == 303
    set_cookie = r.headers["set-cookie"]
    assert "HttpOnly" in set_cookie and "SameSite=strict" in set_cookie
    assert "Secure" in set_cookie and "Path=/admin" in set_cookie
    cookie = {"cookie": set_cookie.split(";")[0]}
    page = client.get("/admin", headers=cookie)
    assert page.status_code == 200
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    return cookie, csrf


def test_admin_needs_the_token(client):
    page = client.get("/admin")
    assert page.status_code == 200 and 'name="token"' in page.text
    assert page.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert client.get("/admin/api/users").status_code == 401
    wrong = {"Authorization": "Bearer " + "x" * 40}
    assert client.get("/admin/api/users", headers=wrong).status_code == 401
    assert client.get("/admin", headers=wrong).status_code == 401
    r = client.post("/admin/login", data={"token": "nope"})
    assert r.status_code == 401 and "Wrong token" in r.text
    assert "/admin" not in client.get("/openapi.json").text


def test_wrong_tokens_are_rate_limited(client):
    wrong = {"Authorization": "Bearer " + "x" * 40}
    for _ in range(5):
        assert client.get("/admin/api/users", headers=wrong).status_code == 401
    assert client.get("/admin/api/users", headers=wrong).status_code == 429
    # Even the right token waits, so the limit can't be used to confirm a guess.
    assert client.get("/admin/api/users", headers=BEARER).status_code == 429


def test_right_tokens_are_not_rate_limited(client):
    for _ in range(10):
        assert client.get("/admin/api/users", headers=BEARER).status_code == 200


def test_lists_users_vaults_sizes_and_devices(client, alice, vault):
    phone = Device(client, "alice", name="Pixel")
    phone.login()
    creating = Device(client, "alice", vault_name="Work", name="Desk")
    creating.login(SECRET)
    (user,) = users(client)
    assert user["username"] == "alice" and user["disabled"] is False
    assert user["lastSeenAt"] is not None
    assert "devices" not in user
    (v,) = user["vaults"]
    assert (v["name"], v["size"], v["files"], v["disabled"]) == ("Personal", 10, 1, False)
    assert v["revisions"] == 1
    assert v["lastChangeAt"] is not None
    assert [(d["name"], d["status"]) for d in v["devices"]] == [
        ("MacBook", "active"),
        ("Pixel", "pending"),
    ]
    d = v["devices"][0]
    assert d["id"] == alice.device_id and d["fingerprint"].startswith("SHA256:")
    assert d["createdAt"] and d["lastSeenAt"]
    (c,) = user["creating"]
    assert (c["vaultName"], c["device"]["name"], c["device"]["id"]) == (
        "Work",
        "Desk",
        creating.device_id,
    )


def test_page_escapes_names(client, alice):
    second_vault(client, "<b>x</b>")
    cookie, _ = login(client)
    page = client.get("/admin", headers=cookie).text
    assert "&lt;b&gt;x&lt;/b&gt;" in page and "<b>x</b>" not in page


def test_page_lists_devices_with_fingerprints(client, alice):
    cookie, _ = login(client)
    page = client.get("/admin", headers=cookie).text
    fp = alice.get("/api/v1/devices/self").json()["fingerprint"]
    assert "MacBook" in page and fp in page


def test_page_lists_keys_under_their_vault(client, alice):
    other = second_vault(client, "Work")
    creating = Device(client, "alice", vault_name="Notes", name="Laptop")
    creating.login(SECRET)
    cookie, _ = login(client)
    page = client.get("/admin", headers=cookie).text
    cards = re.findall(r'<section class="vault[^"]*">(.*?)</section>', page)
    by_name = {re.search(r"<h3>([^< ]+)", c)[1]: c for c in cards}
    assert set(by_name) == {"Personal", "Work", "Notes"}
    fp = alice.get("/api/v1/devices/self").json()["fingerprint"]
    other_fp = other.get("/api/v1/devices/self").json()["fingerprint"]
    assert fp in by_name["Personal"] and other_fp not in by_name["Personal"]
    assert other_fp in by_name["Work"] and fp not in by_name["Work"]
    assert "Laptop" in by_name["Notes"] and "(being created)" in by_name["Notes"]
    assert "<th>Vault</th>" not in page


def test_performance_tab(client, alice):
    cookie, _ = login(client)
    vaults = client.get("/admin", headers=cookie)
    assert "script-src" not in vaults.headers["content-security-policy"]
    assert 'href="/admin?tab=performance"' in vaults.text
    page = client.get("/admin?tab=performance", headers=cookie)
    assert page.status_code == 200
    csp = page.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "connect-src 'self'" in csp
    assert '<script src="/admin/performance.js"></script>' in page.text
    assert '<option value="5" selected>5 s</option>' in page.text
    assert '<option value="0">Paused</option>' in page.text
    for value_id in ("commits", "conflicts", "bin", "lag", "disk", "gclast"):
        assert f'id="{value_id}"' in page.text
    assert 'id="spark-rps"' in page.text
    # Shown by the script only with S3 and while Litestream replicates.
    assert '<section class="stripe" id="card-s3" hidden>' in page.text
    assert '<section class="stripe" id="card-litestream" hidden>' in page.text
    for value_id in ("s3rps", "s3p95", "s3results", "lsup", "lssync", "lsbytes"):
        assert f'id="{value_id}"' in page.text
    js = client.get("/admin/performance.js")
    assert js.status_code == 200 and js.headers["content-type"].startswith("text/javascript")
    assert "innerHTML" not in js.text
    # Without a login: the login form, and no data.
    assert 'name="token"' in client.get("/admin?tab=performance").text
    assert client.get("/admin/performance.json").status_code == 401
    assert client.get("/admin/api/performance").status_code == 401
    assert client.get("/admin/api/performance", headers=cookie).status_code == 401


def test_performance_snapshot(client, alice, vault):
    alice.get(f"/api/v1/vaults/{alice.vault_id}/changes")
    cookie, _ = login(client)
    r = client.get("/admin/performance.json", headers=cookie)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    snap = r.json()
    assert client.get("/admin/api/performance", headers=BEARER).json().keys() == snap.keys()
    assert (snap["users"], snap["vaults"], snap["files"], snap["blobBytes"]) == (1, 1, 1, 10)
    assert snap["devices"] == {"pending": 0, "active": 1, "revoked": 0}
    assert snap["maintenance"] is False and snap["longpolls"] == 0
    assert snap["startedAt"] <= snap["time"]
    changes = "/api/v1/vaults/{vault_id}/changes"
    (req,) = [x for x in snap["requests"] if x["route"] == changes]
    assert (req["method"], req["status"], req["count"]) == ("GET", "200", 1)
    (d,) = [x for x in snap["durations"] if x["route"] == changes]
    assert len(d["buckets"]) == len(snap["buckets"]) + 1 and d["buckets"][-1] == 1
    # The page's own polling isn't counted, and nothing names a user, vault or device.
    assert not any(x["route"].startswith("/admin/perf") for x in snap["requests"])
    assert all(k in snap["process"] for k in ("cpuSeconds", "memoryBytes", "openFds"))
    # The blob upload's 10 bytes in, the responses out. The poll itself isn't counted.
    assert snap["requestBytes"] >= 10 and snap["responseBytes"] > 0
    assert snap["inFlight"] == 0 and snap["loopLagSeconds"] >= 0
    assert snap["disk"]["freeBytes"] > 0 and snap["disk"]["totalBytes"] >= snap["disk"]["freeBytes"]
    assert snap["dbBytes"] > 0
    assert snap["gcLastRun"] == {"expired": None, "retention": None, "blobs": None}
    assert (snap["prunedRevisions"], snap["deletedBlobs"]) == (0, 0)
    for secret in ("alice", "Personal", alice.vault_id, alice.device_id):
        assert secret not in r.text


def test_activity_tab(client, alice):
    cookie, _ = login(client)
    assert 'href="/admin?tab=activity"' in client.get("/admin", headers=cookie).text
    page = client.get("/admin?tab=activity", headers=cookie)
    assert page.status_code == 200
    csp = page.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "connect-src 'self'" in csp
    assert '<script src="/admin/activity.js"></script>' in page.text
    for value_id in ("interval", "groupby", "activity", "since", "updated"):
        assert f'id="{value_id}"' in page.text
    js = client.get("/admin/activity.js")
    assert js.status_code == 200 and js.headers["content-type"].startswith("text/javascript")
    assert "innerHTML" not in js.text
    assert 'name="token"' in client.get("/admin?tab=activity").text
    assert client.get("/admin/activity.json").status_code == 401
    assert client.get("/admin/api/activity").status_code == 401


def test_activity_snapshot(client, alice):
    phone = Device(client, "alice", name="Pixel")
    phone.join(alice)
    alice.get(f"/api/v1/vaults/{alice.vault_id}/changes")
    cookie, _ = login(client)
    r = client.get("/admin/activity.json", headers=cookie)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    snap = r.json()
    assert client.get("/admin/api/activity", headers=BEARER).json().keys() == snap.keys()
    assert snap["startedAt"] <= snap["time"]
    by_id = {d["deviceId"]: d for d in snap["devices"]}
    mine = by_id[alice.device_id]
    names = (mine["username"], mine["vaultName"], mine["deviceName"], mine["status"])
    assert names == ("alice", "Personal", "MacBook", "active")
    assert mine["fingerprint"].startswith("SHA256:")
    assert mine["routes"]["GET /api/v1/vaults/{vault_id}/changes"] == 1
    # Every key is listed, also one without requests yet.
    assert phone.device_id in by_id
    # The logins came before the sessions: counted without a device.
    assert by_id[None]["routes"]["POST /api/v1/auth/verify"] >= 1
    assert by_id[None]["username"] is None
    # The tab's own polling isn't counted.
    assert not any(k.startswith("GET /admin/") for k in by_id[None]["routes"])
    # The Performance snapshot names nobody.
    perf = client.get("/admin/api/performance", headers=BEARER).text
    assert "activity" not in json.loads(perf) and alice.device_id not in perf


def test_performance_counts_requests_without_metrics(settings):
    settings = dataclasses.replace(settings, disable_metrics=True)
    with TestClient(create_app(settings)) as c:
        c.get("/health")
        snap = c.get("/admin/api/performance", headers=BEARER).json()
        assert any(x["route"] == "/health" for x in snap["requests"])


def test_page_explains_retention_and_counts_versions(client, alice, vault):
    cookie, _ = login(client)
    page = client.get("/admin", headers=cookie).text
    assert "every version for 30 days, at least the last 10" in page
    assert "deleted files for 90 days" in page
    assert "1 files · 1 versions" in page


def test_disable_and_enable_a_vault(client, alice, vault):
    other = second_vault(client)
    assert act(client, "vaults", vault, "disable").status_code == 204
    r = alice.get(f"/api/v1/vaults/{vault}/changes")
    assert (r.status_code, r.json()["error"]) == (403, "vault_disabled")
    r = alice.post("/api/v1/vaults/open", json={"name": "Personal"})
    assert (r.status_code, r.json()["error"]) == (403, "vault_disabled")
    assert other.get(f"/api/v1/vaults/{other.vault_id}/changes").status_code == 200
    assert next(v for v in users(client)[0]["vaults"] if v["id"] == vault)["disabled"] is True

    assert act(client, "vaults", vault, "enable").status_code == 204
    assert alice.get(f"/api/v1/vaults/{vault}/changes").status_code == 200


def test_purge_a_vault(client, clock, alice, vault, settings):
    other = second_vault(client)
    phone = Device(client, "alice", name="Pixel")
    phone.join(alice)
    pending = Device(client, "alice", name="Pending")
    pending.login()
    r = phone.post(f"/api/v1/vaults/{vault}/locks/{file_id(5)}", json={"clientId": "A" * 22})
    assert r.status_code == 200, r.text
    user_id = users(client)[0]["id"]
    folder = settings.data_dir / "blobs" / user_id / vault
    assert any(folder.rglob("*"))
    clock.advance(60)

    r = act(client, "vaults", vault, "purge", "Personal")
    assert (r.status_code, r.json()["error"]) == (409, "not_disabled")
    act(client, "vaults", vault, "disable")
    r = act(client, "vaults", vault, "purge", "personal")
    assert (r.status_code, r.json()["error"]) == (400, "confirm")
    assert act(client, "vaults", vault, "purge", "Personal").status_code == 204

    assert not any(p.is_file() for p in folder.rglob("*"))
    db = client.app.state.ctx.db
    assert db.one("SELECT COUNT(*) FROM vaults WHERE id = ?", vault)[0] == 0
    for table in ("files", "revisions", "blobs", "keyrings", "locks", "devices"):
        assert db.one(f"SELECT COUNT(*) FROM {table} WHERE vault_id = ?", vault)[0] == 0  # noqa: S608
    for dev in (alice, phone, pending):
        assert db.one("SELECT COUNT(*) FROM devices WHERE id = ?", dev.device_id)[0] == 0
        assert db.one("SELECT COUNT(*) FROM sessions WHERE device_id = ?", dev.device_id)[0] == 0
        assert dev.get("/api/v1/devices/self").status_code == 401
    assert [v["id"] for v in users(client)[0]["vaults"]] == [other.vault_id]
    assert act(client, "vaults", vault, "purge", "Personal").status_code == 404
    # The other vault keeps working.
    assert other.get(f"/api/v1/vaults/{other.vault_id}/changes").status_code == 200
    # The keys are unknown now, and the name is free: creating it needs the secret again.
    assert alice.login(expect=403)["error"] == "join_required"
    assert alice.login(SECRET)["status"] == "active"
    alice.create_vault()


def test_disable_enable_and_purge_a_user(client, clock, alice, vault, settings):
    second_vault(client)
    Device(client, "alice", vault_name="Work").login(SECRET)  # creating a vault
    bob = Device(client, "bob")
    bob.login(SECRET)
    bob.create_vault()
    user_id = next(u["id"] for u in users(client) if u["username"] == "alice")
    clock.advance(60)  # stay under the per-minute auth limit

    assert act(client, "users", user_id, "disable").status_code == 204
    r = alice.get("/api/v1/devices/self")
    assert (r.status_code, r.json()["error"]) == (403, "user_disabled")
    assert alice.login(expect=403)["error"] == "user_disabled"
    assert bob.get(f"/api/v1/vaults/{bob.vault_id}/changes").status_code == 200

    assert act(client, "users", user_id, "enable").status_code == 204
    alice.login()
    assert alice.get(f"/api/v1/vaults/{vault}/changes").status_code == 200

    act(client, "users", user_id, "disable")
    assert act(client, "users", user_id, "purge", "alice").status_code == 204
    assert [u["username"] for u in users(client)] == ["bob"]
    assert not any(p.is_file() for p in (settings.data_dir / "blobs" / user_id).rglob("*"))
    db = client.app.state.ctx.db
    assert db.one("SELECT COUNT(*) FROM devices WHERE user_id = ?", user_id)[0] == 0
    assert db.one("SELECT COUNT(*) FROM vaults WHERE user_id = ?", user_id)[0] == 0
    assert db.one("SELECT COUNT(*) FROM sessions")[0] == 1  # bob's
    # The username can join again, as a new user.
    Device(client, "alice").login(SECRET)


def test_form_session_and_csrf(client, alice, vault):
    cookie, csrf = login(client)
    page = client.get("/admin", headers=cookie).text
    assert "alice" in page and "Personal" in page and "MacBook" in page

    r = client.post(
        f"/admin/vaults/{vault}/disable", headers=cookie, data={}, follow_redirects=False
    )
    assert (r.status_code, r.headers["location"]) == (303, "/admin?done=csrf")
    assert users(client)[0]["vaults"][0]["disabled"] is False

    r = client.post(
        f"/admin/vaults/{vault}/disable",
        headers=cookie,
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/admin?done=disabled"
    assert users(client)[0]["vaults"][0]["disabled"] is True
    page = client.get("/admin?done=disabled", headers=cookie).text
    assert "Disabled." in page and "type Personal to purge" in page

    r = client.post(
        f"/admin/vaults/{vault}/purge",
        headers=cookie,
        data={"csrf": csrf, "confirm": "Personal"},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/admin?done=purged"
    assert users(client)[0]["vaults"] == []
    assert "Purged." in client.get("/admin?done=purged", headers=cookie).text

    r = client.post("/admin/logout", headers=cookie, data={"csrf": csrf}, follow_redirects=False)
    assert r.headers["location"] == "/admin?done=logged_out"
    assert 'name="token"' in client.get("/admin", headers=cookie).text


def test_form_actions_need_a_login(client, alice, vault):
    r = client.post(f"/admin/vaults/{vault}/disable", data={})
    assert r.status_code == 401 and 'name="token"' in r.text
    assert users(client)[0]["vaults"][0]["disabled"] is False


def test_sessions_expire(client, clock):
    cookie, _ = login(client)
    clock.advance(12 * 3600 + 1)
    assert 'name="token"' in client.get("/admin", headers=cookie).text


def test_admin_cookie_is_secure_unless_plain_http_to_this_machine(settings):
    def cookie(settings, headers=None, peer=("127.0.0.1", 50000)) -> str:
        with TestClient(create_app(settings), client=peer) as c:
            r = c.post(
                "/admin/login", data={"token": ADMIN_TOKEN}, headers=headers, follow_redirects=False
            )
            assert r.status_code == 303
            return r.headers["set-cookie"]

    proxied = dataclasses.replace(settings, url=None, behind_proxy=True)
    # A proxy that says the client used plain HTTP still gets a Secure cookie.
    claims_http = {"x-forwarded-proto": "http", "host": "notes.example.com"}
    assert "Secure" in cookie(proxied, claims_http, ("10.0.0.2", 50000))
    assert "Secure" in cookie(proxied, {"host": "notes.example.com"}, ("10.0.0.2", 50000))
    # Plain HTTP to this machine, for development: not Secure, or the browser drops it.
    assert "Secure" not in cookie(proxied, {"host": "localhost:8080"})
    assert "Secure" not in cookie(proxied, {"host": "127.0.0.1:8080"})


def test_admin_csp_allows_only_its_own_stylesheet(client):
    import base64
    import hashlib

    for page in (client.get("/admin"), client.get("/")):
        csp = page.headers["content-security-policy"]
        assert "unsafe-inline" not in csp
        style = re.search(r"<style>(.*?)</style>", page.text, re.S)[1]
        digest = base64.b64encode(hashlib.sha256(style.encode()).digest()).decode()
        assert f"style-src 'sha256-{digest}'" in csp
        assert " style=" not in page.text
