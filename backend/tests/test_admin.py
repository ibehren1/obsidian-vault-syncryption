import re

import pytest

from tests.helpers import ADMIN_TOKEN, SECRET, Device, blob, file_id

BEARER = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture
def vault(alice) -> str:
    vault_id = alice.create_vault("Notes")
    blob_id, data = blob(b"ciphertext")
    assert alice.put(f"/api/v1/vaults/{vault_id}/blobs/{blob_id}", content=data).status_code == 201
    r = alice.put(
        f"/api/v1/vaults/{vault_id}/files/{file_id()}",
        json={"parentRev": None, "deleted": False, "meta": "bWV0YQ", "blobs": [blob_id]},
    )
    assert r.status_code == 201, r.text
    return vault_id


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
    (user,) = users(client)
    assert user["username"] == "alice" and user["disabled"] is False
    assert user["lastSeenAt"] is not None
    (v,) = user["vaults"]
    assert (v["name"], v["size"], v["files"], v["disabled"]) == ("Notes", 10, 1, False)
    assert v["lastChangeAt"] is not None
    (d,) = user["devices"]
    assert (d["name"], d["status"]) == ("MacBook", "active")


def test_page_escapes_names(client, alice):
    alice.create_vault("<b>x</b>")
    cookie, _ = login(client)
    page = client.get("/admin", headers=cookie).text
    assert "&lt;b&gt;x&lt;/b&gt;" in page and "<b>x</b>" not in page


def test_disable_and_enable_a_vault(client, alice, vault):
    other = alice.create_vault("Other")
    assert act(client, "vaults", vault, "disable").status_code == 204
    r = alice.get(f"/api/v1/vaults/{vault}/changes")
    assert (r.status_code, r.json()["error"]) == (403, "vault_disabled")
    r = alice.post("/api/v1/vaults/open", json={"name": "Notes"})
    assert (r.status_code, r.json()["error"]) == (403, "vault_disabled")
    assert alice.get(f"/api/v1/vaults/{other}/changes").status_code == 200
    assert users(client)[0]["vaults"][0]["disabled"] is True

    assert act(client, "vaults", vault, "enable").status_code == 204
    assert alice.get(f"/api/v1/vaults/{vault}/changes").status_code == 200


def test_purge_a_vault(client, alice, vault, settings):
    other = alice.create_vault("Other")
    user_id = users(client)[0]["id"]
    folder = settings.data_dir / "blobs" / user_id / vault
    assert any(folder.rglob("*"))

    r = act(client, "vaults", vault, "purge", "Notes")
    assert (r.status_code, r.json()["error"]) == (409, "not_disabled")
    act(client, "vaults", vault, "disable")
    r = act(client, "vaults", vault, "purge", "notes")
    assert (r.status_code, r.json()["error"]) == (400, "confirm")
    assert act(client, "vaults", vault, "purge", "Notes").status_code == 204

    assert not any(p.is_file() for p in folder.rglob("*"))
    db = client.app.state.ctx.db
    assert db.one("SELECT COUNT(*) FROM vaults WHERE id = ?", vault)[0] == 0
    for table in ("files", "revisions", "blobs", "keyrings", "memberships"):
        assert db.one(f"SELECT COUNT(*) FROM {table} WHERE vault_id = ?", vault)[0] == 0  # noqa: S608
    assert [v["id"] for v in users(client)[0]["vaults"]] == [other]
    assert act(client, "vaults", vault, "purge", "Notes").status_code == 404
    # The name is free again.
    alice.create_vault("Notes")


def test_disable_enable_and_purge_a_user(client, alice, vault, settings):
    bob = Device(client, "bob")
    bob.login(SECRET)
    user_id = next(u["id"] for u in users(client) if u["username"] == "alice")

    assert act(client, "users", user_id, "disable").status_code == 204
    r = alice.get("/api/v1/vaults")
    assert (r.status_code, r.json()["error"]) == (403, "user_disabled")
    assert alice.login(expect=403)["error"] == "user_disabled"
    assert bob.get("/api/v1/vaults").status_code == 200

    assert act(client, "users", user_id, "enable").status_code == 204
    alice.login()
    assert alice.get(f"/api/v1/vaults/{vault}/changes").status_code == 200

    act(client, "users", user_id, "disable")
    assert act(client, "users", user_id, "purge", "alice").status_code == 204
    assert [u["username"] for u in users(client)] == ["bob"]
    assert not any(p.is_file() for p in (settings.data_dir / "blobs" / user_id).rglob("*"))
    db = client.app.state.ctx.db
    assert db.one("SELECT COUNT(*) FROM devices WHERE user_id = ?", user_id)[0] == 0
    assert db.one("SELECT COUNT(*) FROM sessions")[0] == 1  # bob's
    # The username can join again, as a new user.
    Device(client, "alice").login(SECRET)


def test_form_session_and_csrf(client, alice, vault):
    cookie, csrf = login(client)
    page = client.get("/admin", headers=cookie).text
    assert "alice" in page and "Notes" in page and "MacBook" in page

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
    assert "Disabled." in page and "type Notes to purge" in page

    r = client.post(
        f"/admin/vaults/{vault}/purge",
        headers=cookie,
        data={"csrf": csrf, "confirm": "Notes"},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/admin?done=purged"
    assert users(client)[0]["vaults"] == []

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
