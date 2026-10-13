"""Per-vault storage quotas and the free-disk reserve (docs/protocol.md 12)."""

import re
import shutil
from collections import namedtuple

from syncryption_server import blobs
from syncryption_server.admin import GB
from syncryption_server.blobs import DISK_RESERVE, collect_garbage
from tests.helpers import ADMIN_TOKEN, META, blob, file_id

BEARER = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
Usage = namedtuple("Usage", "total used free")


def put(device, data: bytes):
    blob_id, body = blob(data)
    return device.put(f"/api/v1/vaults/{device.vault_id}/blobs/{blob_id}", content=body)


def commit(device, blob_ids: list[str], n: int = 0, parent: int | None = None, deleted=False):
    return device.put(
        f"/api/v1/vaults/{device.vault_id}/files/{file_id(n)}",
        json={"parentRev": parent, "deleted": deleted, "meta": META, "blobs": blob_ids},
    )


def set_quota(client, vault_id: str, quota: int | None):
    path = f"/admin/api/vaults/{vault_id}/quota"
    return client.post(path, headers=BEARER, json={"quotaBytes": quota})


def vault_info(client) -> dict:
    users = client.get("/admin/api/users", headers=BEARER).json()["users"]
    return users[0]["vaults"][0]


def test_vaults_have_no_quota_by_default(client, alice):
    assert vault_info(client)["quota"] is None
    for i in range(5):
        assert put(alice, bytes([i]) * 1000).status_code == 201
    assert vault_info(client)["size"] == 5000


def test_quota_refuses_new_blobs_past_it(client, alice):
    assert put(alice, b"a" * 600).status_code == 201
    assert set_quota(client, alice.vault_id, 1000).status_code == 204
    assert vault_info(client)["quota"] == 1000

    r = put(alice, b"b" * 500)
    assert r.status_code == 507
    assert r.json()["error"] == "quota_exceeded"
    assert r.json()["details"] == {"quota": 1000, "used": 600}
    # A blob that is already stored takes no space; one that fits is still taken.
    assert put(alice, b"a" * 600).status_code == 200
    assert put(alice, b"c" * 400).status_code == 201
    assert put(alice, b"d").status_code == 507

    # Back to unlimited.
    assert set_quota(client, alice.vault_id, None).status_code == 204
    assert put(alice, b"d").status_code == 201


def test_garbage_collection_frees_quota(client, clock, alice):
    blob_id, data = blob(b"x" * 800)
    alice.put(f"/api/v1/vaults/{alice.vault_id}/blobs/{blob_id}", content=data)
    set_quota(client, alice.vault_id, 1000)
    assert put(alice, b"y" * 800).status_code == 507
    clock.advance(24 * 3600 + 1)
    alice.login()
    assert client.portal.call(collect_garbage, client.app.state.ctx) == 1
    assert vault_info(client)["size"] == 0
    assert put(alice, b"y" * 800).status_code == 201


def test_quota_is_per_vault(client, alice):
    from tests.test_admin import second_vault

    other = second_vault(client)
    set_quota(client, alice.vault_id, 10)
    assert put(alice, b"z" * 100).status_code == 507
    assert put(other, b"z" * 100).status_code == 201


def test_admin_api_validates_the_quota(client, alice):
    path = f"/admin/api/vaults/{alice.vault_id}/quota"
    assert client.post(path, json={"quotaBytes": 5}).status_code == 401
    for bad in (0, -1, 2**51):
        assert set_quota(client, alice.vault_id, bad).status_code == 400
    assert set_quota(client, "nope", None).status_code == 404


def test_admin_quota_form(client, alice):
    r = client.post("/admin/login", data={"token": ADMIN_TOKEN}, follow_redirects=False)
    cookie = {"cookie": r.headers["set-cookie"].split(";")[0]}
    page = client.get("/admin", headers=cookie).text
    assert 'aria-label="Storage quota in GB"' in page
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    path = f"/admin/vaults/{alice.vault_id}/quota"

    def post(data: dict) -> str:
        return client.post(path, headers=cookie, data=data, follow_redirects=False).headers[
            "location"
        ]

    assert post({"csrf": csrf, "gb": "5"}) == "/admin?done=quota_set"
    assert vault_info(client)["quota"] == 5 * GB
    assert 'value="5"' in client.get("/admin", headers=cookie).text
    for bad in ("0", "x", "-1", "1.5"):
        assert post({"csrf": csrf, "gb": bad}) == "/admin?done=bad_quota"
    assert post({"csrf": csrf, "gb": ""}) == "/admin?done=quota_set"
    assert vault_info(client)["quota"] is None
    assert post({"gb": "5"}) == "/admin?done=csrf"
    assert vault_info(client)["quota"] is None


def test_disk_reserve_refuses_uploads_and_commits(client, alice, monkeypatch):
    blob_id, data = blob(b"stored before")
    alice.put(f"/api/v1/vaults/{alice.vault_id}/blobs/{blob_id}", content=data)
    assert commit(alice, [blob_id]).status_code == 201

    real = shutil.disk_usage
    monkeypatch.setattr(
        blobs.shutil,
        "disk_usage",
        lambda p: Usage(real(p).total, real(p).total - DISK_RESERVE + 1, DISK_RESERVE - 1),
    )
    r = put(alice, b"new")
    assert (r.status_code, r.json()["error"]) == (507, "storage_full")
    # Re-uploading a stored blob takes no space.
    r = alice.put(f"/api/v1/vaults/{alice.vault_id}/blobs/{blob_id}", content=data)
    assert r.status_code == 200
    assert commit(alice, [blob_id], n=1).json()["error"] == "storage_full"
    # Deleting a file still works.
    assert commit(alice, [], parent=1, deleted=True).status_code == 201

    monkeypatch.setattr(
        blobs.shutil, "disk_usage", lambda p: Usage(DISK_RESERVE * 2, 0, DISK_RESERVE)
    )
    assert put(alice, b"new").status_code == 201
    assert commit(alice, [blob_id], n=1).status_code == 201
