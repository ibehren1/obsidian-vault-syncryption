import hashlib

from syncryption_server.blobs import MAX_BLOB_SIZE, collect_garbage
from tests.helpers import META, SECRET, Device, blob, file_id


def test_upload_and_download(client, alice, settings):
    vault_id = alice.vault_id
    blob_id, data = blob(b"encrypted chunk")
    url = f"/api/v1/vaults/{vault_id}/blobs/{blob_id}"
    assert alice.head(url).status_code == 404

    r = alice.put(url, content=data)
    assert r.status_code == 201
    assert r.json() == {"id": blob_id, "size": len(data)}
    assert alice.put(url, content=data).status_code == 200

    h = alice.head(url)
    assert h.status_code == 200 and h.headers["content-length"] == str(len(data))
    g = alice.get(url)
    assert g.content == data
    assert g.headers["content-type"] == "application/octet-stream"

    user_id = client.app.state.ctx.db.one("SELECT user_id FROM vaults")[0]
    path = settings.data_dir / "blobs" / user_id / vault_id / blob_id[:2] / blob_id
    assert path.read_bytes() == data


def test_hash_mismatch_and_bad_ids(client, alice):
    vault_id = alice.vault_id
    blob_id, _ = blob(b"one")
    r = alice.put(f"/api/v1/vaults/{vault_id}/blobs/{blob_id}", content=b"two")
    assert (r.status_code, r.json()["error"]) == (422, "hash_mismatch")
    r = alice.put(f"/api/v1/vaults/{vault_id}/blobs/{blob_id.upper()}", content=b"one")
    assert r.status_code == 400


def test_size_limit(client, alice):
    vault_id = alice.vault_id
    data = b"\0" * (MAX_BLOB_SIZE + 1)
    r = alice.put(
        f"/api/v1/vaults/{vault_id}/blobs/{hashlib.sha256(data).hexdigest()}", content=data
    )
    assert (r.status_code, r.json()["error"]) == (413, "too_large")
    data = b"\0" * MAX_BLOB_SIZE
    r = alice.put(
        f"/api/v1/vaults/{vault_id}/blobs/{hashlib.sha256(data).hexdigest()}", content=data
    )
    assert r.status_code == 201


def test_missing(client, alice):
    vault_id = alice.vault_id
    a, data = blob(b"a")
    b, _ = blob(b"b")
    alice.put(f"/api/v1/vaults/{vault_id}/blobs/{a}", content=data)
    r = alice.post(f"/api/v1/vaults/{vault_id}/blobs/missing", json={"ids": [a, b, b]})
    assert r.json() == {"missing": [b]}
    r = alice.post(f"/api/v1/vaults/{vault_id}/blobs/missing", json={"ids": [a] * 1001})
    assert r.status_code == 400


def test_blobs_are_scoped_per_vault(client, alice):
    one = alice.vault_id
    work = Device(client, "alice", vault_name="Work")
    work.login(SECRET)
    two = work.create_vault()
    blob_id, data = blob(b"secret")
    alice.put(f"/api/v1/vaults/{one}/blobs/{blob_id}", content=data)
    assert work.head(f"/api/v1/vaults/{two}/blobs/{blob_id}").status_code == 404
    assert work.get(f"/api/v1/vaults/{one}/blobs/{blob_id}").status_code == 403
    bob = Device(client, "bob")
    bob.login(SECRET)
    bob.create_vault()
    assert bob.get(f"/api/v1/vaults/{one}/blobs/{blob_id}").status_code == 403


def test_garbage_collection(client, clock, alice):
    vault_id = alice.vault_id
    kept, kept_data = blob(b"kept")
    orphan, orphan_data = blob(b"orphan")
    for blob_id, data in ((kept, kept_data), (orphan, orphan_data)):
        alice.put(f"/api/v1/vaults/{vault_id}/blobs/{blob_id}", content=data)
    alice.put(
        f"/api/v1/vaults/{vault_id}/files/{file_id()}",
        json={"parentRev": None, "meta": META, "blobs": [kept]},
    )
    state = client.app.state.ctx
    run = client.portal.call  # the app's event loop, where the database lives
    assert run(collect_garbage, state) == 0  # inside the grace period
    clock.advance(24 * 3600 + 1)
    alice.login()
    assert run(collect_garbage, state) == 1
    assert alice.head(f"/api/v1/vaults/{vault_id}/blobs/{kept}").status_code == 200
    assert alice.head(f"/api/v1/vaults/{vault_id}/blobs/{orphan}").status_code == 404
