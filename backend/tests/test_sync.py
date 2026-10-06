import threading
import time

import pytest

from tests.helpers import META, Device, blob, file_id, meta


@pytest.fixture
def vault(alice) -> str:
    return alice.vault_id


def upload(dev: Device, vault_id: str, data: bytes) -> str:
    blob_id, body = blob(data)
    assert dev.put(f"/api/v1/vaults/{vault_id}/blobs/{blob_id}", content=body).status_code in (
        200,
        201,
    )
    return blob_id


def commit(dev, vault_id, fid, parent, blobs=(), meta=META, deleted=False):
    return dev.put(
        f"/api/v1/vaults/{vault_id}/files/{fid}",
        json={"parentRev": parent, "deleted": deleted, "meta": meta, "blobs": list(blobs)},
    )


def test_commit_and_head(alice, vault):
    a = upload(alice, vault, b"chunk a")
    b = upload(alice, vault, b"chunk bb")
    r = commit(alice, vault, file_id(), None, [a, b])
    assert r.status_code == 201
    rev = r.json()
    assert rev["rev"] == 1
    assert rev["parentRev"] is None
    assert rev["blobs"] == [a, b]
    assert rev["size"] == 9 + 7 + 8  # meta + blobs
    assert rev["device"] == alice.device_id
    assert alice.get(f"/api/v1/vaults/{vault}/files/{file_id()}").json() == rev


def test_stale_parent_returns_the_head(alice, vault):
    first = commit(alice, vault, file_id(), None).json()
    second = commit(alice, vault, file_id(), first["rev"], meta=meta(b"v2")).json()

    r = commit(alice, vault, file_id(), first["rev"], meta=meta(b"v3"))
    assert r.status_code == 409
    body = r.json()
    assert body["error"] == "stale_parent"
    assert body["details"]["head"] == second

    r = commit(alice, vault, file_id(), None)
    assert r.status_code == 409  # "must not exist yet"
    r = commit(alice, vault, file_id(1), 5)
    assert r.status_code == 409
    assert r.json()["details"]["head"] is None


def test_missing_blobs(alice, vault):
    present = upload(alice, vault, b"here")
    absent, _ = blob(b"not uploaded")
    r = commit(alice, vault, file_id(), None, [present, absent])
    assert (r.status_code, r.json()["error"]) == (422, "missing_blobs")
    assert r.json()["details"] == {"missing": [absent]}
    assert alice.get(f"/api/v1/vaults/{vault}/files/{file_id()}").status_code == 404


def test_validation(alice, vault):
    cases = [
        (file_id(), {"parentRev": None, "meta": "", "blobs": []}, 400),
        (file_id(), {"parentRev": None, "meta": "a=", "blobs": []}, 400),
        (file_id(), {"parentRev": None, "meta": META, "blobs": ["XY"]}, 400),
        ("short", {"parentRev": None, "meta": META, "blobs": []}, 400),
        (file_id(), {"parentRev": None, "meta": "A" * (90 * 1024), "blobs": []}, 413),
    ]
    for fid, body, status in cases:
        assert alice.put(f"/api/v1/vaults/{vault}/files/{fid}", json=body).status_code == status


def test_delete_and_recreate(alice, vault):
    a = upload(alice, vault, b"content")
    first = commit(alice, vault, file_id(), None, [a]).json()
    assert commit(alice, vault, file_id(), first["rev"], [a], deleted=True).status_code == 400
    tomb = commit(alice, vault, file_id(), first["rev"], deleted=True).json()
    assert tomb["deleted"] is True and tomb["blobs"] == []
    again = commit(alice, vault, file_id(), tomb["rev"], [a])
    assert again.status_code == 201


def test_history(alice, vault):
    parent = None
    for i in range(5):
        parent = commit(alice, vault, file_id(), parent, meta=meta(f"v{i}".encode())).json()["rev"]
        commit(alice, vault, file_id(1), parent - 1 if i else None)  # interleave another file
    r = alice.get(f"/api/v1/vaults/{vault}/files/{file_id()}/revs?limit=2").json()
    revs = [x["rev"] for x in r["revisions"]]
    assert revs == sorted(revs, reverse=True) and len(revs) == 2 and r["more"] is True
    older = alice.get(
        f"/api/v1/vaults/{vault}/files/{file_id()}/revs?before={revs[-1]}&limit=50"
    ).json()
    assert len(older["revisions"]) == 3 and older["more"] is False
    one = alice.get(f"/api/v1/vaults/{vault}/files/{file_id()}/revs/{revs[0]}")
    assert one.json()["rev"] == revs[0]
    other = alice.get(f"/api/v1/vaults/{vault}/files/{file_id(1)}/revs/{revs[0]}")
    assert other.status_code == 404


def test_change_feed_is_ordered_and_paged(alice, vault):
    heads: dict[int, int | None] = {}
    for i in range(12):
        fid = i % 4
        heads[fid] = commit(alice, vault, file_id(fid), heads.get(fid)).json()["rev"]

    page = alice.get(f"/api/v1/vaults/{vault}/changes?since=0&limit=5").json()
    assert [c["rev"] for c in page["changes"]] == [1, 2, 3, 4, 5]
    assert page["cursor"] == 5 and page["more"] is True
    rest = alice.get(f"/api/v1/vaults/{vault}/changes?since=5").json()
    assert [c["rev"] for c in rest["changes"]] == list(range(6, 13))
    assert rest["cursor"] == 12 and rest["more"] is False
    assert rest["changes"][0]["meta"] == META
    empty = alice.get(f"/api/v1/vaults/{vault}/changes?since=12").json()
    assert empty == {"changes": [], "cursor": 12, "more": False, "keyringVersion": 1}
    assert alice.get(f"/api/v1/vaults/{vault}/changes?limit=1001").status_code == 400


def test_concurrent_commits_get_one_winner(client, alice, vault):
    phone = Device(client, "alice")
    phone.join(alice)
    base = commit(alice, vault, file_id(), None).json()["rev"]

    results = []

    def push(dev):
        results.append(commit(dev, vault, file_id(), base).status_code)

    threads = [threading.Thread(target=push, args=(d,)) for d in (alice, phone, alice, phone)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [201, 409, 409, 409]


def test_wait_returns_on_commit(client, alice, vault):
    out = {}

    def waiter():
        start = time.monotonic()
        out["body"] = alice.get(f"/api/v1/vaults/{vault}/wait?since=0&timeout=10").json()
        out["took"] = time.monotonic() - start

    t = threading.Thread(target=waiter)
    t.start()
    time.sleep(0.2)
    commit(alice, vault, file_id(), None)
    t.join(5)
    assert out["body"] == {"seq": 1, "locksSeq": 0, "keyringVersion": 1, "changed": True}
    assert out["took"] < 5


def test_wait_returns_at_once_if_already_ahead(alice, vault):
    commit(alice, vault, file_id(), None)
    r = alice.get(f"/api/v1/vaults/{vault}/wait?since=0&timeout=10").json()
    assert r["changed"] is True


def test_wait_times_out(alice, vault):
    r = alice.get(f"/api/v1/vaults/{vault}/wait?since=0&timeout=0.2").json()
    assert r == {"seq": 0, "locksSeq": 0, "keyringVersion": 1, "changed": False}
    assert alice.get(f"/api/v1/vaults/{vault}/wait?timeout=26").status_code == 400


def test_wait_returns_on_a_new_keyring(alice, vault):
    out = {}

    def waiter():
        out["body"] = alice.get(
            f"/api/v1/vaults/{vault}/wait?since=0&keyringSince=1&timeout=10"
        ).json()

    t = threading.Thread(target=waiter)
    t.start()
    time.sleep(0.2)
    assert alice.put(f"/api/v1/vaults/{vault}/keyring", json=alice.keyring(2)).status_code == 201
    t.join(5)
    assert out["body"] == {"seq": 0, "locksSeq": 0, "keyringVersion": 2, "changed": True}
    changes = alice.get(f"/api/v1/vaults/{vault}/changes?since=0").json()
    assert changes["keyringVersion"] == 2
    # Without keyringSince, a keyring version doesn't count as a change.
    r = alice.get(f"/api/v1/vaults/{vault}/wait?since=0&timeout=0.2").json()
    assert r["changed"] is False


def test_third_wait_releases_the_oldest(alice, vault):
    out: list[tuple[int, dict]] = []

    def waiter(n):
        out.append((n, alice.get(f"/api/v1/vaults/{vault}/wait?since=0&timeout=3").json()))

    threads = []
    for n in range(3):
        t = threading.Thread(target=waiter, args=(n,))
        t.start()
        threads.append(t)
        time.sleep(0.2)
    threads[0].join(2)
    assert out and out[0][0] == 0 and out[0][1]["changed"] is False
    commit(alice, vault, file_id(), None)
    for t in threads:
        t.join(5)
    assert sorted(n for n, body in out if body["changed"]) == [1, 2]
