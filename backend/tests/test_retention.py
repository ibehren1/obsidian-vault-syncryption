"""History retention (protocol.md 9.3): which revisions `prune` drops, and what clients see."""

import pytest

from syncryption_server import retention
from syncryption_server.blobs import collect_garbage
from syncryption_server.encoding import b64u
from syncryption_server.retention import prune
from tests.helpers import Device, blob, file_id, meta

DAY = 24 * 3600


@pytest.fixture
def vault(alice) -> str:
    return alice.vault_id


@pytest.fixture
def run(client):
    """Run a coroutine function with the app's state, on the app's event loop."""
    state = client.app.state.ctx
    return lambda fn: client.portal.call(fn, state)


def later(clock, dev: Device, days: float) -> None:
    clock.advance(days * DAY)
    dev.login()  # the session has expired by then


def commit(dev, vault_id, fid, parent, *, epoch=1, deleted=False, data=None):
    blobs = []
    if data is not None:
        blob_id, body = blob(data)
        dev.put(f"/api/v1/vaults/{vault_id}/blobs/{blob_id}", content=body)
        blobs = [blob_id]
    r = dev.put(
        f"/api/v1/vaults/{vault_id}/files/{fid}",
        json={
            "parentRev": parent,
            "deleted": deleted,
            "meta": meta(b"v", epoch),
            "blobs": blobs,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["rev"]


def versions(dev, vault_id, fid=None, n=1, **kw) -> list[int]:
    """Commit n versions of a file; returns their revs."""
    fid = fid or file_id()
    head = dev.get(f"/api/v1/vaults/{vault_id}/files/{fid}")
    parent = head.json()["rev"] if head.status_code == 200 else None
    revs = []
    for _ in range(n):
        parent = commit(dev, vault_id, fid, parent, **kw)
        revs.append(parent)
    return revs


def history(dev, vault_id, fid=None) -> list[int]:
    r = dev.get(f"/api/v1/vaults/{vault_id}/files/{fid or file_id()}/revs?limit=100").json()
    return [x["rev"] for x in r["revisions"]]


def test_every_version_is_kept_for_30_days(clock, alice, vault, run):
    revs = versions(alice, vault, n=15)
    later(clock, alice, 29)
    assert run(prune) == 0
    later(clock, alice, 2)
    assert run(prune) == 5  # the last 10 stay
    assert history(alice, vault) == revs[5:][::-1]
    assert run(prune) == 0


def test_the_last_10_versions_are_kept(clock, alice, vault, run):
    versions(alice, vault, n=10)
    later(clock, alice, 365)
    assert run(prune) == 0
    assert len(history(alice, vault)) == 10


def test_recent_versions_beyond_10_are_kept(clock, alice, vault, run):
    old = versions(alice, vault, n=12)
    later(clock, alice, 31)
    new = versions(alice, vault, n=3)
    assert run(prune) == 5  # old versions 11 and older (from the newest)
    assert history(alice, vault) == (old[5:] + new)[::-1]
    later(clock, alice, 365)
    assert run(prune) == 0  # 10 left


def test_deleted_files_keep_only_the_tombstone_after_90_days(clock, alice, vault, run):
    revs = versions(alice, vault, n=3, data=b"content")
    tomb = commit(alice, vault, file_id(), revs[-1], deleted=True)
    later(clock, alice, 89)
    assert run(prune) == 0
    later(clock, alice, 2)
    assert run(prune) == 3
    assert history(alice, vault) == [tomb]
    for rev in revs:
        r = alice.get(f"/api/v1/vaults/{vault}/files/{file_id()}/revs/{rev}")
        assert (r.status_code, r.json()["error"]) == (404, "not_found")
    later(clock, alice, 365)
    assert run(prune) == 0  # the tombstone is the head: kept for ever
    # Re-creating the file uses the tombstone as its parent.
    again = commit(alice, vault, file_id(), tomb, data=b"new content")
    assert history(alice, vault) == [again, tomb]


def test_a_recreated_file_is_not_purged(clock, alice, vault, run):
    revs = versions(alice, vault, n=2)
    tomb = commit(alice, vault, file_id(), revs[-1], deleted=True)
    again = commit(alice, vault, file_id(), tomb)
    later(clock, alice, 91)
    assert run(prune) == 0
    assert history(alice, vault) == [again, tomb, *revs[::-1]]


def test_old_epochs_go_30_days_after_a_newer_one(clock, alice, vault, run):
    versions(alice, vault, n=3, epoch=1)
    other = versions(alice, vault, fid=file_id(1), n=3, epoch=1)  # not re-encrypted yet
    later(clock, alice, 40)
    new = versions(alice, vault, n=1, epoch=2)  # the rotation's re-encryption
    later(clock, alice, 29)
    assert run(prune) == 0
    later(clock, alice, 2)
    assert run(prune) == 3
    assert history(alice, vault) == new
    assert history(alice, vault, file_id(1)) == other[::-1]


def test_an_old_epoch_head_is_kept(clock, alice, vault, run):
    # A newer epoch, then a device still on the old one commits: the head is never pruned.
    first = versions(alice, vault, n=1, epoch=2)
    head = versions(alice, vault, n=1, epoch=1)
    later(clock, alice, 31)
    assert run(prune) == 0
    assert history(alice, vault) == head + first


def test_pruned_blobs_are_collected_in_the_same_pass(clock, alice, vault, run):
    parent = versions(alice, vault, n=11)[-1]
    blob_ids = []
    for i in range(2):
        parent = commit(alice, vault, file_id(), parent, data=f"chunk {i}".encode())
        blob_ids.append(blob(f"chunk {i}".encode())[0])
    versions(alice, vault, n=9)  # 22 versions: the newest 10 include only chunk 1's
    later(clock, alice, 31)
    assert run(collect_garbage) == 0  # still referenced
    assert run(prune) == 12
    assert run(collect_garbage) == 1  # chunk 0; chunk 1 is in a kept version
    blob_url = f"/api/v1/vaults/{vault}/blobs"
    assert alice.head(f"{blob_url}/{blob_ids[0]}").status_code == 404
    assert alice.head(f"{blob_url}/{blob_ids[1]}").status_code == 200


def test_history_and_feed_with_gaps(clock, alice, vault, run):
    a = versions(alice, vault, n=13)
    b = versions(alice, vault, fid=file_id(1), n=2)
    later(clock, alice, 31)
    assert run(prune) == 3
    kept = a[3:]
    page = alice.get(f"/api/v1/vaults/{vault}/files/{file_id()}/revs?limit=4").json()
    assert [x["rev"] for x in page["revisions"]] == kept[::-1][:4] and page["more"]
    rest = alice.get(
        f"/api/v1/vaults/{vault}/files/{file_id()}/revs?before={kept[-4]}&limit=100"
    ).json()
    assert [x["rev"] for x in rest["revisions"]] == kept[::-1][4:] and not rest["more"]

    feed = alice.get(f"/api/v1/vaults/{vault}/changes?since=0&limit=5").json()
    assert [c["rev"] for c in feed["changes"]] == kept[:5]
    assert feed["cursor"] == kept[4] and feed["more"]
    feed = alice.get(f"/api/v1/vaults/{vault}/changes?since={feed['cursor']}").json()
    assert [c["rev"] for c in feed["changes"]] == kept[5:] + b
    assert not feed["more"]


def test_prune_works_in_batches(clock, alice, vault, run, monkeypatch):
    monkeypatch.setattr(retention, "BATCH", 2)
    revs = versions(alice, vault, n=15)
    later(clock, alice, 31)
    assert run(prune) == 5
    assert history(alice, vault) == revs[5:][::-1]


@pytest.mark.parametrize(
    "data",
    [
        b"ciphertext",  # no header
        b"\x01",  # too short
        b"\x01\x00\x00\x00",
        b"\x02\x00\x00\x00\x01ciphertext",  # another format
        b"\x01\x00\x00\x00\x00ciphertext",  # epoch 0
    ],
)
def test_malformed_meta_header_is_refused(alice, vault, data):
    body = {"parentRev": None, "meta": b64u(data), "blobs": []}
    r = alice.put(f"/api/v1/vaults/{vault}/files/{file_id()}", json=body)
    assert (r.status_code, r.json()["error"]) == (422, "malformed")


def test_the_epoch_is_stored(client, alice, vault):
    versions(alice, vault, n=1, epoch=7)
    row = client.app.state.ctx.db.one("SELECT epoch FROM revisions")
    assert row[0] == 7
