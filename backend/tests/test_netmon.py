import dataclasses
import os
import re
import sqlite3
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient

from syncryption_server import netmon
from syncryption_server.app import create_app
from tests.helpers import ADMIN_TOKEN, SECRET, Device, blob

BEARER = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
MAC_AGENT = "VaultSyncryptionClient/37 CFNetwork/3826.400.120 Darwin/25.0.0"


def flush(client) -> None:
    state = client.app.state.ctx
    client.portal.call(state.netmon.flush, state)


def rows(client) -> list[sqlite3.Row]:
    flush(client)
    conn = sqlite3.connect(client.app.state.ctx.settings.data_dir / netmon.FILE)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM traffic ORDER BY minute, source").fetchall()
    finally:
        conn.close()


def by_source(client) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for r in rows(client):
        key = f"device:{r['device_id']}" if r["source"] == "device" else r["source"]
        totals = out.setdefault(key, dict.fromkeys(netmon.FIELDS, 0))
        for f in netmon.FIELDS:
            totals[f] += r[f]
    return out


def traffic(client, **params) -> dict:
    flush(client)
    r = client.get("/admin/api/network/traffic", headers=BEARER, params=params)
    assert r.status_code == 200, r.text
    return r.json()


def totals(client, **params) -> dict:
    flush(client)
    r = client.get("/admin/api/network/totals", headers=BEARER, params=params)
    assert r.status_code == 200, r.text
    return r.json()


def upload(device) -> bytes:
    blob_id, body = blob(os.urandom(32))
    url = f"/api/v1/vaults/{device.vault_id}/blobs/{blob_id}"
    assert device.put(url, content=body).status_code == 201
    assert device.get(url).content == body
    return body


def test_always_on_from_the_start(client, settings, clock):
    assert (settings.data_dir / netmon.FILE).exists()
    status = client.get("/admin/api/network", headers=BEARER).json()
    assert status["since"] == int(clock.t) and status["bytes"] > 0
    assert status["periods"] == [{"start": int(clock.t), "end": None}]


def test_counts_each_device_and_the_other_sources(client, alice, settings, clock):
    client.headers["user-agent"] = MAC_AGENT
    body = upload(alice)
    assert client.get("/health").status_code == 200
    client.get("/metrics")
    client.get("/admin/api/network", headers=BEARER)
    s = by_source(client)
    mine = s[f"device:{alice.device_id}"]
    assert mine["requests"] >= 3  # creating the vault, then the upload and download
    # Bodies plus the request lines and headers.
    assert mine["web_in"] > len(body) and mine["web_out"] > len(body)
    assert mine["s3_ops"] == 0  # local storage
    assert s["anonymous"]["requests"] == 3  # the login's challenge and verify, /health
    assert s["metrics"]["requests"] == 1
    assert s["admin"]["requests"] == 1
    status = client.get("/admin/api/network", headers=BEARER).json()
    assert status["rows"] > 0 and status["bytes"] > 0
    data = traffic(client, group="device")
    row = next(t for t in data["totals"] if t["key"] == f"device:{alice.device_id}")
    assert row["label"] == "alice / Personal / MacBook"
    assert row["client"] == "macOS client"


def test_s3_bytes_go_to_the_device_that_caused_them(settings, clock, s3_settings):
    settings = dataclasses.replace(settings, s3=s3_settings)
    with TestClient(create_app(settings, clock=clock), client=("127.0.0.1", 50000)) as c:
        d = Device(c, "alice", name="MacBook")
        d.login(SECRET)
        d.create_vault()
        body = upload(d)
        assert c.get("/health").status_code == 200
        state = c.app.state.ctx
        # Outside a request (the hourly cleanup): the server's.
        c.portal.call(state.store.exists, "blobs/x/y/ab/abcd")
        s = by_source(c)
    mine = s[f"device:{d.device_id}"]
    assert mine["s3_out"] == len(body) and mine["s3_in"] == len(body)
    assert mine["s3_ops"] >= 2
    assert s["anonymous"]["s3_ops"] == 1  # the /health ping
    assert s["server"]["s3_ops"] == 1 and s["server"]["s3_in"] == 0


def test_litestream_bytes_are_the_change_between_samples():
    m = netmon.NetMonitor(clock=lambda: 600.0)
    m.enabled = True
    samples = {
        "litestream_replica_operation_bytes_total": [
            ({"operation": "PUT"}, 1000.0),
            ({"operation": "GET"}, 10.0),
        ],
        "litestream_replica_operation_total": [({"operation": "PUT"}, 5.0)],
    }
    ls = SimpleNamespace(up=True, samples=samples)
    metrics = SimpleNamespace(litestream=ls)
    m._litestream_sample(metrics)
    assert m.pending == {}  # the first sample is the baseline
    samples["litestream_replica_operation_bytes_total"][0] = ({"operation": "PUT"}, 1500.0)
    samples["litestream_replica_operation_total"][0] = ({"operation": "PUT"}, 7.0)
    m._litestream_sample(metrics)
    assert m.pending == {(600, "litestream", ""): [0, 0, 0, 0, 500, 2]}


def test_monitoring_and_its_data_survive_a_restart(settings, clock):
    with TestClient(create_app(settings, clock=clock), client=("127.0.0.1", 50000)) as c:
        c.get("/health")
    clock.advance(600)
    with TestClient(create_app(settings, clock=clock), client=("127.0.0.1", 50000)) as c:
        status = c.get("/admin/api/network", headers=BEARER).json()
        assert status["since"] == int(clock.t)
        assert len(status["periods"]) == 2
        assert status["periods"][0]["end"] is not None and status["periods"][1]["end"] is None
        assert by_source(c)["anonymous"]["requests"] == 1


def test_graphs_bucket_by_minute_and_group(client, alice, clock):
    other = Device(client, "bob", name="Phone")
    other.login(SECRET)
    other.create_vault()
    upload(alice)
    clock.advance(120)
    upload(other)
    upload(other)
    data = traffic(client, group="device", start=int(clock.t) - 3600)
    assert data["step"] == 60
    assert len(data["times"]) == len(data["series"][0]["web_in"])
    series = {s["key"]: s for s in data["series"]}
    a, b = series[f"device:{alice.device_id}"], series[f"device:{other.device_id}"]
    # Each device's minutes: alice only the first, bob also two minutes later.
    busy_a = [i for i, v in enumerate(a["web_out"]) if v]
    busy_b = [i for i, v in enumerate(b["web_out"]) if v]
    assert busy_b == [busy_a[0], busy_a[0] + 2] and len(busy_a) == 1
    # The totals add up to the series, busiest first.
    keys = [t["key"] for t in data["totals"]]
    assert keys.index(f"device:{other.device_id}") < keys.index(f"device:{alice.device_id}")
    bob = data["totals"][keys.index(f"device:{other.device_id}")]
    assert sum(b["web_out"]) == bob["web_out"]
    summary = {s["window"]: s for s in data["summary"]}
    assert summary["all"]["web_out"] == sum(t["web_out"] for t in data["totals"])
    assert summary["hour"]["web_out"] == summary["all"]["web_out"]
    # By user, and only bob's.
    users = traffic(client, group="user")
    assert {t["label"] for t in users["totals"]} >= {"alice", "bob"}
    only = traffic(client, group="vault", filter=f"user:{other_user(client)}")
    assert [t["label"] for t in only["totals"]] == ["bob / Personal"]
    assert only["filterLabel"] == "bob"
    clients = traffic(client, group="client")
    assert "client:Other" in {t["key"] for t in clients["totals"]}
    sources = traffic(client, filter="admin")
    assert [t["key"] for t in sources["totals"]] == ["admin"]


def other_user(client) -> str:
    return next(
        u["id"]
        for u in client.get("/admin/api/users", headers=BEARER).json()["users"]
        if u["username"] == "bob"
    )


def test_long_ranges_take_bigger_steps(client, clock):
    client.get("/health")
    data = traffic(client, start=int(clock.t) - 30 * 86400)
    assert data["step"] == 3 * 3600
    assert len(data["times"]) <= netmon.MAX_POINTS
    # The whole monitored time by default.
    assert traffic(client)["step"] == 60


def test_totals_by_period(client, clock):
    client.get("/health")
    clock.advance(86400)
    client.get("/health")
    client.get("/health")
    days = totals(client, period="day", tz="UTC", filter="anonymous")
    assert [p["requests"] for p in days["periods"]] == [2, 1]
    assert days["more"] is False
    p = days["periods"][0]
    assert p["end"] - p["start"] == 86400 and p["start"] % 86400 == 0
    assert p["groups"][0]["key"] == "anonymous"
    hours = totals(client, period="hour", tz="Asia/Kolkata", filter="anonymous")
    assert hours["periods"][0]["start"] % 3600 == 1800  # +05:30
    assert sum(p["requests"] for p in hours["periods"]) == 2
    assert hours["more"] is True
    older = totals(
        client,
        period="hour",
        tz="Asia/Kolkata",
        filter="anonymous",
        before=hours["periods"][-1]["start"],
    )
    assert older["periods"][0]["end"] == hours["periods"][-1]["start"]
    weeks = totals(client, period="week", tz="UTC", filter="anonymous")
    months = totals(client, period="month", tz="UTC", filter="anonymous")
    assert sum(p["requests"] for p in weeks["periods"]) == 3
    assert sum(p["requests"] for p in months["periods"]) == 3
    r = client.get("/admin/api/network/totals", headers=BEARER, params={"tz": "Nowhere/Else"})
    assert r.status_code == 400
    r = client.get("/admin/api/network/traffic", headers=BEARER, params={"filter": "x:y"})
    assert r.status_code == 400


def test_periods_follow_the_calendar():
    zone = ZoneInfo("Europe/Berlin")
    # Sunday 2026-11-01 12:00 UTC.
    before = 1793534400
    months = netmon._periods("month", zone, before)
    assert months[0][0] == 1793487600  # November
    assert months[1] == (1790805600, 1793487600)  # October: 31 days and a DST change
    weeks = netmon._periods("week", zone, before)
    assert weeks[0][0] == 1792969200  # Monday 2026-10-26 00:00 CET
    assert weeks[1][1] - weeks[1][0] == 7 * 86400 + 3600  # the week of the change
    assert len(netmon._periods("day", zone, before)) == netmon.PERIODS_PAGE


def test_prune_and_auto_prune(client, clock, settings):
    client.get("/health")
    clock.advance(3 * 86400)
    client.get("/health")
    flush(client)
    r = client.post("/admin/api/network/prune", headers=BEARER, json={"olderThanDays": 1})
    assert r.status_code == 200 and r.json()["deletedRows"] >= 1
    assert by_source(client)["anonymous"]["requests"] == 1
    r = client.post("/admin/api/network/prune", headers=BEARER, json={"olderThanDays": -1})
    assert r.status_code == 400
    r = client.post("/admin/api/network", headers=BEARER, json={"autoPruneDays": 0})
    assert r.status_code == 400
    r = client.post("/admin/api/network", headers=BEARER, json={"autoPruneDays": 2})
    assert r.status_code == 204
    assert client.get("/admin/api/network", headers=BEARER).json()["autoPruneDays"] == 2
    clock.advance(3 * 86400)
    client.get("/health")
    state = client.app.state.ctx
    client.portal.call(state.netmon.tick, state)
    assert by_source(client)["anonymous"]["requests"] == 1
    r = client.post("/admin/api/network", headers=BEARER, json={"clearAutoPrune": True})
    assert r.status_code == 204
    assert client.get("/admin/api/network", headers=BEARER).json()["autoPruneDays"] is None
    r = client.post("/admin/api/network/prune", headers=BEARER, json={"olderThanDays": 0})
    assert r.status_code == 200
    assert client.get("/admin/api/network", headers=BEARER).json()["rows"] == 0


def login(client) -> tuple[dict[str, str], str]:
    r = client.post("/admin/login", data={"token": ADMIN_TOKEN}, follow_redirects=False)
    cookie = {"cookie": r.headers["set-cookie"].split(";")[0]}
    page = client.get("/admin?tab=network", headers=cookie)
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    return cookie, csrf


def test_the_network_tab_and_its_forms(client):
    cookie, csrf = login(client)
    page = client.get("/admin?tab=network", headers=cookie)
    assert page.status_code == 200
    assert "Recording since" in page.text and 'src="/admin/network.js"' in page.text
    assert 'value="mtd"' in page.text and 'id="flow"' in page.text
    assert "script-src 'self'" in page.headers["content-security-policy"]
    r = client.post(
        "/admin/network/prune",
        data={"csrf": "nope", "days": "1"},
        headers=cookie,
        follow_redirects=False,
    )
    assert r.headers["location"] == "/admin?tab=network&done=csrf"
    r = client.post(
        "/admin/network/prune",
        data={"csrf": csrf, "days": "x"},
        headers=cookie,
        follow_redirects=False,
    )
    assert r.headers["location"].endswith("done=bad_days")
    r = client.post(
        "/admin/network/auto-prune",
        data={"csrf": csrf, "days": "7"},
        headers=cookie,
        follow_redirects=False,
    )
    assert r.headers["location"].endswith("done=netmon_auto")
    assert (
        "older than 7 days is deleted automatically"
        in client.get("/admin?tab=network", headers=cookie).text
    )
    r = client.post(
        "/admin/network/prune",
        data={"csrf": csrf, "days": "0"},
        headers=cookie,
        follow_redirects=False,
    )
    assert r.headers["location"].endswith("done=netmon_pruned")
    data = client.get("/admin/network.json", headers=cookie)
    assert data.status_code == 200 and data.json()["status"]["since"]
    assert data.headers["cache-control"] == "no-store"
    period = client.get("/admin/network-totals.json?period=week&tz=UTC", headers=cookie)
    assert period.status_code == 200
    assert client.get("/admin/network.json").status_code == 401
    assert client.get("/admin/network.js").status_code == 200


def test_the_api_needs_the_token(client):
    assert client.get("/admin/api/network").status_code == 401
    assert client.post("/admin/api/network", json={"autoPruneDays": 1}).status_code == 401
    assert client.get("/admin/api/network/traffic").status_code == 401


@pytest.mark.parametrize(
    ("agent", "kind"),
    [
        (MAC_AGENT, "macOS client"),
        ("Mozilla/5.0 (Macintosh) AppleWebKit obsidian/1.9.10 Electron/37", "Obsidian"),
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X)", "Obsidian"),
        ("curl/8.7.1", "Other"),
    ],
)
def test_client_kind(agent, kind):
    assert netmon.client_kind(agent) == kind


def test_demo_mode_cant_delete_or_change_it(settings, clock):
    settings = dataclasses.replace(settings, demo_mode=True)
    with TestClient(create_app(settings, clock=clock), client=("127.0.0.1", 50000)) as c:
        assert c.post("/admin/api/network", json={"autoPruneDays": 1}).status_code == 403
        r = c.post("/admin/api/network/prune", json={"olderThanDays": 0})
        assert r.status_code == 403
        assert "Delete data older" not in c.get("/admin?tab=network").text
