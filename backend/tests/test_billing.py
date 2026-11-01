import os
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from syncryption_server import billing, netmon
from syncryption_server.app import create_app
from tests.helpers import ADMIN_TOKEN, SECRET, Device, blob

BEARER = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
GB = 2**30
# The FakeClock starts in September 2026 (UTC).
MONTH = "2026-09"


def call(client, fn, *args):
    return client.portal.call(fn, *args)


def state(client):
    return client.app.state.ctx


def sample(client) -> None:
    call(client, billing.sample, state(client))


def report(client, month: str = MONTH) -> dict:
    s = state(client)
    call(client, s.netmon.flush, s)
    r = client.get("/admin/api/billing", headers=BEARER, params={"month": month})
    assert r.status_code == 200, r.text
    return r.json()


def write(client, sql: str, *params) -> None:
    db = state(client).db

    def run() -> None:
        with db.transaction() as conn:
            conn.execute(sql, params)

    call(client, db.run, run)


def vault_line(r: dict, username: str, vault: str) -> dict:
    user = next(u for u in r["users"] if u["username"] == username)
    return next(v for v in user["vaults"] if v["vaultName"] == vault)


def upload(device, size: int = 1000) -> bytes:
    blob_id, body = blob(os.urandom(size))
    url = f"/api/v1/vaults/{device.vault_id}/blobs/{blob_id}"
    assert device.put(url, content=body).status_code == 201
    return body


def test_months_are_calendar_months_in_utc():
    start, end = billing.month_bounds("2026-02")
    assert (end - start) == 28 * 86400 and start == 1769904000
    assert billing.month_bounds("2024-02")[1] - billing.month_bounds("2024-02")[0] == 29 * 86400
    for bad in ("2026-13", "2026-1", "x", "1969-12"):
        with pytest.raises(billing.BillingError):
            billing.month_bounds(bad)


def test_sampling_records_each_vault_and_the_server(client, alice, clock):
    body = upload(alice)
    sample(client)
    conn = sqlite3.connect(state(client).settings.db_path)
    rows = conn.execute("SELECT vault_id, store, bytes FROM storage_samples").fetchall()
    names = conn.execute("SELECT username, vault_name FROM billing_vaults").fetchall()
    conn.close()
    by_vault = {v: (store, n) for v, store, n in rows}
    assert by_vault[alice.vault_id] == ("local", len(body))
    assert by_vault[""][0] == "local" and by_vault[""][1] > 0  # meta.db, netmon.db
    assert names == [("alice", "Personal")]


def test_storage_is_billed_per_gb_month(client, alice, clock):
    start, end = billing.month_bounds(MONTH)
    hour = int(clock.t) // 3600 * 3600
    # 2 GB from the first hour of the month, 4 GB for the last 10 hours up to now.
    write(
        client,
        "INSERT INTO storage_samples VALUES (?, ?, 'local', ?)",
        start,
        alice.vault_id,
        2 * GB,
    )
    write(
        client,
        "INSERT INTO storage_samples VALUES (?, ?, 's3', ?)",
        hour - 36000,
        alice.vault_id,
        4 * GB,
    )
    write(
        client,
        "INSERT OR REPLACE INTO billing_vaults VALUES (?, ?, 'alice', 'Personal')",
        alice.vault_id,
        "u",
    )
    r = report(client)
    assert r["current"] and r["elapsedSeconds"] == int(clock.t) - start
    line = vault_line(r, "alice", "Personal")
    month = end - start
    assert line["localGbMonths"] == pytest.approx(2 * (hour - 36000 - start) / month)
    assert line["s3GbMonths"] == pytest.approx(4 * (int(clock.t) - hour + 36000) / month)
    assert line["storageCost"] == pytest.approx(
        line["localGbMonths"] * 0.08 + line["s3GbMonths"] * 0.023
    )
    # A past month without samples of its own is billed from the last one before it.
    write(client, "DELETE FROM storage_samples WHERE hour > ?", start)
    october = report(client, "2026-08")
    assert october["users"] == [] and october["total"]["total"] == 0


def test_a_purged_vault_stops_costing(client, alice, clock):
    upload(alice, 5000)
    sample(client)
    clock.advance(7200)
    write(client, "UPDATE vaults SET blob_bytes = 0")  # as if purged: no bytes from here
    sample(client)
    clock.advance(7200)
    r = report(client)
    line = vault_line(r, "alice", "Personal")
    start, end = billing.month_bounds(MONTH)
    assert line["localGbMonths"] == pytest.approx(5000 * 7200 / GB / (end - start), rel=0.01)


def test_outbound_goes_to_the_vault_and_its_user(client, alice):
    other = Device(client, "alice", vault_name="Work", name="Laptop")
    other.login(SECRET)
    other.create_vault()
    body = upload(alice, 50_000)
    blob_id = blob(body)[0]
    for _ in range(3):
        alice.get(f"/api/v1/vaults/{alice.vault_id}/blobs/{blob_id}")
    upload(other)
    client.get("/health")
    sample(client)
    r = report(client)
    personal, work = vault_line(r, "alice", "Personal"), vault_line(r, "alice", "Work")
    assert personal["transferBytes"] > 3 * 50_000 > work["transferBytes"] > 0
    assert personal["transferCost"] == pytest.approx(personal["transferBytes"] / GB * 0.09)
    [user] = r["users"]
    assert user["total"] == pytest.approx(personal["total"] + work["total"])
    assert r["server"]["transferBytes"] > 0  # the logins and /health
    assert r["server"]["localGbMonths"] > 0
    assert r["total"]["total"] == pytest.approx(user["total"] + r["server"]["total"])
    assert r["monitoredSeconds"] == 0 < r["elapsedSeconds"]  # recorded from the start, now
    # Deleting old minutes keeps the hourly totals.
    prune = client.post("/admin/api/network/prune", headers=BEARER, json={"olderThanDays": 0})
    assert prune.status_code == 200
    assert (
        vault_line(report(client), "alice", "Personal")["transferBytes"]
        == (personal["transferBytes"])
    )


def test_rates_apply_from_the_month_they_are_set_in(client, alice, clock):
    write(
        client,
        "INSERT INTO storage_samples VALUES (?, ?, 'local', ?)",
        billing.month_bounds("2026-08")[0],
        alice.vault_id,
        GB,
    )
    sample(client)
    r = client.post(
        "/admin/api/billing/rates",
        headers=BEARER,
        json={"transferPerGb": 0.05, "localPerGbMonth": 0.1, "s3PerGbMonth": 0.02},
    )
    assert r.status_code == 204
    assert report(client)["rates"] == {
        "transferPerGb": 0.05,
        "localPerGbMonth": 0.1,
        "s3PerGbMonth": 0.02,
    }
    august = report(client, "2026-08")
    assert august["rates"]["localPerGbMonth"] == 0.08 and not august["current"]
    assert vault_line(august, "alice", "Personal")["localGbMonths"] == pytest.approx(1)
    assert vault_line(august, "alice", "Personal")["storageCost"] == pytest.approx(0.08)
    bad = {"transferPerGb": -1, "localPerGbMonth": 0.1, "s3PerGbMonth": 0.02}
    assert client.post("/admin/api/billing/rates", headers=BEARER, json=bad).status_code == 400
    months = client.get("/admin/api/billing/months", headers=BEARER).json()
    assert [m["month"] for m in months["months"]] == ["2026-09", "2026-08"]
    assert months["months"][1]["total"] == pytest.approx(august["total"]["total"])
    assert months["rates"]["transferPerGb"] == 0.05


def test_future_and_bad_months_are_refused(client):
    for month in ("2026-10", "nope"):
        r = client.get("/admin/api/billing", headers=BEARER, params={"month": month})
        assert r.status_code == 400
    assert client.get("/admin/api/billing").status_code == 401


def test_outbound_is_filled_in_from_an_older_netmon_db(settings, clock):
    with TestClient(create_app(settings, clock=clock), client=("127.0.0.1", 50000)) as c:
        c.get("/health")
    conn = sqlite3.connect(settings.data_dir / netmon.FILE)
    conn.execute("DROP TABLE outbound")
    conn.commit()
    conn.close()
    with TestClient(create_app(settings, clock=clock), client=("127.0.0.1", 50000)) as c:
        assert report(c)["server"]["transferBytes"] > 0


def test_the_billing_tab(client, alice):
    upload(alice)
    sample(client)
    r = client.post("/admin/login", data={"token": ADMIN_TOKEN}, follow_redirects=False)
    cookie = {"cookie": r.headers["set-cookie"].split(";")[0]}
    page = client.get("/admin?tab=billing", headers=cookie)
    assert page.status_code == 200
    assert "September 2026 (so far)" in page.text and "Personal" in page.text
    assert "Server" in page.text and "$0.08" not in page.text.split("Rates")[0]
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    form = {"csrf": csrf, "transferPerGb": "0.1", "localPerGbMonth": "0.08", "s3PerGbMonth": "x"}
    r = client.post("/admin/billing/rates", data=form, headers=cookie, follow_redirects=False)
    assert r.headers["location"] == "/admin?tab=billing&done=bad_rate"
    form["s3PerGbMonth"] = "0.03"
    r = client.post("/admin/billing/rates", data=form, headers=cookie, follow_redirects=False)
    assert r.headers["location"] == "/admin?tab=billing&done=rates_set"
    assert 'value="0.03"' in client.get("/admin?tab=billing", headers=cookie).text
    bad = client.get("/admin?tab=billing&month=2030-01", headers=cookie)
    assert "Unknown month" in bad.text
