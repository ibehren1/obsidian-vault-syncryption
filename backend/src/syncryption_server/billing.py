"""Cost estimates for the admin Billing tab (protocol.md 14.5).

What the server would cost on AWS per calendar month (UTC), by user and vault: outbound
transfer, from network monitoring (`netmon`), and storage, from an hourly sample of each
vault's stored bytes, billed per GB-month on the server's disk (EBS) or in S3. Traffic to
and from S3 isn't charged. A GB is 2^30 bytes. Outbound traffic without a vault (no session,
the admin page, `/metrics`) and the server's own files (meta.db, netmon.db, certificates)
are the server's line. A month is billed at the rates in force at its end (now, for the
current month), so changing the rates doesn't change past months.
"""

from __future__ import annotations

import asyncio
import calendar
import contextlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from syncryption_server.db import Database

if TYPE_CHECKING:
    from syncryption_server.state import AppState

GB = 2**30
HOUR = 3600
# Seconds after the start before the first sample, so it doesn't race the startup.
FIRST_SAMPLE = 60
MAX_RATE = 1000.0
# The months table lists at most this many, newest first.
MONTHS_SHOWN = 24
SERVER_FILES = ("meta.db", "meta.db-wal", "meta.db-shm", "netmon.db", "netmon.db-wal")
MONTH = re.compile(r"^(\d{4})-(\d{2})$")

log = logging.getLogger(__name__)


class BillingError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Rates:
    """US dollars per GB sent to clients, and per GB-month on the disk and in S3."""

    transfer_gb: float = 0.09
    local_gb_month: float = 0.08
    s3_gb_month: float = 0.023

    def json(self) -> dict:
        return {
            "transferPerGb": self.transfer_gb,
            "localPerGbMonth": self.local_gb_month,
            "s3PerGbMonth": self.s3_gb_month,
        }


DEFAULT_RATES = Rates()


def month_bounds(month: str) -> tuple[int, int]:
    """`YYYY-MM` to its first second and the first second of the next month, in UTC."""
    m = MONTH.match(month)
    if m is None or not 1 <= int(m[2]) <= 12 or int(m[1]) < 1970:
        raise BillingError("bad_month")
    year, mon = int(m[1]), int(m[2])
    start = calendar.timegm((year, mon, 1, 0, 0, 0))
    days = calendar.monthrange(year, mon)[1]
    return start, start + days * 86400


def month_of(t: float) -> str:
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m")


def _previous(month: str) -> str:
    year, mon = int(month[:4]), int(month[5:])
    return f"{year - 1}-12" if mon == 1 else f"{year}-{mon - 1:02d}"


# Sampling


def _server_bytes(data_dir: Path) -> int:
    """The bytes of the server's own files on the disk: the databases and certificates."""
    total = 0
    for name in SERVER_FILES:
        with contextlib.suppress(OSError):
            total += (data_dir / name).stat().st_size
    for root, _, files in os.walk(data_dir / "caddy"):
        for name in files:
            with contextlib.suppress(OSError):
                total += (Path(root) / name).stat().st_size
    return total


async def sample(state: AppState) -> None:
    """Record every vault's stored bytes for this hour, and the server's own files."""
    hour = state.now() // HOUR * HOUR
    store = "local" if state.settings.blob_s3 is None else "s3"
    server = await asyncio.to_thread(_server_bytes, state.settings.data_dir)

    def write() -> None:
        with state.db.transaction() as db:
            vaults = db.execute(
                "SELECT v.id, v.user_id, u.username, v.name, v.blob_bytes FROM vaults v "
                "JOIN users u ON u.id = v.user_id"
            ).fetchall()
            db.executemany(
                "INSERT OR REPLACE INTO storage_samples (hour, vault_id, store, bytes) "
                "VALUES (?, ?, ?, ?)",
                [(hour, v["id"], store, v["blob_bytes"]) for v in vaults]
                + [(hour, "", "local", server)],
            )
            db.executemany(
                "INSERT OR REPLACE INTO billing_vaults (vault_id, user_id, username, "
                "vault_name) VALUES (?, ?, ?, ?)",
                [(v["id"], v["user_id"], v["username"], v["name"]) for v in vaults],
            )

    await state.db.run(write)


async def run(state: AppState) -> None:
    """Sample a minute after the start, then at the start of every hour."""
    await asyncio.sleep(FIRST_SAMPLE)
    while True:
        try:
            await sample(state)
        except Exception:
            log.exception("billing: sampling the stored bytes failed")
        await asyncio.sleep(HOUR - state.clock() % HOUR + 1)


# Rates


def rates_at(db: Database, t: int) -> Rates:
    """The rates in force at `t`; the defaults before any were set."""
    row = db.one(
        "SELECT transfer_gb, local_gb_month, s3_gb_month FROM billing_rates WHERE since <= ? "
        "ORDER BY since DESC LIMIT 1",
        t,
    )
    return Rates(*row) if row else DEFAULT_RATES


async def set_rates(state: AppState, rates: Rates) -> None:
    for v in (rates.transfer_gb, rates.local_gb_month, rates.s3_gb_month):
        if not 0 <= v <= MAX_RATE:
            raise BillingError("bad_rate")
    now = state.now()

    def write() -> None:
        with state.db.transaction() as db:
            db.execute(
                "INSERT OR REPLACE INTO billing_rates (since, transfer_gb, local_gb_month, "
                "s3_gb_month) VALUES (?, ?, ?, ?)",
                (now, rates.transfer_gb, rates.local_gb_month, rates.s3_gb_month),
            )

    await state.db.run(write)
    log.info("admin: billing rates changed")


# Computing


def _storage(db: Database, start: int, stop: int) -> dict[str, dict[str, float]]:
    """Byte-seconds per vault ('' for the server) and store over [start, stop). A sample
    holds until the next one, also across a restart; a vault missing from it has 0."""
    first = db.one("SELECT MAX(hour) FROM storage_samples WHERE hour <= ?", start)[0]
    lo = first if first is not None else start
    hours = [
        r[0]
        for r in db.all(
            "SELECT DISTINCT hour FROM storage_samples WHERE hour >= ? AND hour < ? ORDER BY hour",
            lo,
            stop,
        )
    ]
    span = {
        h: max(0, min(hours[i + 1] if i + 1 < len(hours) else stop, stop) - max(h, start))
        for i, h in enumerate(hours)
    }
    out: dict[str, dict[str, float]] = {}
    for r in db.all(
        "SELECT hour, vault_id, store, bytes FROM storage_samples WHERE hour >= ? AND hour < ?",
        lo,
        stop,
    ):
        seconds = span[r["hour"]]
        if seconds:
            by_store = out.setdefault(r["vault_id"], {"local": 0.0, "s3": 0.0})
            by_store[r["store"]] += r["bytes"] * seconds
    return out


def _first_sample(db: Database) -> int | None:
    return db.one("SELECT MIN(hour) FROM storage_samples")[0]


def _money(gb: float, rate: float) -> float:
    return gb * rate


def _line(transfer: int, local: float, s3: float, rates: Rates) -> dict:
    transfer_cost = _money(transfer / GB, rates.transfer_gb)
    storage_cost = _money(local, rates.local_gb_month) + _money(s3, rates.s3_gb_month)
    return {
        "transferBytes": transfer,
        "transferCost": transfer_cost,
        "localGbMonths": local,
        "s3GbMonths": s3,
        "storageCost": storage_cost,
        "total": transfer_cost + storage_cost,
    }


def _sum(lines: list[dict], rates: Rates) -> dict:
    return _line(
        sum(x["transferBytes"] for x in lines),
        sum(x["localGbMonths"] for x in lines),
        sum(x["s3GbMonths"] for x in lines),
        rates,
    )


async def month_report(state: AppState, month: str) -> dict:
    """One month's costs: per user, each vault and the user's total, then the server's line
    and the month's total. The current month counts up to now."""
    start, end = month_bounds(month)
    now = state.now()
    if start > now:
        raise BillingError("bad_month")
    stop = min(end, now)
    outbound, names, monitored = await state.netmon.outbound(start, stop)

    def read() -> tuple[Rates, dict, list]:
        return (
            rates_at(state.db, min(end - 1, now)),
            _storage(state.db, start, stop),
            state.db.all("SELECT vault_id, user_id, username, vault_name FROM billing_vaults"),
        )

    rates, storage, known = await state.db.read(read)
    vault_names = {r["vault_id"]: dict(r) for r in known}
    for vault_id, n in names.items():
        vault_names.setdefault(vault_id, n)
    month_gb_seconds = GB * (end - start)

    users: dict[str, dict] = {}
    for vault_id in sorted((set(storage) | set(outbound)) - {""}):
        n = vault_names.get(vault_id)
        if n is None:
            continue
        s = storage.get(vault_id, {"local": 0.0, "s3": 0.0})
        line = _line(
            outbound.get(vault_id, 0),
            s["local"] / month_gb_seconds,
            s["s3"] / month_gb_seconds,
            rates,
        )
        user = users.setdefault(
            n["user_id"], {"userId": n["user_id"], "username": n["username"], "vaults": []}
        )
        user["vaults"].append({"vaultId": vault_id, "vaultName": n["vault_name"], **line})
    # Traffic of vaults no longer known, and of no vault, is the server's.
    unknown = sum(v for k, v in outbound.items() if k != "" and k not in vault_names)
    server_storage = storage.get("", {"local": 0.0, "s3": 0.0})
    server = _line(
        outbound.get("", 0) + unknown,
        server_storage["local"] / month_gb_seconds,
        server_storage["s3"] / month_gb_seconds,
        rates,
    )
    out_users = []
    for user in sorted(users.values(), key=lambda u: u["username"]):
        user["vaults"].sort(key=lambda v: v["vaultName"])
        out_users.append({**user, **_sum(user["vaults"], rates)})
    return {
        "month": month,
        "start": start,
        "end": end,
        "current": end > now,
        "rates": rates.json(),
        # Seconds of the month (up to now) while network monitoring recorded transfer.
        "monitoredSeconds": monitored,
        "elapsedSeconds": stop - start,
        "users": out_users,
        "server": server,
        "total": _sum([*out_users, server], rates),
    }


async def months(state: AppState) -> list[dict]:
    """The months with data, newest first, each with its totals."""
    first = await state.db.read(lambda: _first_sample(state.db))
    oldest_traffic = await state.netmon.oldest()
    starts = [t for t in (first, oldest_traffic) if t is not None]
    if not starts:
        return []
    oldest = month_of(min(starts))
    month = month_of(state.now())
    out = []
    while len(out) < MONTHS_SHOWN:
        report = await month_report(state, month)
        out.append(
            {
                "month": month,
                "current": report["current"],
                "monitoredSeconds": report["monitoredSeconds"],
                "elapsedSeconds": report["elapsedSeconds"],
                **report["total"],
            }
        )
        if month <= oldest:
            break
        month = _previous(month)
    return out
