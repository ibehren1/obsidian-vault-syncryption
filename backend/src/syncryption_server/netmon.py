"""Network monitoring for the admin page's Network tab (protocol.md 14.4).

Always on. The bytes of every request on the web port (bodies, plus an estimate of the HTTP
headers) and of every S3 call are added up per minute and per source, and written to
`netmon.db` beside meta.db. Litestream replicates only meta.db, so monitoring makes no S3
traffic of its own. Each vault's outbound bytes are also kept per hour, for the Billing tab
(`billing`); deleting old minutes leaves those.

A source is a device (by its session), or `anonymous` (no session: logins, `/health` and
anything else), `admin` (the admin page and API), `metrics` (`/metrics` scrapes), `server`
(S3 calls of the hourly cleanup) or `litestream` (its replication of meta.db, from its own
metrics). Device, vault and user names are copied in as devices are seen, so the history
outlives a removed device. The admin deletes old minutes by age, by hand or automatically.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from contextvars import ContextVar
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from syncryption_server.db import Database
from syncryption_server.metrics import ACTOR

if TYPE_CHECKING:
    from syncryption_server.metrics import Metrics
    from syncryption_server.state import AppState

FILE = "netmon.db"
MINUTE = 60
DAY = 24 * 3600
# Counters are written this often (seconds), so the graphs are at most this far behind.
FLUSH_INTERVAL = 15
PRUNE_INTERVAL = 3600
MAX_DAYS = 3650
# A graph has at most MAX_POINTS points: the smallest step of STEPS (seconds) that fits.
MAX_POINTS = 360
STEPS = (60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, DAY, 7 * DAY)
# A graph shows the TOP busiest groups, the rest summed as "other".
TOP = 8
# The period table: periods per page, and groups listed per period.
PERIODS_PAGE = 24
PERIOD_GROUPS = 20
# The summary: the last hour, day, week and 30 days, then all monitored time (None).
WINDOWS = (("hour", 3600), ("day", DAY), ("week", 7 * DAY), ("month", 30 * DAY), ("all", None))
MAX_AGENT = 200
FIELDS = ("web_in", "web_out", "requests", "s3_in", "s3_out", "s3_ops")
SOURCES = {
    "anonymous": "No session (logins, /health, other)",
    "admin": "Admin page and API",
    "metrics": "/metrics scrapes",
    "server": "Server (cleanup)",
    "litestream": "Litestream (meta.db replication)",
}
GROUPS = ("device", "vault", "user", "client")
Group = Literal["device", "vault", "user", "client"]
Period = Literal["hour", "day", "week", "month"]

# The device of the request being answered (its scope's actor), for S3 calls it makes.
CURRENT: ContextVar[dict | None] = ContextVar("syncryption_netmon_actor", default=None)

SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic (
    minute INTEGER NOT NULL,
    source TEXT NOT NULL,
    device_id TEXT NOT NULL DEFAULT '',
    web_in INTEGER NOT NULL DEFAULT 0,
    web_out INTEGER NOT NULL DEFAULT 0,
    requests INTEGER NOT NULL DEFAULT 0,
    s3_in INTEGER NOT NULL DEFAULT 0,
    s3_out INTEGER NOT NULL DEFAULT 0,
    s3_ops INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (minute, source, device_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    user_id TEXT,
    username TEXT,
    vault_id TEXT,
    vault_name TEXT,
    device_name TEXT,
    client TEXT,
    user_agent TEXT,
    seen_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS periods (
    started_at INTEGER PRIMARY KEY,
    stopped_at INTEGER
);
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    auto_prune_days INTEGER
);
INSERT OR IGNORE INTO settings (id) VALUES (1);
CREATE TABLE IF NOT EXISTS outbound (
    hour INTEGER NOT NULL,
    vault_id TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    PRIMARY KEY (hour, vault_id)
) WITHOUT ROWID
"""
# Fills `outbound` from the minutes of a netmon.db written before it existed.
_BACKFILL = """
INSERT INTO outbound (hour, vault_id, bytes)
SELECT t.minute / 3600 * 3600, COALESCE(d.vault_id, ''), SUM(t.web_out)
FROM traffic t LEFT JOIN devices d ON t.source = 'device' AND d.device_id = t.device_id
GROUP BY 1, 2
"""
HOUR = 3600

_UPSERT = (
    "INSERT INTO traffic (minute, source, device_id, web_in, web_out, requests, s3_in, s3_out, "
    "s3_ops) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (minute, source, device_id) DO UPDATE "
    "SET web_in = web_in + excluded.web_in, web_out = web_out + excluded.web_out, "
    "requests = requests + excluded.requests, s3_in = s3_in + excluded.s3_in, "
    "s3_out = s3_out + excluded.s3_out, s3_ops = s3_ops + excluded.s3_ops"
)

# Each traffic row with its device's names, for grouping and filtering.
_FROM = "FROM traffic t LEFT JOIN devices d ON t.source = 'device' AND d.device_id = t.device_id"

log = logging.getLogger(__name__)


class NetmonError(Exception):
    """A request the Network tab can't do. `code` picks the admin page's message."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def client_kind(user_agent: str) -> str:
    """Which client a device runs, from its User-Agent: the macOS client's URLSession names
    the app, Obsidian's names Obsidian or a browser engine."""
    ua = user_agent.lower()
    if "vaultsyncryption" in ua:
        return "macOS client"
    if "obsidian" in ua or "mozilla" in ua:
        return "Obsidian"
    return "Other"


def _source(path: str) -> str:
    """The source of a request without a device session."""
    if path == "/metrics":
        return "metrics"
    if path == "/admin" or path.startswith("/admin/"):
        return "admin"
    return "anonymous"


def _headers_size(headers: list[tuple[bytes, bytes]]) -> int:
    return sum(len(k) + len(v) + 4 for k, v in headers)


class NetMonitor:
    """The counters of one app, and its `netmon.db`. Counts from `start` on."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        self.path: Path | None = None
        self.db: Database | None = None
        self.enabled = False
        self.since: int | None = None
        self.auto_prune_days: int | None = None
        # (minute, source, device id) to the FIELDS, not yet written.
        self.pending: dict[tuple[int, str, str], list[int]] = {}
        # Device id to its latest User-Agent, not yet written.
        self.agents: dict[str, str] = {}
        self._litestream: tuple[float, float, float] | None = None
        self._pruned_at = 0.0
        self._lock = asyncio.Lock()

    def now(self) -> int:
        return int(self.clock())

    # Recording

    def add(self, source: str, device_id: str = "", **counts: int) -> None:
        if not self.enabled:
            return
        key = (self.now() // MINUTE * MINUTE, source, device_id)
        c = self.pending.get(key)
        if c is None:
            c = self.pending[key] = [0] * len(FIELDS)
        for i, name in enumerate(FIELDS):
            c[i] += counts.get(name, 0)

    def s3(self, uploaded: int, downloaded: int) -> None:
        """One S3 call, for the device whose request made it (`server` outside requests)."""
        actor = CURRENT.get()
        if actor is None:
            source, device = "server", ""
        elif actor.get("device"):
            source, device = "device", actor["device"]
        else:
            source, device = actor.get("source", "anonymous"), ""
        self.add(source, device, s3_in=downloaded, s3_out=uploaded, s3_ops=1)

    def _litestream_sample(self, metrics: Metrics) -> None:
        """Litestream's replica bytes since the last sample (downloads are GETs)."""
        ls = metrics.litestream
        if ls is None or not ls.up:
            return
        down = up = 0.0
        for labels, value in ls.samples.get("litestream_replica_operation_bytes_total", []):
            if labels.get("operation", "").upper() == "GET":
                down += value
            else:
                up += value
        ops = sum(v for _, v in ls.samples.get("litestream_replica_operation_total", []))
        last, self._litestream = self._litestream, (up, down, ops)
        if last is None:
            return
        if up < last[0] or down < last[1] or ops < last[2]:
            last = (0.0, 0.0, 0.0)  # Litestream restarted: its totals started over
        self.add(
            "litestream",
            s3_out=int(up - last[0]),
            s3_in=int(down - last[1]),
            s3_ops=int(ops - last[2]),
        )

    # Storage

    def _open(self) -> Database:
        """Open (or create) netmon.db. Not on the event loop thread."""
        db = Database(self.path or FILE)
        if db.one("PRAGMA page_count")[0] <= 1:
            # Only before the first table: deleted rows then free their pages (prune).
            db.conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
        with db.transaction() as conn:
            new = (
                conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'outbound'").fetchone()
                is None
            )
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    conn.execute(statement)
            if new:
                conn.execute(_BACKFILL)
        return db

    async def start(self, data_dir: Path, clock: Callable[[], float]) -> None:
        """Open (or create) netmon.db and start counting. A period left open by a crash
        ends at its last minute with data."""
        self.clock = clock
        self.path = data_dir / FILE
        self.db = db = await asyncio.to_thread(self._open)
        now = self.now()

        def load() -> int | None:
            with db.transaction() as conn:
                row = conn.execute("SELECT auto_prune_days FROM settings").fetchone()
                open_ = conn.execute(
                    "SELECT started_at FROM periods WHERE stopped_at IS NULL"
                ).fetchone()
                if open_ is not None:
                    last = conn.execute(
                        "SELECT MAX(minute) FROM traffic WHERE minute >= ?", (open_[0],)
                    ).fetchone()[0]
                    end = min(now, last + MINUTE) if last is not None else open_[0]
                    conn.execute(
                        "UPDATE periods SET stopped_at = ? WHERE started_at = ?", (end, open_[0])
                    )
                conn.execute(
                    "INSERT OR REPLACE INTO periods (started_at, stopped_at) VALUES (?, NULL)",
                    (now,),
                )
            return row["auto_prune_days"]

        self.auto_prune_days = await db.run(load)
        self.enabled, self.since = True, now

    async def stop(self, state: AppState) -> None:
        """Write what is pending and end the period."""
        if self.db is None:
            return
        self.enabled = False
        try:
            await self.flush(state)
        except Exception:
            log.exception("network monitoring: the last write failed")
        db, now = self.db, self.now()

        def close() -> None:
            with db.transaction() as conn:
                conn.execute("UPDATE periods SET stopped_at = ? WHERE stopped_at IS NULL", (now,))

        await db.run(close)
        await asyncio.to_thread(db.close)
        self.db = None

    async def set_auto_prune(self, days: int | None) -> None:
        if days is not None and not 1 <= days <= MAX_DAYS:
            raise NetmonError("bad_days")
        db = self._need_db()

        def save() -> None:
            with db.transaction() as conn:
                conn.execute("UPDATE settings SET auto_prune_days = ?", (days,))

        await db.run(save)
        self.auto_prune_days = days

    def _need_db(self) -> Database:
        if self.db is None:
            raise NetmonError("netmon_never")
        return self.db

    async def flush(self, state: AppState) -> None:
        """Write the pending counters, and the names of the devices among them."""
        db = self.db
        if db is None or not (self.pending or self.agents):
            return
        pending, self.pending = self.pending, {}
        agents, self.agents = self.agents, {}
        ids = sorted({k[2] for k in pending if k[1] == "device"} | set(agents))

        def names() -> list:
            marks = ",".join("?" * len(ids))
            return state.db.all(
                "SELECT d.id, d.user_id, u.username, d.vault_id, d.vault_name, d.name "  # noqa: S608
                f"FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id IN ({marks})",
                *ids,
            )

        rows = await state.db.read(names) if ids else []
        now = self.now()
        vault_of = {r["id"]: r["vault_id"] or "" for r in rows}
        outbound: dict[tuple[int, str], int] = {}
        for (minute, source, device), counts in pending.items():
            key = (minute // HOUR * HOUR, vault_of.get(device, "") if source == "device" else "")
            outbound[key] = outbound.get(key, 0) + counts[1]

        def write() -> None:
            with db.transaction() as conn:
                conn.executemany(_UPSERT, [(*k, *v) for k, v in pending.items()])
                conn.executemany(
                    "INSERT INTO outbound (hour, vault_id, bytes) VALUES (?, ?, ?) "
                    "ON CONFLICT (hour, vault_id) DO UPDATE SET bytes = bytes + excluded.bytes",
                    [(*k, v) for k, v in outbound.items() if v],
                )
                for r in rows:
                    agent = agents.get(r["id"])
                    conn.execute(
                        "INSERT INTO devices (device_id, user_id, username, vault_id, vault_name, "
                        "device_name, client, user_agent, seen_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (device_id) DO UPDATE SET "
                        "user_id = excluded.user_id, username = excluded.username, "
                        "vault_id = excluded.vault_id, vault_name = excluded.vault_name, "
                        "device_name = excluded.device_name, "
                        "client = COALESCE(excluded.client, client), "
                        "user_agent = COALESCE(excluded.user_agent, user_agent), "
                        "seen_at = excluded.seen_at",
                        (
                            r["id"],
                            r["user_id"],
                            r["username"],
                            r["vault_id"],
                            r["vault_name"],
                            r["name"],
                            client_kind(agent) if agent is not None else None,
                            agent,
                            now,
                        ),
                    )

        try:
            await db.run(write)
        except Exception:
            # Put them back, to be written next time.
            for k, v in pending.items():
                c = self.pending.setdefault(k, [0] * len(FIELDS))
                for i, n in enumerate(v):
                    c[i] += n
            for k, v in agents.items():
                self.agents.setdefault(k, v)
            raise

    async def prune(self, days: int) -> int:
        """Delete the minutes older than `days` days (0: everything until now) and free their
        space. Returns the rows deleted. The hourly outbound bytes per vault stay."""
        if not 0 <= days <= MAX_DAYS:
            raise NetmonError("bad_days")
        db = self._need_db()
        cutoff = (self.now() - days * DAY) // MINUTE * MINUTE
        if days == 0:
            cutoff += MINUTE
            self.pending.clear()

        def delete() -> int:
            with db.transaction() as conn:
                n = conn.execute("DELETE FROM traffic WHERE minute < ?", (cutoff,)).rowcount
                conn.execute(
                    "DELETE FROM periods WHERE stopped_at IS NOT NULL AND stopped_at <= ?",
                    (cutoff,),
                )
                conn.execute(
                    "UPDATE periods SET started_at = ? WHERE started_at < ?", (cutoff, cutoff)
                )
            db.conn.execute("PRAGMA incremental_vacuum")
            db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return n

        n = await db.run(delete)
        if n:
            log.info("network monitoring: deleted %d rows older than %d days", n, days)
        return n

    async def tick(self, state: AppState) -> None:
        """One pass of the loop: Litestream's bytes, the write, and the hourly auto-prune."""
        ls = state.metrics.litestream
        if self.enabled and ls is not None:
            await ls.refresh()
            self._litestream_sample(state.metrics)
        await self.flush(state)
        days = self.auto_prune_days
        if days and self.db is not None and self.clock() - self._pruned_at >= PRUNE_INTERVAL:
            self._pruned_at = self.clock()
            await self.prune(days)

    async def run(self, state: AppState) -> None:
        while True:
            await asyncio.sleep(FLUSH_INTERVAL)
            try:
                await self.tick(state)
            except Exception:
                log.exception("network monitoring failed")

    # Reading

    async def outbound(self, start: int, stop: int) -> tuple[dict[str, int], dict, int]:
        """For billing: the bytes sent per vault ('' for no vault) over the hours in
        [start, stop), the names netmon knows per vault, and the seconds monitored."""
        db = self.db
        if db is None:
            return {}, {}, 0

        def read() -> tuple[dict[str, int], dict, int]:
            sent = {
                r[0]: r[1]
                for r in db.all(
                    "SELECT vault_id, SUM(bytes) FROM outbound WHERE hour >= ? AND hour < ? "
                    "GROUP BY vault_id",
                    start,
                    stop,
                )
            }
            names = {
                r["vault_id"]: dict(r)
                for r in db.all(
                    "SELECT vault_id, user_id, username, vault_name FROM devices "
                    "WHERE vault_id IS NOT NULL ORDER BY seen_at"
                )
            }
            monitored = 0
            for p in db.all("SELECT started_at, stopped_at FROM periods"):
                end = p[1] if p[1] is not None else stop
                monitored += max(0, min(end, stop) - max(p[0], start))
            return sent, names, monitored

        return await db.read(read)

    async def oldest(self) -> int | None:
        """The first hour with outbound bytes, or None."""
        db = self.db
        if db is None:
            return None
        return await db.read(lambda: db.one("SELECT MIN(hour) FROM outbound")[0])

    def size(self) -> int:
        if self.path is None:
            return 0
        total = 0
        for suffix in ("", "-wal", "-shm"):
            with contextlib.suppress(OSError):
                total += self.path.with_name(self.path.name + suffix).stat().st_size
        return total

    async def status(self) -> dict:
        """Since when it records, its settings, and the data kept: size, rows, time span
        and the monitored periods (Unix seconds; `end` null for the current one)."""
        base = {
            "since": self.since,
            "autoPruneDays": self.auto_prune_days,
            "bytes": self.size(),
            "rows": 0,
            "oldest": None,
            "newest": None,
            "periods": [],
        }
        db = self.db
        if db is None:
            return base

        def read() -> dict:
            row = db.one("SELECT COUNT(*), MIN(minute), MAX(minute) FROM traffic")
            periods = db.all("SELECT started_at, stopped_at FROM periods ORDER BY started_at")
            return {
                "rows": row[0],
                "oldest": row[1],
                "newest": row[2] + MINUTE if row[2] is not None else None,
                "periods": [{"start": p[0], "end": p[1]} for p in periods],
            }

        return {**base, **await db.read(read)}

    async def traffic(
        self,
        group: Group,
        filter_key: str | None,
        start: int | None,
        end: int | None,
    ) -> dict:
        """The graphs and table of a time range (`start` None: from the oldest data)."""
        db = self.db
        now = self.now()
        end = min(end or now + MINUTE, now + MINUTE)
        if db is None:
            return _empty(group, end)
        where, params = _filter(filter_key)

        def read() -> dict:
            first = start
            if first is None:
                row = db.one("SELECT MIN(minute) FROM traffic")
                p = db.one("SELECT MIN(started_at) FROM periods")
                candidates = [v for v in (row[0], p[0]) if v is not None]
                first = min(candidates) if candidates else end - 3600
            span = max(end - first, MINUTE)
            step = next((s for s in STEPS if span / s <= MAX_POINTS), STEPS[-1])
            first = first // step * step
            count = -(-(end - first) // step)
            totals = _totals(db, group, where, params, first, end)
            top = [t["key"] for t in totals[:TOP]]
            series: dict[str, dict] = {}
            for t in totals[:TOP]:
                series[t["key"]] = {
                    "key": t["key"],
                    "label": t["label"],
                    **{f: [0] * count for f in ("web_in", "web_out", "s3_in", "s3_out")},
                }
            key = _key(group)
            for r in db.all(
                f"SELECT (t.minute - ?) / ? AS i, {key} AS k, SUM(t.web_in), SUM(t.web_out), "  # noqa: S608
                f"SUM(t.s3_in), SUM(t.s3_out) {_FROM} "
                f"WHERE t.minute >= ? AND t.minute < ?{where} GROUP BY i, k",
                first,
                step,
                first,
                end,
                *params,
            ):
                k = r["k"] if r["k"] in top else "other"
                s = series.get(k)
                if s is None:
                    s = series[k] = {
                        "key": "other",
                        "label": "Other",
                        **{f: [0] * count for f in ("web_in", "web_out", "s3_in", "s3_out")},
                    }
                for j, f in enumerate(("web_in", "web_out", "s3_in", "s3_out"), start=2):
                    s[f][r["i"]] += r[j]
            return {
                "group": group,
                "filter": filter_key,
                "filterLabel": _filter_label(db, filter_key),
                "start": first,
                "end": end,
                "step": step,
                "times": [first + i * step for i in range(count)],
                "series": list(series.values()),
                "totals": totals,
                "summary": _summary(db, where, params, now),
                "periods": [
                    {"start": p[0], "end": p[1]}
                    for p in db.all(
                        "SELECT started_at, stopped_at FROM periods "
                        "WHERE stopped_at IS NULL OR stopped_at > ? ORDER BY started_at",
                        first,
                    )
                ],
            }

        return {"time": now, **await db.read(read)}

    async def period_totals(
        self,
        group: Group,
        filter_key: str | None,
        period: Period,
        tz: str,
        before: int | None,
    ) -> dict:
        """Totals per hour, day, week or month of the time zone `tz`, newest first, a page of
        PERIODS_PAGE ending before `before` (default: the period now, included)."""
        try:
            zone = ZoneInfo(tz)
        except (ZoneInfoNotFoundError, ValueError) as e:
            raise NetmonError("bad_tz") from e
        now = self.now()
        db = self.db
        empty = {"period": period, "tz": tz, "periods": [], "more": False}
        if db is None:
            return empty
        where, params = _filter(filter_key)
        bounds = _periods(period, zone, before if before is not None else now + 1)

        def read() -> dict:
            oldest = db.one(f"SELECT MIN(t.minute) {_FROM} WHERE 1 = 1{where}", *params)[0]  # noqa: S608
            if oldest is None:
                return empty
            rows = []
            for s, e in bounds:
                if e <= oldest:
                    break
                groups = _totals(db, group, where, params, s, e)
                total = {f: sum(g[f] for g in groups) for f in FIELDS}
                rows.append({"start": s, "end": e, **total, "groups": groups[:PERIOD_GROUPS]})
            more = bool(rows) and len(rows) == len(bounds) and bounds[-1][0] > oldest
            return {"period": period, "tz": tz, "periods": rows, "more": more}

        return await db.read(read)


def _empty(group: str, end: int) -> dict:
    return {
        "time": end - MINUTE,
        "group": group,
        "filter": None,
        "filterLabel": None,
        "start": end - 3600,
        "end": end,
        "step": MINUTE,
        "times": [],
        "series": [],
        "totals": [],
        "summary": [{"window": w, **{f: 0 for f in FIELDS}} for w, _ in WINDOWS],
        "periods": [],
    }


def _key(group: str) -> str:
    """The SQL that names a row's group; rows that aren't a device's are their source."""
    inner = {
        "device": "'device:' || t.device_id",
        "vault": "'vault:' || COALESCE(d.vault_id, '')",
        "user": "'user:' || COALESCE(d.user_id, '')",
        "client": "'client:' || COALESCE(d.client, 'Unknown')",
    }[group]
    return f"CASE WHEN t.source = 'device' THEN {inner} ELSE t.source END"


def _filter(key: str | None) -> tuple[str, list[str]]:
    """The SQL condition for a group key, as `_key` makes them."""
    if not key:
        return "", []
    kind, sep, value = key.partition(":")
    column = {
        "device": "t.device_id",
        "vault": "d.vault_id",
        "user": "d.user_id",
        "client": "COALESCE(d.client, 'Unknown')",
    }.get(kind)
    if sep and column is not None:
        return f" AND t.source = 'device' AND {column} = ?", [value]
    if key in SOURCES:
        return " AND t.source = ?", [key]
    raise NetmonError("bad_filter")


def _filter_label(db: Database, key: str | None) -> str | None:
    if not key:
        return None
    kind, _, value = key.partition(":")
    if key in SOURCES:
        return SOURCES[key]
    if kind == "client":
        return value
    column = {"device": "device_id", "vault": "vault_id", "user": "user_id"}[kind]
    row = db.one(
        f"SELECT username, vault_name, device_name FROM devices WHERE {column} = ? "  # noqa: S608
        "ORDER BY seen_at DESC LIMIT 1",
        value,
    )
    if row is None:
        return value
    return _label(kind, row["username"], row["vault_name"], row["device_name"], None)


def _label(
    group: str, username: str | None, vault: str | None, device: str | None, client: str | None
) -> str:
    user = username or "?"
    if group == "user":
        return user
    if group == "vault":
        return f"{user} / {vault or '?'}"
    if group == "client":
        return client or "Unknown"
    return f"{user} / {vault or '?'} / {device or '?'}"


def _totals(
    db: Database, group: str, where: str, params: list[str], start: int, end: int
) -> list[dict]:
    """Each group's sums over [start, end), busiest (most bytes) first."""
    key = _key(group)
    rows = db.all(
        f"SELECT {key} AS k, MAX(d.username) AS username, MAX(d.vault_name) AS vault_name, "  # noqa: S608
        "MAX(d.device_name) AS device_name, MAX(d.client) AS client, "
        "SUM(t.web_in), SUM(t.web_out), SUM(t.requests), SUM(t.s3_in), SUM(t.s3_out), "
        f"SUM(t.s3_ops) {_FROM} "
        f"WHERE t.minute >= ? AND t.minute < ?{where} GROUP BY k",
        start,
        end,
        *params,
    )
    out = []
    for r in rows:
        k = r["k"]
        device = k not in SOURCES
        out.append(
            {
                "key": k,
                "label": _label(
                    group, r["username"], r["vault_name"], r["device_name"], r["client"]
                )
                if device
                else SOURCES[k],
                "source": "device" if device else k,
                "username": r["username"] if device else None,
                "vaultName": r["vault_name"] if device and group in ("vault", "device") else None,
                "deviceName": r["device_name"] if device and group == "device" else None,
                "client": r["client"] if device and group in ("device", "client") else None,
                **{f: r[i] for i, f in enumerate(FIELDS, start=5)},
            }
        )
    out.sort(key=lambda t: (-(t["web_in"] + t["web_out"] + t["s3_in"] + t["s3_out"]), t["label"]))
    return out


def _summary(db: Database, where: str, params: list[str], now: int) -> list[dict]:
    out = []
    for window, seconds in WINDOWS:
        since = now - seconds if seconds is not None else 0
        row = db.one(
            "SELECT "  # noqa: S608
            + ", ".join(f"COALESCE(SUM(t.{f}), 0)" for f in FIELDS)
            + f" {_FROM} WHERE t.minute >= ?{where}",
            since // MINUTE * MINUTE,
            *params,
        )
        out.append({"window": window, **{f: row[i] for i, f in enumerate(FIELDS)}})
    return out


def _periods(period: str, zone: ZoneInfo, before: int) -> list[tuple[int, int]]:
    """PERIODS_PAGE periods in `zone`, newest first; the first holds the second `before - 1`."""
    local = datetime.fromtimestamp(before - 1, zone)
    if period == "hour":
        # Hours are 3600 s apart in every zone, also across a DST change.
        start = int(local.replace(minute=0, second=0, microsecond=0).timestamp())
        return [(start - i * 3600, start - i * 3600 + 3600) for i in range(PERIODS_PAGE)]
    day = local.replace(tzinfo=None, hour=0, minute=0, second=0, microsecond=0)
    if period == "week":
        day -= timedelta(days=day.weekday())
    elif period == "month":
        day = day.replace(day=1)

    def step(d: datetime, n: int) -> datetime:
        if period == "day":
            return d + timedelta(days=n)
        if period == "week":
            return d + timedelta(days=7 * n)
        months = d.year * 12 + d.month - 1 + n
        return d.replace(year=months // 12, month=months % 12 + 1)

    def stamp(d: datetime) -> int:
        return int(d.replace(tzinfo=zone).timestamp())

    return [(stamp(step(day, -i)), stamp(step(day, 1 - i))) for i in range(PERIODS_PAGE)]


class TrafficMonitor:
    """Count every request's bytes for the NetMonitor while it is on: bodies, the request
    line and status line, and the headers. Outermost, so it sees every answer."""

    def __init__(self, app: ASGIApp, monitor: NetMonitor):
        self.app = app
        self.monitor = monitor

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        monitor = self.monitor
        if scope["type"] != "http" or not monitor.enabled:
            await self.app(scope, receive, send)
            return
        # Shared with RequestMetrics, which authentication fills in with the device.
        actor = scope.setdefault(ACTOR, {})
        actor["source"] = _source(scope["path"])
        headers = scope.get("headers", [])
        received = (
            len(scope["method"])
            + len(scope.get("raw_path") or scope["path"].encode())
            + len(scope.get("query_string", b""))
            + 12
            + _headers_size(headers)
        )
        sent = 0

        async def counted_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
            return message

        async def counted_send(message: Message) -> None:
            nonlocal sent
            if message["type"] == "http.response.start":
                sent += 17 + _headers_size(message.get("headers", []))
            elif message["type"] == "http.response.body":
                sent += len(message.get("body", b""))
            await send(message)

        token = CURRENT.set(actor)
        try:
            await self.app(scope, counted_receive, counted_send)
        finally:
            CURRENT.reset(token)
            device = actor.get("device")
            if device:
                monitor.add("device", device, web_in=received, web_out=sent, requests=1)
                agent = dict(headers).get(b"user-agent", b"").decode("latin-1")
                monitor.agents[device] = agent[:MAX_AGENT]
            else:
                monitor.add(actor["source"], web_in=received, web_out=sent, requests=1)
