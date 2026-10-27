"""Prometheus metrics, served at `/metrics` unless `DISABLE_METRICS=TRUE`, and the same
numbers as JSON for the admin page's Performance tab (`snapshot`), which works either way.

Only counts: no label carries a username, vault name, id, path or key. Request metrics are
labelled with the route template, never the raw path. The activity per device
(`DeviceActivity`) is kept outside the Prometheus registry, so it appears only on the admin
page's Activity tab (`activity`), never on `/metrics`.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
import urllib.request
from collections import Counter as Tally
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, Metric
from prometheus_client.gc_collector import GCCollector
from prometheus_client.parser import text_string_to_metric_families
from prometheus_client.platform_collector import PlatformCollector
from prometheus_client.process_collector import ProcessCollector
from prometheus_client.registry import Collector
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from syncryption_server import PROTOCOL_VERSION, __version__
from syncryption_server.sshkeys import fingerprint, parse_public_key

if TYPE_CHECKING:
    from syncryption_server.state import AppState

PREFIX = "syncryption_"
# Up to a minute, so `/wait` long-polls land in a bucket of their own.
DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)
DEVICE_STATUSES = ("pending", "active", "revoked")
GC_TASKS = ("expired", "retention", "blobs")
# The event-loop lag: measured every LAG_INTERVAL seconds, the worst of the last LAG_WINDOW.
LAG_INTERVAL = 0.5
LAG_WINDOW = 20
# S3 calls: one blob is at most 4 MiB, so most take well under a second.
S3_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)
S3_OPERATIONS = ("put", "get", "head", "delete", "list", "ping")
# `throttled`: SlowDown and other 503 or 429 answers, after botocore's own retries.
# `connection`: no answer (refused, timed out, DNS). `other`: anything else that failed.
S3_RESULTS = ("ok", "not_found", "throttled", "client_error", "server_error", "connection", "other")
# Litestream's metrics are read at each scrape: a slow or stopped Litestream costs at most
# LITESTREAM_TIMEOUT, and its answer at most LITESTREAM_MAX_BYTES.
LITESTREAM_TIMEOUT = 2.0
LITESTREAM_MAX_BYTES = 1024**2
# Not counted: the scrapes and the admin page's own polling.
SKIP = (
    "/metrics",
    "/admin/performance.json",
    "/admin/api/performance",
    "/admin/activity.json",
    "/admin/api/activity",
)
# The scope key under which a request's authenticated device is recorded (`auth.py`).
ACTOR = "syncryption.actor"
# Long-polls are counted apart from the other requests of a device.
WAIT_ROUTE = "/api/v1/vaults/{vault_id}/wait"
# Activity of a device unseen this long (seconds) is dropped, and at most this many are kept.
ACTIVITY_TTL = 3600
ACTIVITY_MAX = 5000


class ContainerCollector(Collector):
    """The whole container's memory and CPU (Caddy and Litestream included), from its own
    cgroup v2 files. Reported only when this process sits at the root of a private cgroup
    namespace (`/proc/self/cgroup` is `0::/`, Docker's default on cgroup v2), where
    `/sys/fs/cgroup` is the container's own cgroup and not the host's. Elsewhere (macOS,
    cgroup v1, a host cgroup namespace) the metrics are absent."""

    def __init__(self, cgroup: Path = Path("/sys/fs/cgroup"), proc: Path = Path("/proc/self")):
        self.cgroup = cgroup
        self.proc = proc

    def _read(self, name: str) -> str | None:
        try:
            return (self.cgroup / name).read_text().strip()
        except OSError:
            return None

    def _own_cgroup(self) -> bool:
        try:
            return (self.proc / "cgroup").read_text().strip() == "0::/"
        except OSError:
            return False

    def collect(self) -> Iterator[Metric]:
        if not self._own_cgroup():
            return
        current = self._read("memory.current")
        if current is not None and current.isdigit():
            yield GaugeMetricFamily(
                PREFIX + "container_memory_bytes",
                "Memory the whole container uses, page cache included (cgroup memory.current).",
                value=int(current),
            )
            stat = dict(
                line.split(" ", 1) for line in (self._read("memory.stat") or "").splitlines()
            )
            inactive = stat.get("inactive_file", "0")
            if inactive.isdigit():
                yield GaugeMetricFamily(
                    PREFIX + "container_memory_working_set_bytes",
                    "Container memory without inactive page cache, as `docker stats` shows it.",
                    value=max(int(current) - int(inactive), 0),
                )
        limit = self._read("memory.max")
        if limit is not None and limit.isdigit():  # `max` means no limit: left out
            yield GaugeMetricFamily(
                PREFIX + "container_memory_limit_bytes",
                "The container's memory limit (cgroup memory.max), when it has one.",
                value=int(limit),
            )
        cpu = dict(line.split(" ", 1) for line in (self._read("cpu.stat") or "").splitlines())
        usage = cpu.get("usage_usec", "")
        if usage.isdigit():
            yield CounterMetricFamily(
                PREFIX + "container_cpu_seconds",
                "CPU time of the whole container (cgroup cpu.stat usage_usec).",
                value=int(usage) / 1_000_000,
            )


class DataCollector(Collector):
    """Free space where the data lives, and the size of the database and its WAL."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    def collect(self) -> Iterator[Metric]:
        try:
            disk = shutil.disk_usage(self.data_dir)
        except OSError:
            disk = None
        if disk is not None:
            yield GaugeMetricFamily(
                PREFIX + "data_disk_free_bytes",
                "Free space on the data directory's file system.",
                value=disk.free,
            )
            yield GaugeMetricFamily(
                PREFIX + "data_disk_total_bytes",
                "Size of the data directory's file system.",
                value=disk.total,
            )
        for name, doc, file in (
            ("db_bytes", "Size of meta.db.", "meta.db"),
            ("db_wal_bytes", "Size of meta.db's write-ahead log.", "meta.db-wal"),
        ):
            try:
                size = (self.data_dir / file).stat().st_size
            except OSError:
                continue
            yield GaugeMetricFamily(PREFIX + name, doc, value=size)


class LitestreamCollector(Collector):
    """Litestream's own metrics while it replicates meta.db to S3, read from its metrics
    listener (`addr` in litestream.yml) by `refresh` before each scrape. `/metrics` passes
    its `litestream_*` families on as Litestream wrote them (`text`), so they keep their
    names; its Go runtime and process metrics are left out. This collector itself reports
    only `syncryption_litestream_up`, whether the last read worked."""

    def __init__(self, address: str):
        self.url = f"http://{address}/metrics"
        self.up = False
        self.text = ""
        # Sample name (as the parser names it: counters end in `_total`) to label sets
        # and values, for the admin page.
        self.samples: dict[str, list[tuple[dict[str, str], float]]] = {}

    def _fetch(self) -> str:
        with urllib.request.urlopen(self.url, timeout=LITESTREAM_TIMEOUT) as r:  # noqa: S310
            body = r.read(LITESTREAM_MAX_BYTES + 1)
        if len(body) > LITESTREAM_MAX_BYTES:
            raise ValueError("Litestream's metrics are too large")
        return body.decode()

    @staticmethod
    def _own(line: str) -> bool:
        """Whether the exposition line belongs to a `litestream_*` family."""
        if line.startswith("#"):
            parts = line.split(maxsplit=3)
            return len(parts) >= 3 and parts[1] in ("HELP", "TYPE") and _litestream(parts[2])
        return _litestream(line)

    async def refresh(self) -> None:
        try:
            text = await asyncio.to_thread(self._fetch)
            kept = "".join(line + "\n" for line in text.splitlines() if self._own(line))
            samples: dict[str, list[tuple[dict[str, str], float]]] = {}
            for family in text_string_to_metric_families(kept):
                for sample in family.samples:
                    samples.setdefault(sample.name, []).append((sample.labels, sample.value))
        except (OSError, ValueError):
            self.up, self.text, self.samples = False, "", {}
            return
        self.up, self.text, self.samples = True, kept, samples

    def collect(self) -> Iterator[Metric]:
        yield GaugeMetricFamily(
            PREFIX + "litestream_up",
            "1 when Litestream's metrics could be read at this scrape, else 0.",
            value=1 if self.up else 0,
        )


def _litestream(name: str) -> bool:
    return name.startswith("litestream_")


class S3Metrics:
    """Calls to the S3 blob store, registered only when blobs go to S3. `result` is one of
    S3_RESULTS; `operation` one of S3_OPERATIONS."""

    def __init__(self, registry: CollectorRegistry) -> None:
        r = registry
        self.requests = Counter(
            PREFIX + "s3_requests",
            "S3 calls by operation and result.",
            ["operation", "result"],
            registry=r,
        )
        self.duration = Histogram(
            PREFIX + "s3_request_duration_seconds",
            "S3 call duration by operation, retries and reading the body included.",
            ["operation"],
            buckets=S3_DURATION_BUCKETS,
            registry=r,
        )
        self.retries = Counter(
            PREFIX + "s3_retries",
            "Retries botocore made inside S3 calls, by operation.",
            ["operation"],
            registry=r,
        )
        self.in_flight = Gauge(PREFIX + "s3_requests_in_flight", "S3 calls being made.", registry=r)
        self.uploaded = Counter(
            PREFIX + "s3_uploaded_bytes", "Bytes uploaded to S3 in blobs.", registry=r
        )
        self.downloaded = Counter(
            PREFIX + "s3_downloaded_bytes", "Bytes downloaded from S3 in blobs.", registry=r
        )
        for op in S3_OPERATIONS:
            self.duration.labels(op)
            self.retries.labels(op)
            self.requests.labels(op, "ok")


@dataclass
class Activity:
    """The request totals of one device since the server started (or since it was dropped)."""

    requests: int = 0
    waits: int = 0
    errors4xx: int = 0
    errors5xx: int = 0
    request_bytes: int = 0
    response_bytes: int = 0
    routes: Tally[str] = field(default_factory=Tally)
    last: float = 0.0


class DeviceActivity:
    """Requests per device, for the admin page: `None` holds the requests without a session
    (logins, health, the admin pages). Bounded by ACTIVITY_TTL and ACTIVITY_MAX."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self.devices: dict[str | None, Activity] = {}

    def record(
        self,
        device_id: str | None,
        method: str,
        route: str,
        status: int,
        request_bytes: int,
        response_bytes: int,
    ) -> None:
        a = self.devices.get(device_id)
        if a is None:
            a = self.devices[device_id] = Activity()
        if route == WAIT_ROUTE:
            a.waits += 1
        else:
            a.requests += 1
        if 400 <= status < 500:
            a.errors4xx += 1
        elif status >= 500:
            a.errors5xx += 1
        a.request_bytes += request_bytes
        a.response_bytes += response_bytes
        a.routes[f"{method} {route}"] += 1
        a.last = self.clock()

    def prune(self) -> None:
        before = self.clock() - ACTIVITY_TTL
        for key in [k for k, a in self.devices.items() if a.last < before]:
            del self.devices[key]
        if len(self.devices) > ACTIVITY_MAX:
            oldest = sorted(self.devices, key=lambda k: self.devices[k].last)
            for key in oldest[: len(self.devices) - ACTIVITY_MAX]:
                del self.devices[key]


class Metrics:
    """The collectors of one app. Each app has its own registry, so several apps can run in
    one process (the tests build many)."""

    def __init__(
        self, data_dir: Path | None = None, s3: bool = False, litestream: str | None = None
    ) -> None:
        self.started = time.time()
        self.registry = r = CollectorRegistry()
        ProcessCollector(registry=r)
        PlatformCollector(registry=r)
        GCCollector(registry=r)
        r.register(ContainerCollector())
        if data_dir is not None:
            r.register(DataCollector(data_dir))

        build = Gauge(
            PREFIX + "build_info",
            "The server version and protocol.",
            ["version", "protocol"],
            registry=r,
        )
        build.labels(__version__, str(PROTOCOL_VERSION)).set(1)

        self.requests = Counter(
            PREFIX + "http_requests",
            "HTTP requests by method, route template and status code.",
            ["method", "route", "status"],
            registry=r,
        )
        self.request_bytes = Counter(
            PREFIX + "http_request_bytes", "Bytes received in request bodies.", registry=r
        )
        self.response_bytes = Counter(
            PREFIX + "http_response_bytes", "Bytes sent in response bodies.", registry=r
        )
        self.in_flight = Gauge(
            PREFIX + "http_requests_in_flight",
            "Requests being answered, `/wait` long-polls included.",
            registry=r,
        )
        self.duration = Histogram(
            PREFIX + "http_request_duration_seconds",
            "HTTP request duration by method and route template.",
            ["method", "route"],
            buckets=DURATION_BUCKETS,
            registry=r,
        )

        def gauge(name: str, doc: str, labels: tuple[str, ...] = ()) -> Gauge:
            return Gauge(PREFIX + name, doc, labels, registry=r)

        self.users = gauge("users", "Users.")
        self.vaults = gauge("vaults", "Vaults.")
        self.devices = gauge("devices", "Encryption keys by status.", ("status",))
        self.files = gauge("files", "Files, deleted ones included until retention drops them.")
        self.revisions = gauge("revisions", "File revisions kept.")
        self.blobs = gauge("blobs", "Encrypted blobs stored.")
        self.blob_bytes = gauge("blob_bytes", "Total size of the stored blobs in bytes.")
        self.locks = gauge("locks_active", "Soft locks that have not expired.")
        self.maintenance = gauge("maintenance", "1 while maintenance mode is on, else 0.")
        self.longpolls = gauge("longpoll_waiters", "Open `/wait` long-polls.")
        self.loop_lag = gauge(
            "event_loop_lag_seconds",
            f"The longest event-loop delay over the last {LAG_WINDOW * LAG_INTERVAL:.0f} s.",
        )
        self.gc_last_run = gauge(
            "gc_last_run_timestamp_seconds", "When each cleanup task last ran.", ("task",)
        )

        self.gc_runs = Counter(
            PREFIX + "gc_runs", "Background cleanup runs by task.", ["task"], registry=r
        )
        self.gc_failures = Counter(
            PREFIX + "gc_failures",
            "Failed background cleanup runs by task.",
            ["task"],
            registry=r,
        )
        for task in GC_TASKS:
            self.gc_runs.labels(task)
            self.gc_failures.labels(task)
            self.gc_last_run.labels(task)
        self.pruned = Counter(
            PREFIX + "retention_pruned_revisions", "Revisions deleted by retention.", registry=r
        )
        self.gc_deleted = Counter(
            PREFIX + "gc_deleted_blobs", "Unreferenced blobs deleted.", registry=r
        )
        self.shared_secret_failures = Counter(
            PREFIX + "shared_secret_failures", "Wrong shared secrets sent to join.", registry=r
        )
        self.admin_token_failures = Counter(
            PREFIX + "admin_token_failures", "Wrong admin tokens.", registry=r
        )
        self.activity = DeviceActivity()
        self.s3 = S3Metrics(r) if s3 else None
        self.litestream = LitestreamCollector(litestream) if litestream else None
        if self.litestream is not None:
            r.register(self.litestream)


def _refresh(state: AppState) -> None:
    """Set the gauges counted in the database. Runs on the database thread."""
    m, db = state.metrics, state.db

    def count(sql: str, *params: object) -> int:
        row = db.one(sql, *params)
        return int(row[0]) if row else 0

    m.users.set(count("SELECT COUNT(*) FROM users"))
    m.vaults.set(count("SELECT COUNT(*) FROM vaults"))
    devices = {
        row["status"]: row["n"]
        for row in db.all("SELECT status, COUNT(*) AS n FROM devices GROUP BY status")
    }
    for status in DEVICE_STATUSES:
        m.devices.labels(status).set(devices.get(status, 0))
    m.files.set(count("SELECT COUNT(*) FROM files"))
    m.revisions.set(count("SELECT COUNT(*) FROM revisions"))
    m.blobs.set(count("SELECT COUNT(*) FROM blobs"))
    m.blob_bytes.set(count("SELECT COALESCE(SUM(size), 0) FROM blobs"))
    m.locks.set(count("SELECT COUNT(*) FROM locks WHERE expires_at >= ?", state.now()))


async def _refresh_all(state: AppState) -> None:
    m = state.metrics
    await state.db.read(lambda: _refresh(state))
    m.maintenance.set(0 if state.maintenance is None else 1)
    m.longpolls.set(sum(len(w) for w in state.notifier.waiters.values()))
    if m.litestream is not None:
        await m.litestream.refresh()


async def render(state: AppState) -> bytes:
    """Refresh the gauges from the database and the process, then serialize."""
    await _refresh_all(state)
    body = generate_latest(state.metrics.registry)
    litestream = state.metrics.litestream
    if litestream is not None:
        body += litestream.text.encode()
    return body


def _activity(state: AppState) -> list[dict]:
    """Every key that isn't revoked, and every device with requests, with their totals (0 for
    a device without requests since the server started, or for an hour). Runs on the
    database thread. A device deleted meanwhile keeps its id, with null names."""
    activity = state.metrics.activity
    activity.prune()
    seen = [k for k in activity.devices if k is not None]
    rows = state.db.all(
        "SELECT d.id, d.name, d.vault_name, d.public_key, d.status, u.username FROM devices d "
        "JOIN users u ON u.id = d.user_id WHERE d.status != 'revoked' "
        "OR d.id IN (SELECT value FROM json_each(?))",
        json.dumps(seen),
    )
    names: dict[str | None, dict] = {
        row["id"]: {
            "username": row["username"],
            "vaultName": row["vault_name"],
            "deviceName": row["name"],
            "fingerprint": fingerprint(parse_public_key(row["public_key"])),
            "status": row["status"],
        }
        for row in rows
    }
    unknown = {
        "username": None,
        "vaultName": None,
        "deviceName": None,
        "fingerprint": None,
        "status": None,
    }
    totals = dict(activity.devices)
    out = []
    for device_id in [*names, *(k for k in totals if k not in names)]:
        a = totals.get(device_id) or Activity()
        out.append(
            {
                "deviceId": device_id,
                **names.get(device_id, unknown),
                "requests": a.requests,
                "waits": a.waits,
                "errors4xx": a.errors4xx,
                "errors5xx": a.errors5xx,
                "requestBytes": a.request_bytes,
                "responseBytes": a.response_bytes,
                "routes": dict(a.routes),
            }
        )
    return out


async def activity(state: AppState) -> dict:
    """The admin page's Activity tab: request totals per device since the server started.
    The page adds up the changes between two answers, so its tally outlives a dropped
    device's totals."""
    return {
        "time": time.time(),
        "startedAt": state.metrics.started,
        "devices": await state.db.read(lambda: _activity(state)),
    }


async def snapshot(state: AppState) -> dict:
    """The current values as JSON, for the admin page. Counters are totals since the start:
    the page turns two snapshots into rates. Process and container values are null where
    they aren't available (process metrics need /proc, container ones a private cgroup)."""
    await _refresh_all(state)
    one: dict[str, float] = {}
    labelled: dict[str, list[tuple[dict[str, str], float]]] = {}
    for family in state.metrics.registry.collect():
        for s in family.samples:
            if s.labels:
                labelled.setdefault(s.name, []).append((s.labels, s.value))
            else:
                one[s.name] = s.value

    def by(name: str, label: str) -> dict[str, int]:
        return {labels[label]: int(v) for labels, v in labelled.get(PREFIX + name, [])}

    def histogram(name: str, keys: tuple[str, ...]) -> list[dict]:
        """Each label set's cumulative bucket counts (then +Inf) and sum."""
        out: dict[tuple[str, ...], dict] = {}
        for labels, value in labelled.get(name + "_bucket", []):
            key = tuple(labels[k] for k in keys)
            entry = out.setdefault(key, {**dict(zip(keys, key, strict=True)), "buckets": []})
            entry["buckets"].append(int(value))
        for labels, value in labelled.get(name + "_sum", []):
            out[tuple(labels[k] for k in keys)]["sum"] = value
        return list(out.values())

    ls = state.metrics.litestream
    ls_samples = ls.samples if ls is not None else {}

    def total(name: str) -> float | None:
        """A Litestream value summed over its labels, or None when Litestream lacks it."""
        values = [v for _, v in ls_samples.get(name, [])]
        return sum(values) if values else None

    def ops(name: str) -> dict[str, int]:
        return {labels["operation"]: int(v) for labels, v in ls_samples.get(name, [])}

    s3 = None
    if state.metrics.s3 is not None:
        s3 = {
            "buckets": list(S3_DURATION_BUCKETS),
            "requests": [
                {**labels, "count": int(v)}
                for labels, v in labelled.get(PREFIX + "s3_requests_total", [])
            ],
            "durations": histogram(PREFIX + "s3_request_duration_seconds", ("operation",)),
            "retries": by("s3_retries_total", "operation"),
            "uploadedBytes": int(one[PREFIX + "s3_uploaded_bytes_total"]),
            "downloadedBytes": int(one[PREFIX + "s3_downloaded_bytes_total"]),
            "inFlight": int(one[PREFIX + "s3_requests_in_flight"]),
        }
    litestream = None
    if ls is not None:
        disk_full = total("litestream_disk_full")
        litestream = {
            "up": ls.up,
            "syncs": total("litestream_sync_count_total"),
            "syncErrors": total("litestream_sync_error_count_total"),
            "syncSeconds": total("litestream_sync_seconds_total"),
            "walBytes": total("litestream_total_wal_bytes_total"),
            "dbBytes": total("litestream_db_size"),
            "walSize": total("litestream_wal_size"),
            "txid": total("litestream_txid"),
            "diskFull": None if disk_full is None else bool(disk_full),
            "replicaOperations": ops("litestream_replica_operation_total"),
            "replicaBytes": ops("litestream_replica_operation_bytes_total"),
        }
    container = PREFIX + "container_"
    return {
        "time": time.time(),
        "startedAt": state.metrics.started,
        "buckets": list(DURATION_BUCKETS),
        "requests": [
            {**labels, "count": int(v)}
            for labels, v in labelled.get(PREFIX + "http_requests_total", [])
        ],
        # `buckets` are cumulative counts per bound in `buckets` above, then +Inf.
        "durations": histogram(PREFIX + "http_request_duration_seconds", ("method", "route")),
        "process": {
            "cpuSeconds": one.get("process_cpu_seconds_total"),
            "memoryBytes": one.get("process_resident_memory_bytes"),
            "openFds": one.get("process_open_fds"),
        },
        "container": {
            "cpuSeconds": one.get(container + "cpu_seconds_total"),
            "memoryBytes": one.get(container + "memory_working_set_bytes"),
            "memoryLimitBytes": one.get(container + "memory_limit_bytes"),
        },
        "users": int(one[PREFIX + "users"]),
        "vaults": int(one[PREFIX + "vaults"]),
        "devices": by("devices", "status"),
        "files": int(one[PREFIX + "files"]),
        "revisions": int(one[PREFIX + "revisions"]),
        "blobs": int(one[PREFIX + "blobs"]),
        "blobBytes": int(one[PREFIX + "blob_bytes"]),
        "locks": int(one[PREFIX + "locks_active"]),
        "longpolls": int(one[PREFIX + "longpoll_waiters"]),
        "maintenance": bool(one[PREFIX + "maintenance"]),
        "gcRuns": by("gc_runs_total", "task"),
        "gcFailures": by("gc_failures_total", "task"),
        "requestBytes": int(one[PREFIX + "http_request_bytes_total"]),
        "responseBytes": int(one[PREFIX + "http_response_bytes_total"]),
        "inFlight": int(one[PREFIX + "http_requests_in_flight"]),
        "loopLagSeconds": one[PREFIX + "event_loop_lag_seconds"],
        "disk": {
            "freeBytes": one.get(PREFIX + "data_disk_free_bytes"),
            "totalBytes": one.get(PREFIX + "data_disk_total_bytes"),
        },
        "dbBytes": one.get(PREFIX + "db_bytes"),
        "dbWalBytes": one.get(PREFIX + "db_wal_bytes"),
        "prunedRevisions": int(one[PREFIX + "retention_pruned_revisions_total"]),
        "deletedBlobs": int(one[PREFIX + "gc_deleted_blobs_total"]),
        # Unix seconds, null until the task first ran.
        "gcLastRun": {
            task: (t or None) for task, t in by("gc_last_run_timestamp_seconds", "task").items()
        },
        "adminTokenFailures": int(one[PREFIX + "admin_token_failures_total"]),
        "sharedSecretFailures": int(one[PREFIX + "shared_secret_failures_total"]),
        # Null without S3, and without Litestream (it replicates only with blobs in S3).
        "s3": s3,
        "litestream": litestream,
    }


class RequestMetrics:
    """Count and time HTTP requests, labelled with the matched route template."""

    def __init__(self, app: ASGIApp, metrics: Metrics, skip: tuple[str, ...] = SKIP):
        self.app = app
        self.metrics = metrics
        self.skip = skip

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in self.skip:
            await self.app(scope, receive, send)
            return
        start = time.perf_counter()
        status = 500
        received = sent = 0
        m = self.metrics
        # Filled in by authentication: shared, so copies of the scope see it too.
        actor: dict[str, str] = {}
        scope[ACTOR] = actor

        async def count_body() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                n = len(message.get("body", b""))
                received += n
                m.request_bytes.inc(n)
            return message

        async def send_status(message: Message) -> None:
            nonlocal status, sent
            if message["type"] == "http.response.start":
                status = message["status"]
            elif message["type"] == "http.response.body":
                n = len(message.get("body", b""))
                sent += n
                m.response_bytes.inc(n)
            await send(message)

        m.in_flight.inc()
        try:
            await self.app(scope, count_body, send_status)
        finally:
            m.in_flight.dec()
            route = scope.get("route")
            template = getattr(route, "path", None) or "unmatched"
            method = scope["method"]
            m.requests.labels(method, template, str(status)).inc()
            m.duration.labels(method, template).observe(time.perf_counter() - start)
            m.activity.record(actor.get("device"), method, template, status, received, sent)


async def watch_loop_lag(metrics: Metrics) -> None:
    """Sleep LAG_INTERVAL again and again; how much later than asked it wakes is the lag."""
    loop = asyncio.get_running_loop()
    recent: deque[float] = deque(maxlen=LAG_WINDOW)
    while True:
        start = loop.time()
        await asyncio.sleep(LAG_INTERVAL)
        recent.append(max(loop.time() - start - LAG_INTERVAL, 0.0))
        metrics.loop_lag.set(max(recent))
