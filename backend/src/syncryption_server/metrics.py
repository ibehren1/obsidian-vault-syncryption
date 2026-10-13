"""Prometheus metrics, served at `/metrics` unless `DISABLE_METRICS=TRUE`, and the same
numbers as JSON for the admin page's Performance tab (`snapshot`), which works either way.

Only counts: no label carries a username, vault name, id, path or key. Request metrics are
labelled with the route template, never the raw path.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from collections import deque
from collections.abc import Iterator
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
from prometheus_client.platform_collector import PlatformCollector
from prometheus_client.process_collector import ProcessCollector
from prometheus_client.registry import Collector
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from syncryption_server import PROTOCOL_VERSION, __version__

if TYPE_CHECKING:
    from syncryption_server.state import AppState

PREFIX = "syncryption_"
# Up to a minute, so `/wait` long-polls land in a bucket of their own.
DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)
DEVICE_STATUSES = ("pending", "active", "revoked")
GC_TASKS = ("retention", "blobs")
# The event-loop lag: measured every LAG_INTERVAL seconds, the worst of the last LAG_WINDOW.
LAG_INTERVAL = 0.5
LAG_WINDOW = 20
# Not counted: the scrapes and the admin page's own polling.
SKIP = ("/metrics", "/admin/performance.json", "/admin/api/performance")


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


class Metrics:
    """The collectors of one app. Each app has its own registry, so several apps can run in
    one process (the tests build many)."""

    def __init__(self, data_dir: Path | None = None) -> None:
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


async def render(state: AppState) -> bytes:
    """Refresh the gauges from the database and the process, then serialize."""
    await _refresh_all(state)
    return generate_latest(state.metrics.registry)


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

    durations: dict[tuple[str, str], dict] = {}
    for labels, value in labelled.get(PREFIX + "http_request_duration_seconds_bucket", []):
        key = (labels["method"], labels["route"])
        entry = durations.setdefault(key, {"method": key[0], "route": key[1], "buckets": []})
        entry["buckets"].append(int(value))
    for labels, value in labelled.get(PREFIX + "http_request_duration_seconds_sum", []):
        durations[(labels["method"], labels["route"])]["sum"] = value
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
        "durations": list(durations.values()),
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
        m = self.metrics

        async def count_body() -> Message:
            message = await receive()
            if message["type"] == "http.request":
                m.request_bytes.inc(len(message.get("body", b"")))
            return message

        async def send_status(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            elif message["type"] == "http.response.body":
                m.response_bytes.inc(len(message.get("body", b"")))
            await send(message)

        m.in_flight.inc()
        try:
            await self.app(scope, count_body, send_status)
        finally:
            m.in_flight.dec()
            route = scope.get("route")
            template = getattr(route, "path", None) or "unmatched"
            method = scope["method"]
            self.metrics.requests.labels(method, template, str(status)).inc()
            self.metrics.duration.labels(method, template).observe(time.perf_counter() - start)


async def watch_loop_lag(metrics: Metrics) -> None:
    """Sleep LAG_INTERVAL again and again; how much later than asked it wakes is the lag."""
    loop = asyncio.get_running_loop()
    recent: deque[float] = deque(maxlen=LAG_WINDOW)
    while True:
        start = loop.time()
        await asyncio.sleep(LAG_INTERVAL)
        recent.append(max(loop.time() - start - LAG_INTERVAL, 0.0))
        metrics.loop_lag.set(max(recent))
