import dataclasses
import http.server
import threading

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, ReadTimeoutError
from fastapi.testclient import TestClient
from prometheus_client import CONTENT_TYPE_PLAIN_0_0_4, CollectorRegistry
from prometheus_client.parser import text_string_to_metric_families

from syncryption_server import PROTOCOL_VERSION, __version__
from syncryption_server.app import create_app
from syncryption_server.config import parse_networks
from syncryption_server.metrics import S3_RESULTS, S3Metrics
from syncryption_server.storage import BlobNotFound, S3BlobStore, blob_key, s3_result
from tests.helpers import ADMIN_TOKEN, SECRET, Device, blob

BEARER = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def samples(client: TestClient) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"] == CONTENT_TYPE_PLAIN_0_0_4
    return {
        (s.name, tuple(sorted(s.labels.items()))): s.value
        for family in text_string_to_metric_families(r.text)
        for s in family.samples
    }


def test_metrics_report_build_and_process(client):
    m = samples(client)
    labels = (("protocol", str(PROTOCOL_VERSION)), ("version", __version__))
    assert m[("syncryption_build_info", labels)] == 1
    # Process metrics come from /proc, so only on Linux (the container).
    assert any(name == "python_info" for name, _ in m)
    assert any(name.startswith("python_gc_") for name, _ in m)


def test_metrics_count_the_server(alice):
    m = samples(alice.client)
    assert m[("syncryption_users", ())] == 1
    assert m[("syncryption_vaults", ())] == 1
    assert m[("syncryption_devices", (("status", "active"),))] == 1
    assert m[("syncryption_devices", (("status", "pending"),))] == 0
    assert m[("syncryption_maintenance", ())] == 0
    assert m[("syncryption_longpoll_waiters", ())] == 0


def test_requests_are_labelled_with_the_route_template(alice):
    alice.get(f"/api/v1/vaults/{alice.vault_id}/changes")
    alice.client.get("/no/such/path")
    r = alice.client.get("/metrics")
    assert alice.vault_id not in r.text
    assert alice.device_id not in r.text
    assert "/no/such/path" not in r.text

    m = samples(alice.client)
    changes = (
        ("method", "GET"),
        ("route", "/api/v1/vaults/{vault_id}/changes"),
        ("status", "200"),
    )
    assert m[("syncryption_http_requests_total", changes)] == 1
    unmatched = (("method", "GET"), ("route", "unmatched"), ("status", "404"))
    assert m[("syncryption_http_requests_total", unmatched)] == 1
    # The scrapes themselves aren't counted.
    assert not any(dict(labels).get("route") == "/metrics" for _, labels in m)


def test_wrong_admin_tokens_are_counted(client):
    headers = {"Authorization": "Bearer " + "x" * len(ADMIN_TOKEN)}
    assert client.get("/admin/api/status", headers=headers).status_code == 401
    assert samples(client)[("syncryption_admin_token_failures_total", ())] == 1


def test_metrics_work_during_maintenance(client):
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    assert client.post("/admin/api/maintenance/on", headers=headers).status_code == 204
    assert client.get("/api/v1/devices/self").status_code == 503
    m = samples(client)
    assert m[("syncryption_maintenance", ())] == 1
    unmatched = (("method", "GET"), ("route", "unmatched"), ("status", "503"))
    assert m[("syncryption_http_requests_total", unmatched)] == 1


def test_disable_metrics_removes_the_endpoint(settings):
    settings = dataclasses.replace(settings, disable_metrics=True)
    with TestClient(create_app(settings)) as c:
        r = c.get("/metrics")
        assert r.status_code == 404
        assert r.json()["error"] == "not_found"


def container_collector(tmp_path, own: str = "0::/", **files: str):
    from syncryption_server.metrics import ContainerCollector

    (tmp_path / "proc").mkdir()
    (tmp_path / "proc" / "cgroup").write_text(own + "\n")
    (tmp_path / "cg").mkdir()
    for name, text in files.items():
        (tmp_path / "cg" / name.replace("_", ".", 1)).write_text(text)
    return ContainerCollector(cgroup=tmp_path / "cg", proc=tmp_path / "proc")


def collected(collector) -> dict[str, float]:
    return {s.name: s.value for family in collector.collect() for s in family.samples}


def test_container_metrics_come_from_the_cgroup(tmp_path):
    c = container_collector(
        tmp_path,
        memory_current="1000\n",
        memory_stat="anon 600\ninactive_file 300\nactive_file 100\n",
        memory_max="4096\n",
        cpu_stat="usage_usec 2500000\nuser_usec 2000000\n",
    )
    assert collected(c) == {
        "syncryption_container_memory_bytes": 1000,
        "syncryption_container_memory_working_set_bytes": 700,
        "syncryption_container_memory_limit_bytes": 4096,
        "syncryption_container_cpu_seconds_total": 2.5,
    }


def test_container_metrics_leave_out_no_limit(tmp_path):
    c = container_collector(tmp_path, memory_current="1000", memory_max="max")
    assert "syncryption_container_memory_limit_bytes" not in collected(c)


def test_container_metrics_need_a_private_cgroup_namespace(tmp_path):
    # In the host's namespace, /sys/fs/cgroup would be the whole host.
    c = container_collector(tmp_path, own="0::/system.slice/docker-abc.scope", memory_current="1")
    assert collected(c) == {}


def test_container_metrics_are_absent_without_cgroup_files(tmp_path):
    from syncryption_server.metrics import ContainerCollector

    assert collected(ContainerCollector(cgroup=tmp_path / "no", proc=tmp_path / "no")) == {}


def test_metrics_answer_only_allowed_addresses(settings):
    # Empty METRICS_ALLOWED_IPS: loopback and private ranges.
    for peer, status in [
        ("127.0.0.1", 200),
        ("10.1.2.3", 200),
        ("192.168.1.5", 200),
        ("203.0.113.7", 403),
        ("2001:db8::1", 403),
    ]:
        with TestClient(create_app(settings), client=(peer, 50000)) as c:
            r = c.get("/metrics")
            assert r.status_code == status, peer
            if status == 403:
                assert r.json()["error"] == "forbidden"


def test_metrics_allowed_ips_can_be_narrowed(settings):
    settings = dataclasses.replace(settings, metrics_allowed=parse_networks("10.0.0.5"))
    with TestClient(create_app(settings), client=("10.0.0.5", 50000)) as c:
        assert c.get("/metrics").status_code == 200
    with TestClient(create_app(settings), client=("10.0.0.6", 50000)) as c:
        assert c.get("/metrics").status_code == 403


def test_metrics_check_the_client_behind_a_trusted_proxy(settings):
    settings = dataclasses.replace(settings, behind_proxy=True)
    with TestClient(create_app(settings), client=("172.18.0.2", 50000)) as c:
        # The proxy forwards a public client: refused. A spoofed header can't add one.
        assert c.get("/metrics", headers={"x-forwarded-for": "203.0.113.7"}).status_code == 403
        assert c.get("/metrics", headers={"x-forwarded-for": "10.0.0.9"}).status_code == 200
    with TestClient(create_app(settings), client=("203.0.113.7", 50000)) as c:
        # Not a trusted proxy: its header doesn't count, and its own address is public.
        assert c.get("/metrics", headers={"x-forwarded-for": "10.0.0.9"}).status_code == 403


def test_local_storage_has_no_s3_metrics(client):
    assert not any(name.startswith("syncryption_s3_") for name, _ in samples(client))


def test_s3_calls_are_counted_and_timed(settings, clock, s3_settings):
    settings = dataclasses.replace(settings, s3=s3_settings)
    app = create_app(settings, clock=clock)
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        d = Device(c, "alice", name="MacBook")
        d.login(SECRET)
        d.create_vault()
        blob_id, data = blob(b"ciphertext")
        url = f"/api/v1/vaults/{d.vault_id}/blobs/{blob_id}"
        assert d.put(url, content=data).status_code == 201
        assert d.get(url).content == data
        assert c.get("/health").status_code == 200
        m = samples(c)

    def requests(op: str, result: str = "ok") -> float:
        return m[("syncryption_s3_requests_total", (("operation", op), ("result", result)))]

    assert requests("put") == 1
    assert requests("get") == 1
    assert requests("ping") == 1
    assert requests("delete") == 0
    assert m[("syncryption_s3_request_duration_seconds_count", (("operation", "put"),))] == 1
    assert m[("syncryption_s3_uploaded_bytes_total", ())] == len(data)
    assert m[("syncryption_s3_downloaded_bytes_total", ())] == len(data)
    assert m[("syncryption_s3_requests_in_flight", ())] == 0
    # No label names a bucket, key, user or vault.
    text = "\n".join(str(labels) for _, labels in m)
    assert s3_settings.bucket not in text
    assert d.vault_id not in text


async def test_s3_failures_are_counted_by_result(s3_settings):
    s3 = S3Metrics(CollectorRegistry())
    store = S3BlobStore(s3_settings, s3)
    await store.start()
    try:
        key = blob_key("user", "vault", "ab" + "0" * 62)
        assert await store.size(key) is None
        with pytest.raises(BlobNotFound):
            await store.get(key)
        await store.put(key, b"x")
        assert [k async for k in store.iter_keys()] == [key]
    finally:
        await store.close()
    assert s3.requests.labels("head", "not_found")._value.get() == 1
    assert s3.requests.labels("get", "not_found")._value.get() == 1
    assert s3.requests.labels("list", "ok")._value.get() == 1
    assert s3.downloaded._value.get() == 0


def client_error(code: str, status: int) -> ClientError:
    response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}
    return ClientError(response, "PutObject")  # type: ignore[arg-type]


def test_s3_results_never_carry_the_raw_error_code():
    assert s3_result(client_error("NoSuchKey", 404)) == "not_found"
    assert s3_result(client_error("SlowDown", 503)) == "throttled"
    assert s3_result(client_error("TooManyRequests", 429)) == "throttled"
    assert s3_result(client_error("AccessDenied", 403)) == "client_error"
    assert s3_result(client_error("InternalError", 500)) == "server_error"
    assert s3_result(client_error("whatever-a-provider-says", 0)) == "server_error"
    assert s3_result(EndpointConnectionError(endpoint_url="http://s3")) == "connection"
    assert s3_result(ReadTimeoutError(endpoint_url="http://s3")) == "connection"
    assert s3_result(ValueError()) == "other"
    assert {
        s3_result(e)
        for e in (client_error("NoSuchKey", 404), client_error("SlowDown", 503), ValueError())
    } <= set(S3_RESULTS)


# What Litestream 0.5.17 serves while it replicates to S3 (its Go metrics trimmed).
LITESTREAM_TEXT = """\
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 21
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 0.5
# HELP litestream_db_size The current size of the real DB
# TYPE litestream_db_size gauge
litestream_db_size{db="/data/meta.db"} 8192
# HELP litestream_disk_full Whether replication is paused because the local disk is full
# TYPE litestream_disk_full gauge
litestream_disk_full{db="/data/meta.db"} 0
# HELP litestream_replica_operation_bytes The number of bytes used by replica operations
# TYPE litestream_replica_operation_bytes counter
litestream_replica_operation_bytes{operation="PUT",replica_type="s3"} 1325
# HELP litestream_replica_operation_total The number of replica operations performed
# TYPE litestream_replica_operation_total counter
litestream_replica_operation_total{operation="PUT",replica_type="s3"} 3
# HELP litestream_sync_count Number of sync operations performed
# TYPE litestream_sync_count counter
litestream_sync_count{db="/data/meta.db"} 7
# HELP litestream_sync_error_count Number of sync errors that have occurred
# TYPE litestream_sync_error_count counter
litestream_sync_error_count{db="/data/meta.db"} 1
# HELP litestream_sync_seconds Time spent syncing shadow WAL, in seconds
# TYPE litestream_sync_seconds counter
litestream_sync_seconds{db="/data/meta.db"} 0.25
# HELP litestream_total_wal_bytes Total number of bytes written to shadow WAL
# TYPE litestream_total_wal_bytes counter
litestream_total_wal_bytes{db="/data/meta.db"} 20600
# HELP litestream_txid The current transaction ID
# TYPE litestream_txid gauge
litestream_txid{db="/data/meta.db"} 2
# HELP litestream_wal_size The current size of the real WAL
# TYPE litestream_wal_size gauge
litestream_wal_size{db="/data/meta.db"} 20632
"""


@pytest.fixture
def litestream():
    """A stand-in for Litestream's metrics listener; yields its `host:port`."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = LITESTREAM_TEXT.encode()
            self.send_response(200 if self.path == "/metrics" else 404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_litestream_metrics_are_passed_on(settings, litestream):
    settings = dataclasses.replace(settings, litestream_metrics=litestream)
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as c:
        text = c.get("/metrics").text
        m = samples(c)  # the whole page still parses
        snap = c.get("/admin/api/performance", headers=BEARER).json()
    assert m[("syncryption_litestream_up", ())] == 1
    # Under Litestream's own names, which a parser would give a `_total`.
    assert "# TYPE litestream_sync_count counter\n" in text
    assert 'litestream_sync_count{db="/data/meta.db"} 7\n' in text
    assert 'litestream_txid{db="/data/meta.db"} 2\n' in text
    assert 'litestream_replica_operation_total{operation="PUT",replica_type="s3"} 3\n' in text
    # Litestream's Go and process metrics would clash with the server's own.
    assert "go_goroutines" not in text
    assert "process_cpu_seconds_total 0.5" not in text
    assert snap["litestream"] == {
        "up": True,
        "syncs": 7,
        "syncErrors": 1,
        "syncSeconds": 0.25,
        "walBytes": 20600,
        "dbBytes": 8192,
        "walSize": 20632,
        "txid": 2,
        "diskFull": False,
        "replicaOperations": {"PUT": 3},
        "replicaBytes": {"PUT": 1325},
    }
    assert snap["s3"] is None


def test_litestream_down_is_reported(settings, unused_tcp_port):
    address = f"127.0.0.1:{unused_tcp_port}"
    settings = dataclasses.replace(settings, litestream_metrics=address)
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as c:
        m = samples(c)
        snap = c.get("/admin/api/performance", headers=BEARER).json()
    assert m[("syncryption_litestream_up", ())] == 0
    assert not any(name.startswith("litestream_") for name, _ in m)
    assert snap["litestream"]["up"] is False
    assert snap["litestream"]["syncs"] is None
    assert snap["litestream"]["replicaOperations"] == {}


def test_without_litestream_there_is_no_litestream_metric(client):
    assert not any("litestream" in name for name, _ in samples(client))
    assert client.get("/admin/api/performance", headers=BEARER).json()["litestream"] is None


def test_snapshot_reports_s3_calls(settings, s3_settings):
    settings = dataclasses.replace(settings, s3=s3_settings)
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as c:
        d = Device(c, "alice", name="MacBook")
        d.login(SECRET)
        d.create_vault()
        blob_id, data = blob(b"ciphertext")
        assert d.put(f"/api/v1/vaults/{d.vault_id}/blobs/{blob_id}", content=data).status_code
        s3 = c.get("/admin/api/performance", headers=BEARER).json()["s3"]
    (put,) = [r for r in s3["requests"] if r["operation"] == "put" and r["result"] == "ok"]
    assert put["count"] == 1
    (d,) = [x for x in s3["durations"] if x["operation"] == "put"]
    assert len(d["buckets"]) == len(s3["buckets"]) + 1 and d["buckets"][-1] == 1
    assert s3["uploadedBytes"] == len(data) and s3["downloadedBytes"] == 0
    assert s3["retries"]["put"] == 0 and s3["inFlight"] == 0
