import dataclasses

from fastapi.testclient import TestClient
from prometheus_client import CONTENT_TYPE_PLAIN_0_0_4
from prometheus_client.parser import text_string_to_metric_families

from syncryption_server import PROTOCOL_VERSION, __version__
from syncryption_server.app import create_app
from syncryption_server.config import parse_networks
from tests.helpers import ADMIN_TOKEN


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
