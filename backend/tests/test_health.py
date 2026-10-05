from fastapi.testclient import TestClient

from syncryption_server import __version__
from syncryption_server.app import VERSION_HEADER, create_app
from syncryption_server.storage import LocalBlobStore


def test_health_reports_ok_and_version(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}
    assert response.headers[VERSION_HEADER] == __version__


class UnreachableStore(LocalBlobStore):
    async def ping(self) -> None:
        raise OSError("store unreachable")


def test_health_is_503_when_the_blob_store_is_unreachable(settings):
    # A stub rather than chmod: CI runs as root, which ignores file permissions.
    store = UnreachableStore(settings.data_dir)
    with TestClient(create_app(settings, store=store)) as c:
        assert c.get("/health").status_code == 503


def test_errors_use_the_protocol_format(client):
    r = client.get("/api/v1/nope")
    assert r.status_code == 404
    assert r.json()["error"] == "not_found"
    assert r.headers[VERSION_HEADER] == __version__
