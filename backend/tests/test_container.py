"""End-to-end checks against a running container. Skipped unless SYNCRYPTION_URL is set.

    docker compose -f docker-compose.dev.yml up --build -d
    SYNCRYPTION_URL=http://127.0.0.1:8080 SYNCRYPTION_SECRET=dev-secret uv run pytest \
        tests/test_container.py

With SYNCRYPTION_ADMIN_TOKEN set, it also turns maintenance on and off again.

It also runs without pytest, inside the image (see backend/container-checks.sh):
    python -m tests.test_container
"""

import json
import os
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from tests.helpers import Device, blob, file_id

URL = os.environ.get("SYNCRYPTION_URL", "")
ADMIN_TOKEN = os.environ.get("SYNCRYPTION_ADMIN_TOKEN", "")

try:
    import pytest
except ImportError:  # inside the container image
    pass
else:
    pytestmark = pytest.mark.skipif(not URL, reason="set SYNCRYPTION_URL to run")


@dataclass
class Response:
    status_code: int
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode()

    def json(self) -> Any:
        return json.loads(self.content)


class Client:
    """The few TestClient methods the helpers use, over urllib."""

    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def request(self, method: str, path: str, headers=None, json_body=None, content=None):
        headers = dict(headers or {})
        data = content
        if json_body is not None:
            data = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        url = self.base + path
        req = urllib.request.Request(url, data=data, method=method, headers=headers)  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310
                return Response(r.status, r.read())
        except urllib.error.HTTPError as e:
            return Response(e.code, e.read())

    def get(self, path, headers=None, **_):
        return self.request("GET", path, headers)

    def post(self, path, headers=None, json=None, content=None):
        return self.request("POST", path, headers, json, content)

    def put(self, path, headers=None, json=None, content=None):
        return self.request("PUT", path, headers, json, content)

    def delete(self, path, headers=None, **_):
        return self.request("DELETE", path, headers)


def test_health():
    r = Client(URL).get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_home_page():
    r = Client(URL).get("/")
    assert r.status_code == 200
    assert "Vault Syncryption server" in r.text and "Status: ok" in r.text


def test_maintenance():
    if not ADMIN_TOKEN:
        return
    client = Client(URL)
    admin = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    r = client.post("/admin/api/maintenance/on", admin, json={"message": "container check"})
    assert r.status_code == 204, r.text
    try:
        r = client.get("/api/v1/devices/self")
        assert (r.status_code, r.json()["error"]) == (503, "maintenance")
        health = client.get("/health")
        assert (health.status_code, health.json()["status"]) == (200, "maintenance")
    finally:
        assert client.post("/admin/api/maintenance/off", admin).status_code == 204
    assert client.get("/health").json()["status"] == "ok"


def test_join_create_upload_and_commit():
    client = Client(URL)
    alice = Device(client, f"smoke-{secrets.token_hex(4)}", name="Smoke")
    alice.login(os.environ.get("SYNCRYPTION_SECRET", "dev-secret"))
    vault = alice.create_vault()

    blob_id, data = blob(secrets.token_bytes(1000))
    r = alice.put(f"/api/v1/vaults/{vault}/blobs/{blob_id}", content=data)
    assert r.status_code == 201, r.text
    assert alice.get(f"/api/v1/vaults/{vault}/blobs/{blob_id}").content == data

    body = {"parentRev": None, "deleted": False, "meta": "bWV0YQ", "blobs": [blob_id]}
    r = alice.put(f"/api/v1/vaults/{vault}/files/{file_id()}", json=body)
    assert r.status_code == 201, r.text
    r = alice.put(f"/api/v1/vaults/{vault}/files/{file_id()}", json=body)
    assert r.status_code == 409
    changes = alice.get(f"/api/v1/vaults/{vault}/changes?since=0").json()["changes"]
    assert [c["fileId"] for c in changes] == [file_id()]


if __name__ == "__main__":
    for check in (
        test_health,
        test_home_page,
        test_maintenance,
        test_join_create_upload_and_commit,
    ):
        check()
        print(f"ok {check.__name__}")
