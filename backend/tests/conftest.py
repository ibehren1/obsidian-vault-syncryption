import uuid

import boto3
import pytest
from fastapi.testclient import TestClient
from moto.server import ThreadedMotoServer

from syncryption_server.app import create_app
from syncryption_server.config import S3Settings, Settings
from tests.helpers import ADMIN_TOKEN, SECRET, Device


class FakeClock:
    def __init__(self) -> None:
        self.t = 1_790_000_000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        shared_secret=SECRET,
        admin_token=ADMIN_TOKEN,
        url="https://notes.example.com",
        data_dir=tmp_path,
    )


@pytest.fixture
def client(settings, clock):
    with TestClient(create_app(settings, clock=clock)) as c:
        yield c


@pytest.fixture
def alice(client) -> Device:
    """The first device of a new user, logged in and active in its new vault "Personal"."""
    d = Device(client, "alice", name="MacBook")
    d.login(SECRET)
    d.create_vault()
    return d


@pytest.fixture(scope="session")
def moto_endpoint():
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    host, port = server.get_host_and_port()
    yield f"http://{host}:{port}"
    server.stop()


@pytest.fixture
def s3_settings(moto_endpoint):
    bucket = f"test-{uuid.uuid4().hex}"
    s3 = boto3.client(
        "s3",
        endpoint_url=moto_endpoint,
        region_name="eu-west-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",  # noqa: S106
    )
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
    return S3Settings(bucket, "test", "test", endpoint_url=moto_endpoint)
