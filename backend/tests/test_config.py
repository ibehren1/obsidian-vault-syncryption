from pathlib import Path

import pytest

from syncryption_server.config import ConfigError, load_settings

ADMIN = {"ADMIN_TOKEN": "t" * 32}
BASE = {"SHARED_SECRET": "s", **ADMIN, "URL": "https://Notes.Example.com/"}


def test_defaults():
    s = load_settings(BASE)
    assert s.behind_proxy is False
    assert s.url == "https://notes.example.com"
    assert s.s3 is None
    assert s.migrate_to_s3 is False
    assert s.data_dir == Path("/data")
    assert s.admin_token == "t" * 32
    assert s.admin_contact == ""


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"SHARED_SECRET": "s", **ADMIN}, "URL is required"),
        ({"SHARED_SECRET": "s", **ADMIN, "BEHIND_PROXY": "FALSE"}, "URL is required"),
        ({"URL": "https://a.example", **ADMIN}, "SHARED_SECRET is required"),
        ({**BASE, "ADMIN_TOKEN": ""}, "ADMIN_TOKEN is required"),
        ({**BASE, "ADMIN_TOKEN": "t" * 31}, "ADMIN_TOKEN must be at least 32"),
        ({**BASE, "SHARED_SECRET": "  "}, "SHARED_SECRET is required"),
        ({**BASE, "BEHIND_PROXY": "yes"}, "BEHIND_PROXY must be TRUE or FALSE"),
        ({**BASE, "URL": "ftp://a.example"}, "URL must look like"),
        ({**BASE, "URL": "https://a.example/sync"}, "origin only"),
        ({**BASE, "S3_BUCKET": "b"}, "S3_ACCESS_KEY, S3_SECRET_KEY empty"),
        ({**BASE, "S3_BUCKET": "b", "S3_ACCESS_KEY": "k"}, "S3_SECRET_KEY empty"),
        ({**BASE, "MIGRATE_TO_S3": "TRUE"}, "MIGRATE_TO_S3=TRUE needs"),
        ({**BASE, "ADMIN_CONTACT": "x" * 501}, "ADMIN_CONTACT must be at most 500"),
        ({**BASE, "ADMIN_CONTACT": "a\nb"}, "ADMIN_CONTACT must be a single line"),
        ({**BASE, "ADMIN_CONTACT": "a\tb"}, "ADMIN_CONTACT must be a single line"),
        ({**BASE, "S3_ENDPOINT": "https://s3.example.com"}, "S3_ENDPOINT needs"),
        (
            {
                **BASE,
                "S3_BUCKET": "b",
                "S3_ACCESS_KEY": "k",
                "S3_SECRET_KEY": "x",
                "S3_ENDPOINT": "s3",
            },
            "S3_ENDPOINT must look like",
        ),
    ],
)
def test_invalid(env, message):
    with pytest.raises(ConfigError, match=message):
        load_settings(env)


def test_behind_proxy_without_url():
    s = load_settings({"SHARED_SECRET": "s", **ADMIN, "BEHIND_PROXY": "true"})
    assert s.behind_proxy is True
    assert s.url is None


def test_s3_and_migration():
    s = load_settings(
        {
            **BASE,
            "S3_BUCKET": "b",
            "S3_ACCESS_KEY": "k",
            "S3_SECRET_KEY": "x",
            "MIGRATE_TO_S3": "TRUE",
            "SYNCRYPTION_DATA_DIR": "/tmp/dev",
        }
    )
    assert (s.s3.bucket, s.s3.access_key, s.s3.secret_key) == ("b", "k", "x")
    assert s.s3.endpoint_url is None
    assert s.migrate_to_s3 is True
    assert s.db_path == Path("/tmp/dev/meta.db")


def test_url_keeps_non_default_port():
    assert load_settings({**BASE, "URL": "http://localhost:8080"}).url == "http://localhost:8080"
    assert load_settings({**BASE, "URL": "https://a.example:443"}).url == "https://a.example"


def test_s3_endpoint():
    s = load_settings(
        {
            **BASE,
            "S3_BUCKET": "b",
            "S3_ACCESS_KEY": "k",
            "S3_SECRET_KEY": "x",
            "S3_ENDPOINT": "https://minio.example.com:9000",
        }
    )
    assert s.s3.endpoint_url == "https://minio.example.com:9000"


def test_admin_contact():
    s = load_settings({**BASE, "ADMIN_CONTACT": "  Ops <ops@example.com>, #help on Slack \n"})
    assert s.admin_contact == "Ops <ops@example.com>, #help on Slack"
    assert load_settings({**BASE, "ADMIN_CONTACT": "é" * 500}).admin_contact == "é" * 500
