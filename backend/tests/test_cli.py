import json

import pytest

from syncryption_server.__main__ import main
from syncryption_server.migrate import FROM_MARKER

ADMIN = "admin-token-" + "f" * 32
BASE = {
    "SHARED_SECRET": "very-secret-value",
    "ADMIN_TOKEN": ADMIN,
    "URL": "https://notes.example.com",
}
S3 = {"S3_BUCKET": "bucket", "S3_ACCESS_KEY": "AKIA-key", "S3_SECRET_KEY": "s3-secret"}


@pytest.fixture
def env(monkeypatch):
    def set_env(values):
        for name in (
            "BEHIND_PROXY",
            "URL",
            "SHARED_SECRET",
            "ADMIN_TOKEN",
            "MIGRATE_TO_S3",
            "MIGRATE_FROM_S3",
            "SYNCRYPTION_DATA_DIR",
            "S3_ENDPOINT",
        ):
            monkeypatch.delenv(name, raising=False)
        for name in S3:
            monkeypatch.delenv(name, raising=False)
        for name, value in values.items():
            monkeypatch.setenv(name, value)

    return set_env


def test_check_reports_errors(env, capsys):
    env({"SHARED_SECRET": "x" * 16, "ADMIN_TOKEN": ADMIN})
    assert main(["check"]) == 1
    assert "URL is required" in capsys.readouterr().err


def test_check_never_prints_secrets(env, capsys):
    env({**BASE, **S3, "S3_ENDPOINT": "http://minio:9000"})
    assert main(["check"]) == 0
    out = capsys.readouterr().out
    assert "bucket" in out and "minio" in out
    for secret in ("very-secret", ADMIN, "AKIA-key", "s3-secret"):
        assert secret not in out


def test_render_with_caddy_and_litestream(env, tmp_path, capsys):
    env({**BASE, **S3, "S3_ENDPOINT": "http://minio:9000"})
    assert main(["render", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "behind_proxy=FALSE" in out and "s3_enabled=TRUE" in out
    assert "replicate=TRUE" in out and "migrate=FALSE" in out
    caddy = (tmp_path / "Caddyfile").read_text()
    assert "https://notes.example.com {" in caddy
    assert "reverse_proxy 127.0.0.1:8000" in caddy
    litestream = (tmp_path / "litestream.yml").read_text()
    assert "bucket: bucket" in litestream
    assert "${S3_SECRET_KEY}" in litestream and "s3-secret" not in litestream
    assert "endpoint: ${S3_ENDPOINT}" in litestream


def test_render_while_moving_off_s3(env, tmp_path, capsys):
    env({**BASE, **S3, "MIGRATE_FROM_S3": "TRUE"})
    assert main(["render", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "s3_enabled=TRUE" in out and "migrate=TRUE" in out and "replicate=FALSE" in out
    # Still written: the entrypoint restores the database from the replica first.
    assert (tmp_path / "litestream.yml").exists()


def test_check_describes_the_move_off_s3(env, capsys):
    env({**BASE, **S3, "MIGRATE_FROM_S3": "TRUE"})
    assert main(["check"]) == 0
    out = capsys.readouterr().out
    assert "local blobs in" in out and "from S3 bucket bucket to local storage" in out


def test_check_data_refuses_s3_after_moving_off_it(env, tmp_path, capsys):
    (tmp_path / FROM_MARKER).write_text("done\n")
    env({**BASE, **S3, "SYNCRYPTION_DATA_DIR": str(tmp_path)})
    assert main(["check-data"]) == 1
    assert "moved off S3" in capsys.readouterr().err
    for flags in ({"MIGRATE_FROM_S3": "TRUE"}, {"MIGRATE_TO_S3": "TRUE"}):
        env({**BASE, **S3, "SYNCRYPTION_DATA_DIR": str(tmp_path), **flags})
        assert main(["check-data"]) == 0
    env({**BASE, "SYNCRYPTION_DATA_DIR": str(tmp_path)})
    assert main(["check-data"]) == 0


def test_render_behind_proxy_without_s3(env, tmp_path, capsys):
    env({"SHARED_SECRET": "x" * 16, "ADMIN_TOKEN": ADMIN, "BEHIND_PROXY": "TRUE"})
    assert main(["render", str(tmp_path)]) == 0
    assert "behind_proxy=TRUE" in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == []


def test_litestream_uses_aws_without_an_endpoint(env, tmp_path):
    env({**BASE, **S3})
    main(["render", str(tmp_path)])
    assert "endpoint" not in (tmp_path / "litestream.yml").read_text()


def test_openapi_needs_no_environment(env, capsys):
    env({})
    assert main(["openapi"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert "/api/v1/vaults/{vault_id}/files/{file_id}" in schema["paths"]
