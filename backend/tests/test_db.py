"""The schema version, and refusing data from servers before 0.1.4."""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from syncryption_server.__main__ import main
from syncryption_server.app import create_app
from syncryption_server.db import OLD_DATA_MESSAGE, SCHEMA_VERSION, Database, OldDataError
from tests.helpers import SECRET, Device


def old_database(path, version: int = 4) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE memberships (vault_id TEXT, device_id TEXT)")
    conn.execute(f"PRAGMA user_version = {version}")
    conn.commit()
    conn.close()


def test_a_new_database_gets_the_schema(tmp_path):
    db = Database(tmp_path / "meta.db")
    db.migrate()
    assert db.one("PRAGMA user_version")[0] == SCHEMA_VERSION
    tables = {r[0] for r in db.all("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "devices" in tables and "memberships" not in tables
    db.migrate()  # again: nothing to do
    db.close()


@pytest.mark.parametrize("version", [0, 1, 4])
def test_old_data_is_refused(tmp_path, version):
    old_database(tmp_path / "meta.db", version)
    db = Database(tmp_path / "meta.db")
    with pytest.raises(OldDataError, match="predates server 0.1.4"):
        db.migrate()
    db.close()


def test_the_server_refuses_to_start_with_old_data(settings, caplog):
    old_database(settings.db_path)
    with pytest.raises(OldDataError), TestClient(create_app(settings)):
        pass
    assert OLD_DATA_MESSAGE in caplog.text


def test_data_survives_a_restart(settings, clock):
    with TestClient(create_app(settings, clock=clock)) as c:
        d = Device(c, "alice")
        d.login(SECRET)
        d.create_vault()
    with TestClient(create_app(settings, clock=clock)) as c:
        d.client = c
        assert d.login()["vaultId"] == d.vault_id


def test_check_data_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SHARED_SECRET", "x")
    monkeypatch.setenv("ADMIN_TOKEN", "a" * 32)
    monkeypatch.setenv("BEHIND_PROXY", "TRUE")
    monkeypatch.setenv("SYNCRYPTION_DATA_DIR", str(tmp_path))
    assert main(["check-data"]) == 0  # no database yet
    assert not (tmp_path / "meta.db").exists()
    db = Database(tmp_path / "meta.db")
    db.migrate()
    db.close()
    assert main(["check-data"]) == 0
    (tmp_path / "meta.db").unlink()
    old_database(tmp_path / "meta.db")
    assert main(["check-data"]) == 1
    assert "Delete ./data (or the S3 data)" in capsys.readouterr().err
