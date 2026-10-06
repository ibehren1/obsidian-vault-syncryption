"""SQLite metadata store (docs/architecture.md 2.1).

One connection in WAL mode, used only from the event loop thread. Writes go through
`transaction()`, which takes the write lock up front (`BEGIN IMMEDIATE`), so a commit's
read-check-write is serialised with every other writer. Never `await` inside a
transaction.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# The schema's `PRAGMA user_version`. Versions 1 to 4 were servers before 0.1.4, where one
# key served every vault of a user (memberships); their data can't be used and isn't migrated.
SCHEMA_VERSION = 5
OLD_DATA_MESSAGE = (
    "This server's data predates server 0.1.4 (one key per device per vault). "
    "Delete ./data (or the S3 data) and start again."
)

SCHEMA = """
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    disabled_at INTEGER
);
CREATE TABLE vaults (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    locks_seq INTEGER NOT NULL DEFAULT 0,
    keyring_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    disabled_at INTEGER,
    UNIQUE (user_id, name)
);
-- One key of one device in one vault (protocol.md 3). `vault_id` is NULL while the key
-- creates its vault (`vault_name` is then reserved for it). The status is the membership.
CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    vault_id TEXT REFERENCES vaults(id),
    vault_name TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER
);
CREATE INDEX devices_vault ON devices(vault_id, status);
CREATE INDEX devices_user_vault_name ON devices(user_id, vault_name);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_device ON sessions(device_id);
CREATE TABLE challenges (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    vault_name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    message TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE keyrings (
    vault_id TEXT NOT NULL REFERENCES vaults(id),
    version INTEGER NOT NULL,
    keyring BLOB NOT NULL,
    signature TEXT NOT NULL,
    signer TEXT NOT NULL REFERENCES devices(id),
    -- crypto.md 9: the recovery signer each version trusts, and recovery uploads
    recovery_signer TEXT,
    by_recovery INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, version)
);
CREATE TABLE files (
    vault_id TEXT NOT NULL REFERENCES vaults(id),
    file_id TEXT NOT NULL,
    head_rev INTEGER NOT NULL,
    PRIMARY KEY (vault_id, file_id)
);
CREATE TABLE revisions (
    vault_id TEXT NOT NULL REFERENCES vaults(id),
    rev INTEGER NOT NULL,
    file_id TEXT NOT NULL,
    parent_rev INTEGER,
    deleted INTEGER NOT NULL,
    meta BLOB NOT NULL,
    size INTEGER NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, rev)
);
CREATE INDEX revisions_file ON revisions(vault_id, file_id, rev);
CREATE TABLE blobs (
    vault_id TEXT NOT NULL REFERENCES vaults(id),
    blob_id TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, blob_id)
);
CREATE TABLE revision_blobs (
    vault_id TEXT NOT NULL,
    rev INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    blob_id TEXT NOT NULL,
    PRIMARY KEY (vault_id, rev, idx),
    FOREIGN KEY (vault_id, rev) REFERENCES revisions(vault_id, rev),
    FOREIGN KEY (vault_id, blob_id) REFERENCES blobs(vault_id, blob_id)
);
CREATE INDEX revision_blobs_blob ON revision_blobs(vault_id, blob_id);
CREATE TABLE locks (
    vault_id TEXT NOT NULL REFERENCES vaults(id),
    file_id TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    client_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, file_id)
);
CREATE TABLE join_attempts (
    ip TEXT NOT NULL,
    at INTEGER NOT NULL
);
CREATE INDEX join_attempts_ip ON join_attempts(ip, at);
-- protocol.md 14: browser sessions of the admin page
CREATE TABLE admin_sessions (
    token_hash TEXT PRIMARY KEY,
    csrf TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
-- protocol.md 14.1: one row while maintenance is on
CREATE TABLE maintenance (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    since INTEGER NOT NULL,
    message TEXT
);
"""

# Later schema changes: MIGRATIONS[0] takes SCHEMA_VERSION to SCHEMA_VERSION + 1, and so on.
MIGRATIONS: list[str] = []


class OldDataError(RuntimeError):
    """The database was written by a server older than 0.1.4."""

    def __init__(self) -> None:
        super().__init__(OLD_DATA_MESSAGE)


def check_version(conn: sqlite3.Connection) -> int:
    """The schema version, 0 for an empty database. Raises OldDataError for old data."""
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == 0:
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' LIMIT 1").fetchone():
            raise OldDataError()
    elif version < SCHEMA_VERSION:
        raise OldDataError()
    return version


def check_file(path: Path) -> None:
    """Refuse old data before serving (the entrypoint runs this after a Litestream restore).
    A missing file is fine: the server creates it."""
    if not path.exists():
        return
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        check_version(conn)
    finally:
        conn.close()


class Database:
    def __init__(self, path: Path | str):
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA synchronous = NORMAL")
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 5000")

    def migrate(self) -> None:
        version = check_version(self.conn)
        if version == 0:
            with self.transaction():
                for statement in SCHEMA.split(";"):
                    if statement.strip():
                        self.conn.execute(statement)
                self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            version = SCHEMA_VERSION
        done = version - SCHEMA_VERSION
        for number, script in enumerate(MIGRATIONS[done:], start=version + 1):
            with self.transaction():
                for statement in script.split(";"):
                    if statement.strip():
                        self.conn.execute(statement)
                self.conn.execute(f"PRAGMA user_version = {number}")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    def one(self, sql: str, *params: object) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def all(self, sql: str, *params: object) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def ping(self) -> None:
        self.conn.execute("SELECT 1").fetchone()

    def close(self) -> None:
        self.conn.close()
