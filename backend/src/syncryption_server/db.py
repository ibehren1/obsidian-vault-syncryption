"""SQLite metadata store (docs/architecture.md 2.1).

WAL mode, and no query on the event loop thread, so a slow query never holds up the loop.
Handlers pass each piece of work that must be consistent as one function:
- `run()` for anything that writes: one connection on one database thread, so these
  functions run one at a time, in order. Writes go through `transaction()`, which takes the
  write lock up front (`BEGIN IMMEDIATE`), so a commit's read-check-write is serialised with
  every other writer.
- `read()` for work that only reads: READERS threads, each with its own read-only
  connection, beside the database thread and each other. Each function runs in one read
  transaction, so it sees one snapshot: everything committed before it started.
Inside either, wait only on SQLite.
"""

import asyncio
import sqlite3
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

# The schema's `PRAGMA user_version`. Versions 1 to 4 were servers before 0.1.4, where one
# key served every vault of a user (memberships); their data can't be used and isn't migrated.
# BASE_VERSION is the oldest schema that is migrated; SCHEMA_VERSION is the current one.
BASE_VERSION = 5
# Read-only connections for `Database.read`, each on its own thread.
READERS = 5
SCHEMA_VERSION = 6
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
    -- The key epoch of the meta header (crypto.md 8.1), for retention (protocol.md 9.3).
    epoch INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (vault_id, rev)
);
CREATE INDEX revisions_file ON revisions(vault_id, file_id, rev);
CREATE INDEX revisions_file_epoch ON revisions(vault_id, file_id, epoch);
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


def _revision_epochs(conn: sqlite3.Connection) -> None:
    """Schema 6: `revisions.epoch`, filled in from each meta header (crypto.md 8.1)."""
    conn.execute("ALTER TABLE revisions ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1")
    rows = conn.execute("SELECT vault_id, rev, meta FROM revisions").fetchall()
    updates = [
        (int.from_bytes(meta[1:5], "big"), vault_id, rev)
        for vault_id, rev, meta in rows
        if len(meta) >= 5 and meta[0] == 1 and int.from_bytes(meta[1:5], "big") > 1
    ]
    conn.executemany("UPDATE revisions SET epoch = ? WHERE vault_id = ? AND rev = ?", updates)
    conn.execute("CREATE INDEX revisions_file_epoch ON revisions(vault_id, file_id, epoch)")


# Later schema changes: MIGRATIONS[0] takes BASE_VERSION to BASE_VERSION + 1, and so on. An
# entry is an SQL script or a function that gets the connection; each runs in a transaction.
MIGRATIONS: list[str | Callable[[sqlite3.Connection], None]] = [_revision_epochs]


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
    elif version < BASE_VERSION:
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


def _off_loop() -> None:
    """Queries must not run on the event loop thread: they go through `Database.run`."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError("The database was used on the event loop thread: use Database.run.")


class Database:
    def __init__(self, path: Path | str):
        self._path = Path(path)
        self._conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sqlite")
        self._read_executor = ThreadPoolExecutor(
            max_workers=READERS, thread_name_prefix="sqlite-read"
        )
        self._local = threading.local()  # a reader thread's connection
        self._readers: list[sqlite3.Connection] = []
        self._readers_lock = threading.Lock()

    @property
    def conn(self) -> sqlite3.Connection:
        """The connection of this thread: the reader's on a reader thread, else the writer."""
        _off_loop()
        return getattr(self._local, "conn", None) or self._conn

    async def run[T](self, fn: Callable[[], T]) -> T:
        """Run `fn` on the database thread, after every function passed before it."""
        return await asyncio.get_running_loop().run_in_executor(self._executor, fn)

    async def read[T](self, fn: Callable[[], T]) -> T:
        """Run `fn`, which only reads, on a reader thread, in one read transaction."""
        return await asyncio.get_running_loop().run_in_executor(self._read_executor, self._read, fn)

    def _read[T](self, fn: Callable[[], T]) -> T:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                f"{self._path.resolve().as_uri()}?mode=ro",
                uri=True,
                isolation_level=None,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 5000")
            self._local.conn = conn
            with self._readers_lock:
                self._readers.append(conn)
        conn.execute("BEGIN")
        try:
            return fn()
        finally:
            conn.execute("ROLLBACK")

    def migrate(self) -> None:
        version = check_version(self.conn)
        if version == 0:
            with self.transaction():
                for statement in SCHEMA.split(";"):
                    if statement.strip():
                        self.conn.execute(statement)
                self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            version = SCHEMA_VERSION
        done = version - BASE_VERSION
        for number, step in enumerate(MIGRATIONS[done:], start=version + 1):
            with self.transaction():
                if callable(step):
                    step(self.conn)
                else:
                    for statement in step.split(";"):
                        if statement.strip():
                            self.conn.execute(statement)
                self.conn.execute(f"PRAGMA user_version = {number}")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        if getattr(self._local, "conn", None) is not None:
            raise RuntimeError("A write in Database.read: use Database.run.")
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
        """Wait for queued work, then close. Not on the event loop thread."""
        self._read_executor.shutdown(wait=True)
        self._executor.shutdown(wait=True)
        for conn in self._readers:
            conn.close()
        self.conn.close()
