"""History retention: pruning old revisions (protocol.md 9.3).

A revision is kept for KEEP_DAYS, and the last KEEP_VERSIONS of a file are kept longer.
DELETED_DAYS after a file is deleted, only its tombstone is left. OLD_EPOCH_DAYS after a file
has a revision under a newer key epoch, its revisions under older epochs go, which frees the
copies a key rotation leaves behind. A file's head revision is never pruned, so a tombstone
stays as the `parentRev` for re-creating the file. The blob GC then frees the chunks.
"""

from syncryption_server.state import AppState

KEEP_DAYS = 30
KEEP_VERSIONS = 10
DELETED_DAYS = 90
OLD_EPOCH_DAYS = 30
BATCH = 500
DAY = 24 * 3600

# Every non-head revision that a rule drops, with its file's head at the time.
_SELECT = """
WITH ranked AS (
    SELECT vault_id, rev, file_id, epoch, created_at,
        ROW_NUMBER() OVER (PARTITION BY vault_id, file_id ORDER BY rev DESC) AS n
    FROM revisions
)
SELECT k.vault_id, k.rev, k.file_id, f.head_rev
FROM ranked k
JOIN files f ON f.vault_id = k.vault_id AND f.file_id = k.file_id
JOIN revisions h ON h.vault_id = f.vault_id AND h.rev = f.head_rev
WHERE k.rev != f.head_rev AND (
    (h.deleted = 1 AND h.created_at <= :deleted_before)
    OR EXISTS (
        SELECT 1 FROM revisions x
        WHERE x.vault_id = k.vault_id AND x.file_id = k.file_id
            AND x.epoch > k.epoch AND x.created_at <= :epoch_before
    )
    OR (k.created_at <= :keep_before AND k.n > :keep_versions)
)
ORDER BY k.vault_id, k.rev
"""

# Only while the file's head is still the one seen by the SELECT: a re-created file is no
# longer deleted (rule a), and the other rules only ever add revisions to prune.
_SAME_HEAD = (
    "EXISTS (SELECT 1 FROM files f WHERE f.vault_id = :vault_id AND f.file_id = :file_id "
    "AND f.head_rev = :head_rev)"
)


async def prune(state: AppState) -> int:
    """Delete the revisions the retention rules drop. Returns how many were deleted."""
    now = state.now()
    params = await state.db.read(
        lambda: [
            dict(r)
            for r in state.db.conn.execute(
                _SELECT,
                {
                    "deleted_before": now - DELETED_DAYS * DAY,
                    "epoch_before": now - OLD_EPOCH_DAYS * DAY,
                    "keep_before": now - KEEP_DAYS * DAY,
                    "keep_versions": KEEP_VERSIONS,
                },
            )
        ]
    )

    def delete(batch: list[dict]) -> int:
        with state.db.transaction() as db:
            # revision_blobs first: it references revisions, with no cascade.
            db.executemany(
                "DELETE FROM revision_blobs WHERE vault_id = :vault_id AND rev = :rev "  # noqa: S608
                f"AND {_SAME_HEAD}",
                batch,
            )
            return db.executemany(
                "DELETE FROM revisions WHERE vault_id = :vault_id AND rev = :rev "  # noqa: S608
                f"AND {_SAME_HEAD}",
                batch,
            ).rowcount

    deleted = 0
    # One transaction per batch: other requests' queries run in between.
    for i in range(0, len(params), BATCH):
        batch = params[i : i + BATCH]
        deleted += await state.db.run(lambda batch=batch: delete(batch))
    return deleted
