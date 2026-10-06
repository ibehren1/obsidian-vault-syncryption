# Storage and scaling

How much the server stores, how that grows, and how far one container goes. The numbers
are estimates from the design, not load tests.

## 1. What is stored where
| Where | What | Size |
|---|---|---|
| SQLite, `./data/meta.db` | users, keys, sessions, keyrings, one row per file, one row per revision (with its encrypted metadata: path, times, chunk list), one row per blob | the metadata is at most 64 KiB per revision and usually well under 1 KiB; a keyring is at most 1 MiB |
| Blob store: `./data/blobs/` or the S3 bucket | the encrypted file contents, in chunks of 4 MiB | the file size plus 45 bytes per chunk |
| `./data/caddy/` | TLS certificates | small |

File contents are never in the database. A 1 GB vault is about 1 GB of blobs plus a few
MB of database. Blob keys are `blobs/<userId>/<vaultId>/<blobId[0:2]>/<blobId>`.

## 2. How storage grows
- Every synced change is a new revision with its own encrypted chunks. A changed file
  stores a full new copy, not a diff (the server can't diff ciphertext). Each chunk is
  encrypted with a fresh nonce, so new copies don't share blobs with old ones.
- A key rotation (removing a key, or replacing or removing the recovery key) re-encrypts
  every file under the new epoch: one more full copy of the vault (crypto.md 8.4).
- A deleted file keeps its earlier revisions until retention removes them.

Retention (protocol.md 9.3) bounds this. It uses fixed values:
- every revision for 30 days, and at least the last 10 per file;
- a deleted file's revisions for 90 days, then only its tombstone;
- revisions under an old epoch for 30 days after the file has one under a newer epoch.

So steady-state storage is roughly the vault's current size plus the last 30 days of
changes (more for files with fewer than 10 versions in that time). After a rotation it is
about twice the vault's size for 30 days, then back to normal.

## 3. Garbage collection
Once an hour:
1. `retention` deletes the revisions the rules above select, in batches, together with
   their `revision_blobs` rows. A file's head, tombstones included, is never deleted.
2. The blob collector selects, from the database, the `blobs` rows that no revision
   references and that were uploaded more than 24 h ago (the grace period protects
   uploads in progress), and deletes each object from the store by its key.

The collector never lists the store, local or S3: the database is the index. Listing is
used only when an admin purges a vault (just that vault's prefix) and by the one-shot
`MIGRATE_TO_S3` copy. Both steps cost time in proportion to the number of rows they check,
which retention keeps bounded.

## 4. The single-container model
- One process serves everything: FastAPI on one asyncio event loop, with one SQLite
  connection in WAL mode. Transactions are `BEGIN IMMEDIATE` and never wait on anything
  inside, so there is exactly one writer at a time and no lock contention.
- Long-polls (`/wait`) don't hold the database. Many idle devices cost a little memory
  each, not queries.
- Blob reads and writes go to the disk or S3 outside of database transactions.
- With S3, Litestream continuously replicates `meta.db` to the bucket. A new host restores
  it on first start, which takes longer as the database grows.

## 5. What limits it first
In the order they would show up:
1. **Queries on the event loop.** SQLite calls are synchronous, so a slow one (a big
   history page, the admin page's totals, a large prune batch) briefly delays every
   other request. Retention prunes in batches of 500 and yields between them.
2. **One writer.** Commits are short, so this matters only with many devices writing at
   the same moment, such as several large vaults syncing for the first time or
   re-encrypting after a rotation.
3. **Garbage collection queries,** which grow with the number of revisions and blobs.
   Retention keeps that number bounded.
4. **Restore time** of the Litestream replica on a new host, which grows with the database.
5. **Disk space** without S3. With S3 it is effectively unlimited.

## 6. Rough capacity
- **Comfortable:** personal use, a family or a team of tens of people. Vaults with tens of
  thousands of files and millions of revision rows. Hundreds of connected devices waiting
  for live updates.
- **Possible with care:** a few hundred active users. Expect short delays when many large
  vaults sync at the same time.
- **Not the target:** thousands of active users, or more than one app container. The
  design runs exactly one container, because long-poll notifications and blob locks are
  in-process.

## 7. If it needs to go further
1. **Run SQLite queries on a worker thread.** This is the cheapest step: the event loop stays
   responsive while a query runs. SQLite, the schema and backups stay as they are.
2. **Postgres.** It would allow concurrent writers and, together with shared
   notifications and locks, more than one app process. It is a large change:
   - about 110 query sites rewritten for an async driver, with row locks where
     the single writer is relied on today, plus SQL dialect changes;
   - a Postgres server in the container (initialisation, a process supervisor, major
     version upgrades);
   - Litestream replaced (WAL-G or pgBackRest for the S3 replica and restore), a
     SQLite-to-Postgres migration for existing data, and `MIGRATE_TO_S3` reworked.

   It doesn't reduce storage. That is what retention is for.
