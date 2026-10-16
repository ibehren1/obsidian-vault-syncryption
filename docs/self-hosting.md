# Self-hosting Vault Syncryption

The server is one container, published as `ibehren1/vault-syncryption`. The compose
file is [`backend/docker/docker-compose.yml`](../backend/docker/docker-compose.yml): copy
it into an empty folder on the host. `./data` below is relative to that folder.

## 1. What you need
- A machine with Docker and Docker Compose.
- One of:
  - **Built-in HTTPS:** a domain name pointing at the machine, with ports 80 and 443
    reachable from the internet (Let's Encrypt needs them).
  - **Your own reverse proxy:** nginx, Traefik, Caddy, a load balancer, ... that
    terminates TLS and forwards to the container on port 8080.
- Storage: by default everything is stored on the host in the `./data` folder (a bind
  mount), with no configuration. This is limited by the host's disk.
- Optional: an S3 bucket (AWS, MinIO, Backblaze B2, Cloudflare R2, ...), for effectively
  unlimited storage, and an access key that can read, write, list and delete objects in it. Use a bucket for this server only:
  the database replica lives under `litestream/` in it, and two servers sharing a bucket
  would overwrite each other's replica.
- Obsidian 1.13 or later on every device.

## 2. Configure
The image is on Docker Hub as `ibehren1/vault-syncryption` and on the GitHub Container
Registry as `ghcr.io/ibehren1/vault-syncryption`, tagged with the server version
and `latest`, for `linux/amd64` and `linux/arm64`. Each version also has a `backend-v<version>`
release on GitHub with the image's digest, and its build provenance can be checked with
`gh attestation verify oci://ghcr.io/ibehren1/vault-syncryption@<digest> -R ibehren1/obsidian-vault-syncryption`.
Either image works in `image:`. Beta plugins may need a newer server: its image is
`ghcr.io/ibehren1/vault-syncryption-beta`, tagged `dev-<version>` and `dev-latest`.

Everything is in `docker-compose.yml`, with the variables written inline. There is no
`.env` file. This is the whole file, with a comment on every variable:

```yaml
services:
  vault-syncryption:
    image: ibehren1/vault-syncryption:latest
    restart: unless-stopped
    ports:
      - "80:80"        # Let's Encrypt HTTP-01 and the redirect to HTTPS (BEHIND_PROXY=FALSE)
      - "443:443"      # HTTPS (BEHIND_PROXY=FALSE)
      # - "8080:8080"  # plain HTTP for your own proxy (BEHIND_PROXY=TRUE); remove 80 and 443
    volumes:
      - ./data:/data   # the database, certificates, and the encrypted files unless S3 is set
    environment:
      # TRUE or FALSE.
      #   FALSE: the container serves HTTPS on 80/443 and gets its own Let's Encrypt
      #          certificate for URL. The DNS name must point at this host, and ports 80 and
      #          443 must be reachable from the internet.
      #   TRUE:  plain HTTP on 8080 for your reverse proxy, which terminates TLS and passes
      #          X-Forwarded-Proto and X-Forwarded-Host. Allow requests of at least 30 s.
      BEHIND_PROXY: "FALSE"

      # Only with BEHIND_PROXY=TRUE: the IP addresses or CIDRs your reverse proxy connects
      # from, separated by commas, e.g. "172.18.0.5" or "10.0.0.0/8, fd00::/8". Only
      # requests from these addresses may set X-Forwarded-For, X-Forwarded-Proto and
      # X-Forwarded-Host; from anywhere else they are ignored, so nobody can fake a client
      # address by reaching port 8080 directly. Empty means loopback and private ranges
      # (127.0.0.0/8, ::1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7).
      TRUSTED_PROXIES: ""

      # The public address: scheme and host only, no path, e.g. https://notes.example.com.
      # Required when BEHIND_PROXY=FALSE. Optional when TRUE (the proxy's headers are used).
      URL: "https://notes.example.com"

      # Required, at least 16 characters. Needed only to create a new user or vault;
      # joining an existing vault doesn't need it. Give it only to people who may
      # create vaults. Generate one with: openssl rand -base64 24
      SHARED_SECRET: ""

      # Required, at least 32 characters. Opens /admin (sign in on the page, or send
      # "Authorization: Bearer <token>" to /admin/api). Keep it private.
      # Generate one with: openssl rand -hex 32
      ADMIN_TOKEN: ""

      # Optional. How your users reach you (email, Slack channel, phone, ...): one line, at
      # most 500 characters. Public: shown on /, in /health, and in the plugin during
      # maintenance or when an account is disabled. Example: "admin@example.com"
      ADMIN_CONTACT: ""

      # Storage. Leave all of these empty to keep everything in ./data (the default), or set
      # all three of S3_BUCKET, S3_ACCESS_KEY and S3_SECRET_KEY to store the encrypted files
      # in a bucket, for effectively unlimited storage. With S3, the database stays in
      # ./data and Litestream replicates it to the same bucket under litestream/.
      S3_BUCKET: ""                      # an existing bucket used only by this server
      S3_ACCESS_KEY: ""                  # an access key that can read, write, list and delete in it
      S3_SECRET_KEY: ""
      # Optional, for S3-compatible providers, e.g. https://s3.us-west-004.backblazeb2.com,
      # https://<account>.r2.cloudflarestorage.com or http://minio:9000. Empty means AWS
      # (the region is read from the bucket).
      S3_ENDPOINT: ""

      # TRUE or FALSE. TRUE copies the files already in ./data to the bucket on startup
      # (needs the S3 variables). Set it back to FALSE once the migration has finished.
      MIGRATE_TO_S3: "FALSE"

      # TRUE or FALSE. TRUE copies the files in the bucket back to ./data on startup and
      # serves from ./data (needs the S3 variables). Once the migration has finished,
      # remove the S3 variables and set it back to FALSE.
      MIGRATE_FROM_S3: "FALSE"

      # TRUE or FALSE. The server serves Prometheus metrics at /metrics, without a token:
      # counts only (requests, users, vaults, keys, storage, S3 calls and database
      # replication), no names. TRUE turns it off.
      DISABLE_METRICS: "FALSE"

      # Optional. The client IP addresses or CIDRs, separated by commas, that may read
      # /metrics (e.g. your Prometheus: "10.0.0.5"); others get 403. Behind a proxy the
      # client is the one in X-Forwarded-For from a TRUSTED_PROXIES peer. Empty means
      # loopback and private ranges only.
      METRICS_ALLOWED_IPS: ""
```

| Variable | Required | Meaning |
|---|---|---|
| `BEHIND_PROXY` | yes | `FALSE`: the container gets its own certificate. `TRUE`: plain HTTP on 8080 for your proxy. |
| `TRUSTED_PROXIES` | no | with `BEHIND_PROXY=TRUE`: the IP addresses or CIDRs of your reverse proxy, separated by commas. Only requests from them may set `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`. Empty means loopback and private ranges (`127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`). |
| `URL` | when `BEHIND_PROXY=FALSE` | the public address, e.g. `https://notes.example.com` |
| `SHARED_SECRET` | yes | the secret people need to join the server, at least 16 characters (section 4) |
| `ADMIN_TOKEN` | yes | the token for the admin page, at least 32 characters (section 5) |
| `ADMIN_CONTACT` | no | how users can reach you (email, Slack, phone, ...): one line of free text, at most 500 characters. Shown on the server's `/` page and in `/health`, and in the plugin when the server is in maintenance or an account is disabled. |
| `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY` | all three or none | store data in S3 instead of `./data`. Leave them empty to use local storage. |
| `S3_ENDPOINT` | no | the provider's S3 endpoint, e.g. `https://s3.us-west-004.backblazeb2.com`, `https://<account>.r2.cloudflarestorage.com` or `http://minio:9000`. Empty means AWS. |
| `MIGRATE_TO_S3` | no | `TRUE` copies existing local data to S3 on startup (section 7) |
| `MIGRATE_FROM_S3` | no | `TRUE` copies the data in S3 back to `./data` on startup and serves from `./data` (section 8) |
| `DISABLE_METRICS` | no | `TRUE` turns off the Prometheus endpoint `/metrics` (section 5.1). Default `FALSE`. |
| `METRICS_ALLOWED_IPS` | no | the client IP addresses or CIDRs, separated by commas, that may read `/metrics` (section 5.1). Empty means loopback and private ranges (the same list as `TRUSTED_PROXIES`'s default). |

**Storage:** with the `S3_*` variables empty (the default), file contents are stored in
`./data/blobs` on the host and nothing else needs to be set up. Setting the three `S3_*`
variables stores them in S3 instead, which gives effectively unlimited storage. The
database always stays in `./data` (replicated to the bucket when S3 is used, section 6).
You can start locally and move to S3 later (section 7), and move back (section 8).

Generate a shared secret with, for example, `openssl rand -base64 24`, and an admin
token with `openssl rand -hex 32`.

The container refuses to start, with a message saying why, if `URL` is missing when
`BEHIND_PROXY=FALSE`, if `SHARED_SECRET` is empty or shorter than 16 characters, if `ADMIN_TOKEN` is
missing or shorter than 32 characters, if only some of the `S3_*`
variables are set, if `S3_ENDPOINT` is set without them, if `MIGRATE_TO_S3=TRUE`
or `MIGRATE_FROM_S3=TRUE` without S3, if both are `TRUE`, or if `BEHIND_PROXY`,
`MIGRATE_TO_S3`, `MIGRATE_FROM_S3` or `DISABLE_METRICS` is neither `TRUE` nor `FALSE`, or
if an entry of `TRUSTED_PROXIES` or `METRICS_ALLOWED_IPS` is neither an IP address nor a CIDR. It
also refuses to start if the `S3_*` variables are set again after a move off S3 (section 8).

## 3. Start
```
docker compose up -d
docker compose logs -f vault-syncryption
```
With `BEHIND_PROXY=FALSE`, the first start requests a certificate. It is stored in
`./data/caddy` and renewed automatically.

With `BEHIND_PROXY=TRUE`, publish port 8080 instead of 80/443:
```yaml
    ports:
      - "8080:8080"
```
and point your proxy at it. The container's healthcheck (`docker compose ps`) shows when
it is ready. The proxy must pass `X-Forwarded-Proto` and
`X-Forwarded-Host`, and must allow requests to stay open for at least 30 seconds (live
updates use long-polling). Don't expose port 8080 to the internet directly.

The server honours `X-Forwarded-For` (it takes the last entry, the one your proxy added),
`X-Forwarded-Proto` and `X-Forwarded-Host` only on connections from `TRUSTED_PROXIES`.
The default, loopback and private ranges, covers a proxy on the same host or on a Docker
network. If your proxy connects from a public address, set `TRUSTED_PROXIES` to it; if
other machines on your private network can reach port 8080, narrow it to the proxy's
address. Requests from any other address are counted (for rate limits) and logged under
their own address, and their origin uses the scheme and `Host` they arrived with.

Check it's up: `curl https://notes.example.com/health`. It answers 200 with
`"status": "ok"`, or `"status": "maintenance"` while maintenance mode is on (section 5),
together with the server `version`, the `protocol` version, the `maintenance` details
(`since` and `message`, or `null`) and `ADMIN_CONTACT` as `adminContact`. If the database
or the blob store can't be reached it answers 503 with `"status": "unavailable"`.

Opening `https://notes.example.com/` in a browser shows a short page for your users:
what the service is (self-hosted, end-to-end encrypted Obsidian sync; the server holds
only ciphertext), how to connect (install the plugin, enter this URL, a username and a
vault name, and create an encryption key), that creating a vault needs the shared secret from you,
your `ADMIN_CONTACT`, whether the server is in maintenance, and the current `/health`
response as pretty-printed JSON.

## 4. Giving people access
Anyone who has the **endpoint URL**, chooses a **username**, and knows the
**shared secret** can create vaults. How you hand out the secret is up to you and your
organisation. Without it, the plugin tells people to contact their administrator
(set `ADMIN_CONTACT` so they know how).

- The secret is only needed to create a vault (or a new username). A new device joining
  an existing vault doesn't need it: it waits until a device that already syncs the
  vault approves it. After that, people log in with their encryption key alone.
- Changing `SHARED_SECRET` (and restarting) stops new people from joining. It doesn't
  lock out anyone who has already joined.
- The secret controls who may use the server. It doesn't give access to anyone's notes:
  vaults are end-to-end encrypted and readable only by their members' keys.

In the plugin, each person sets:
- the endpoint URL, which must be `https://` (`http://` works only for a server on the
  same machine, such as `http://localhost:8080`)
- their username
- a vault name (a new name creates the vault)
- an encryption key: the plugin generates one for each device and vault (a key opens
  exactly one vault, so two vaults on one device use two keys)

People should create a recovery key when the plugin offers it. Device keys never leave
their device, so the recovery key is the only way back into a vault when every device is
lost.

Adding another device to a vault: open the vault with the same username and vault name.
The device generates a new key, shows a pairing code, and someone approves it from a
device that already syncs that vault. Any device of the vault can see every key (by
fingerprint and device name) and remove one; files a removed device already has stay on
it.

## 5. Admin page
`https://notes.example.com/admin` has two tabs. **Vaults** lists every user with their
vaults, and under each vault its keys: the stored (encrypted) size of each vault, its number of files and of kept revisions, when it was created
and last changed, and each key's fingerprint, device name, status (pending, active or revoked),
whether it is a remote-only device and whether it is locked, and when it joined and was
last seen. Keys that registered to create a vault that doesn't exist yet are listed as
"being created", under the name of that vault. File names and contents stay encrypted,
so the page can't show them. **Performance** shows the server's current numbers and
refreshes them every 1, 2, 5 (the default), 10, 30 or 60 seconds, or not at all, as picked
in its dropdown: requests per second, 4xx and 5xx responses per second, latency
percentiles (without the `/wait` long-polls) and the busiest routes; sync activity (file
commits, conflicts, blob uploads and downloads, logins, 401 and 429 answers per second);
bytes received and sent per second, requests in flight, open long-polls and event-loop lag;
CPU and memory of the process and of the container; free space on the data disk, the size
of the database and its write-ahead log, and the cleanup's runs and results; the stored
totals; and, only when blobs are in S3, the bucket calls per second, failed calls by
result, latency percentiles, upload and download throughput, retries and calls in flight,
and Litestream's replication of the database (status, syncs and sync errors, time spent
syncing, WAL written, uploads to S3 and their throughput). Rates cover the time since the previous refresh. A small line next to the
main numbers shows their last 60 readings; it is kept in the browser and starts over when
the page reloads. The process and container lines need Linux and
show "–" elsewhere. This tab works also with `DISABLE_METRICS: "TRUE"`.

- **Logging in:** the page asks for `ADMIN_TOKEN` and keeps you logged in for 12 hours
  (an HttpOnly, SameSite=Strict cookie). Five wrong tokens from one address block that
  address for 15 minutes.
- **Disable / Enable:** disabling a user or a vault blocks access but keeps all data.
  The plugin stops syncing and tells the person the administrator disabled it. Enable
  restores access.
- **Purge:** only for something already disabled. You type its name to confirm. Purge
  deletes the vault's encrypted files, history and devices (for a user: all their vaults
  and devices) and **can't be undone**. The username or vault name can then be used again.
- **Maintenance mode:** turn it on before maintenance work (a backup, a move, an
  upgrade), with an optional message for your users, and turn it off when you're done.
  It stays on across restarts until you turn it off. While it's on, the sync API answers
  503 `maintenance` (with `Retry-After`): the plugin shows "maintenance", pauses syncing,
  tells the person to contact you if needed, and resumes by itself once it's off. Edits
  made meanwhile stay on the device and sync afterwards. `/`, `/health` (still 200, with
  `"status": "maintenance"`) and `/admin` keep working.
- **Remote-only grace period:** each vault has a grace period for its remote-only devices
  (devices that keep the vault's contents only as ciphertext, [remote-only.md](remote-only.md)):
  how long such a device may go without reaching the server before it locks its files. The
  default is 24 hours. Enter a whole number of hours from 1 to 8760 in the vault's box, or
  leave it empty for the default. Devices get the new value at their next login.
- **Storage quota:** each vault can have a quota on its stored (encrypted) size, the size
  the page shows. There is none by default. Enter a whole number of GB in the vault's box,
  or leave it empty for no quota. Once a vault reaches it, new uploads are refused with
  507 `quota_exceeded` and the plugin shows the server's message; data already stored is
  kept. The size includes the old versions the server keeps, so deleting files frees space
  only once those versions expire (30 days of history, 90 days for deleted files) and the
  hourly cleanup has run ([protocol.md](protocol.md) sections 9.3 and 12).
- **Disk reserve:** the server keeps 1 GiB free on the data volume, which always holds
  `meta.db` (also with S3). Below that, it refuses new uploads and changes with 507
  `storage_full`, so the database can't run out of room; deletions still go through.
  Free space on the data disk shows on the Performance tab. Free some space, or grow the
  volume, and syncing resumes on its own.
- Admin actions are written to the container log.

The same data is available as JSON for scripts:
```
curl -H "Authorization: Bearer $ADMIN_TOKEN" https://notes.example.com/admin/api/users
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://notes.example.com/admin/api/vaults/<vault id>/disable
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"message": "Moving to a new host, back by 18:00"}' \
  https://notes.example.com/admin/api/maintenance/on
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://notes.example.com/admin/api/maintenance/off
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"graceSeconds": 172800}' \
  https://notes.example.com/admin/api/vaults/<vault id>/grace
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"quotaBytes": 10737418240}' \
  https://notes.example.com/admin/api/vaults/<vault id>/quota
```
The message is optional: `maintenance/on` also works without a body. `graceSeconds` is
3600 to 31536000, or `null` for the default. `quotaBytes` is 1 to 2^50 bytes, or `null`
for no quota. `GET /admin/api/status` returns the version,
maintenance state and `adminContact`, and `GET /admin/api/performance` the numbers of the
Performance tab (counters as totals since the server started). The API is
described in [protocol.md](protocol.md), sections 2 and 14.

### 5.1 Metrics
`/metrics` serves Prometheus metrics. It needs no token, but it answers only clients in
`METRICS_ALLOWED_IPS`; others get `403 forbidden`. Left empty, that is loopback and private
ranges, so a Prometheus on the same host, Docker network or LAN can scrape it and the
internet can't. Behind your own proxy (`BEHIND_PROXY=TRUE`) the client is the address in
`X-Forwarded-For` from a `TRUSTED_PROXIES` peer, so a request the proxy forwards from the
internet is refused; a request from the proxy itself without that header counts as the
proxy's address. It holds only counts: no label names a user, vault, device or file. Set
`DISABLE_METRICS: "TRUE"` to turn it off (it then answers 404); the admin page's
Performance tab keeps working.

| Metric | Type | Meaning |
|---|---|---|
| `syncryption_build_info{version,protocol}` | gauge | always 1; the server and protocol version |
| `syncryption_http_requests_total{method,route,status}` | counter | requests, by route template (e.g. `/api/v1/vaults/{vault_id}/changes`; `unmatched` for unknown paths and for requests answered before routing, such as the maintenance 503) |
| `syncryption_http_request_duration_seconds{method,route}` | histogram | request duration; `/api/v1/vaults/{vault_id}/wait` long-polls take up to their timeout |
| `syncryption_http_request_bytes_total`, `syncryption_http_response_bytes_total` | counter | bytes received in request bodies and sent in response bodies |
| `syncryption_http_requests_in_flight` | gauge | requests being answered, long-polls included |
| `syncryption_event_loop_lag_seconds` | gauge | the longest delay of the server's event loop over the last 10 seconds; high values mean the server is overloaded |
| `syncryption_users`, `syncryption_vaults` | gauge | users and vaults |
| `syncryption_devices{status}` | gauge | encryption keys that are `pending`, `active` or `revoked` |
| `syncryption_files`, `syncryption_revisions` | gauge | files and kept revisions |
| `syncryption_blobs`, `syncryption_blob_bytes` | gauge | stored encrypted blobs and their total size |
| `syncryption_locks_active` | gauge | soft locks that haven't expired |
| `syncryption_longpoll_waiters` | gauge | open long-polls (roughly, devices online) |
| `syncryption_maintenance` | gauge | 1 while maintenance mode is on |
| `syncryption_gc_runs_total{task}`, `syncryption_gc_failures_total{task}` | counter | hourly cleanup runs and failures (`expired`: challenges, sessions and pending keys past their lifetime; `retention`; `blobs`) |
| `syncryption_retention_pruned_revisions_total`, `syncryption_gc_deleted_blobs_total` | counter | revisions and blobs the cleanup deleted |
| `syncryption_gc_last_run_timestamp_seconds{task}` | gauge | when each cleanup task last ran (Unix time; 0 before the first run) |
| `syncryption_data_disk_free_bytes`, `syncryption_data_disk_total_bytes` | gauge | free and total space of the file system holding `/data` |
| `syncryption_db_bytes`, `syncryption_db_wal_bytes` | gauge | size of `meta.db` and of its write-ahead log |
| `syncryption_shared_secret_failures_total`, `syncryption_admin_token_failures_total` | counter | wrong shared secrets and admin tokens |
| `syncryption_container_memory_bytes`, `syncryption_container_memory_working_set_bytes` | gauge | memory of the whole container (server, Caddy, Litestream), with and without inactive page cache; the working set is what `docker stats` shows |
| `syncryption_container_memory_limit_bytes` | gauge | the container's memory limit, only when it has one |
| `syncryption_container_cpu_seconds_total` | counter | CPU time of the whole container |
| `syncryption_s3_requests_total{operation,result}` | counter | calls to the S3 bucket for blobs, only when blobs are stored in S3. `operation` is `put`, `get`, `head`, `delete`, `list` or `ping` (the health check); `result` is `ok`, `not_found` (a missing blob), `throttled` (`SlowDown`, other 503 and 429 answers), `client_error` (other 4xx, e.g. `AccessDenied`), `server_error` (5xx), `connection` (no answer: refused, timed out, DNS) or `other` |
| `syncryption_s3_request_duration_seconds{operation}` | histogram | duration of those calls, the client's retries and reading the body included |
| `syncryption_s3_retries_total{operation}` | counter | retries the S3 client made inside the calls that got an answer; steady retries usually mean the provider is throttling or flaky |
| `syncryption_s3_uploaded_bytes_total`, `syncryption_s3_downloaded_bytes_total` | counter | blob bytes uploaded to and downloaded from the bucket |
| `syncryption_s3_requests_in_flight` | gauge | S3 calls being made |
| `syncryption_litestream_up` | gauge | only while Litestream replicates `meta.db` (blobs in S3): 1 when the server could read Litestream's metrics at this scrape, else 0 |
| `litestream_*` | | Litestream's own metrics, passed on under its names while it replicates: among others `litestream_sync_count`, `litestream_sync_error_count` and `litestream_sync_seconds` (syncs of new WAL pages, about once a second), `litestream_total_wal_bytes`, `litestream_replica_operation_total{operation}` and `litestream_replica_operation_bytes{operation}` (its uploads to the bucket), `litestream_db_size`, `litestream_wal_size`, `litestream_txid` and `litestream_disk_full`. Its Go runtime and process metrics are left out. |
| `process_*`, `python_*` | | the Python server process only: CPU, memory, open files, Python GC |

The `syncryption_container_*` metrics come from the container's own cgroup, so they need
no host access: they are there on Linux hosts with cgroup v2 when Docker gives the
container its own cgroup namespace (the default with cgroup v2), and absent otherwise.
For every container on the host, or the host itself, run cAdvisor or node_exporter on
the host. Counters start at zero when the container restarts. Litestream serves its
metrics on `127.0.0.1:9091` inside the container only; the server reads them at each
scrape and adds them to `/metrics`, so one scrape job covers both. A Prometheus scrape job:
```yaml
scrape_configs:
  - job_name: vault-syncryption
    scheme: https
    static_configs:
      - targets: ["notes.example.com"]
```

A Grafana dashboard for these metrics is in
[`backend/dashboard/vault-syncryption.json`](../backend/dashboard/vault-syncryption.json).
In Grafana, open Dashboards, New, Import, upload the file and pick your Prometheus data
source. It has an overview (scrape, version, maintenance, uptime, users, vaults, keys,
storage), request rate, status codes, server errors and latency (without the long-polls),
storage and cleanup, wrong secrets and tokens, the S3 bucket's calls, failures, latency,
throughput and retries, Litestream's replication (syncs, errors, time spent, uploads,
throughput, database and WAL size; both empty without S3), the whole container's CPU and memory, and
the server process's CPU, memory and open files. The Job and Instance variables at the top choose the server when Prometheus scrapes
more than one.

## 6. Data and backups
| Path | Contents |
|---|---|
| `./data/meta.db` (+ `-wal`, `-shm`) | SQLite: users, devices, vaults, revisions (encrypted metadata) |
| `./data/blobs/` | encrypted file chunks, when S3 is not used |
| `./data/caddy/` | TLS certificates |

**Space:** the server keeps every version of a file for 30 days and at least the last 10,
a deleted file's versions for 90 days, and the copies left by a key change for 30 days
(protocol.md 9.3). Older ones are removed every hour and their space is freed, with nothing
to configure. How storage grows and how far one container goes is in
[scaling.md](scaling.md).

Everything except the certificates is ciphertext or non-secret metadata, but back it up
anyway: losing it means devices have to push everything again.
- **Local storage:** stop the container, or use `sqlite3 ./data/meta.db ".backup meta.bak"`,
  and copy `./data`.
- **S3:** blobs live in the bucket, and Litestream continuously replicates `meta.db` to
  `s3://<bucket>/litestream/`. A new host with an empty `./data` restores the database
  from the bucket on first start.

Your notes are also on every device, so the server is never the only copy.

## 7. Moving from local storage to S3
1. Add the three `S3_*` variables and set `MIGRATE_TO_S3: "TRUE"`.
2. `docker compose up -d` and watch the logs. The log first says how many blobs there are,
   then reports progress every 1000 blobs. Every blob is copied and checked before the
   server starts serving, so devices can't connect until it finishes and retry on their
   own. If it's interrupted, starting again continues where it stopped.
3. When the log says the migration is complete, set `MIGRATE_TO_S3` back to `"FALSE"`.
4. Once you're satisfied, delete `./data/blobs`. The migration never deletes it for you.

## 8. Moving from S3 to local storage
1. Keep the three `S3_*` variables and set `MIGRATE_FROM_S3: "TRUE"`.
2. `docker compose up -d` and watch the logs. On a host whose `./data` has no `meta.db`,
   the database is first restored from the bucket's Litestream replica. The log then says
   how many blobs the bucket holds and reports progress every 1000 blobs while every blob
   in the bucket is copied to `./data/blobs` and checked before the server starts
   serving; blobs already in `./data/blobs` and intact are kept. If it's interrupted,
   starting again continues where it stopped. While `MIGRATE_FROM_S3` is `TRUE`, the
   server stores everything in `./data` and Litestream no longer replicates the database.
3. When the log says the migration is complete, remove the `S3_*` variables (and
   `S3_ENDPOINT`) and set `MIGRATE_FROM_S3` back to `"FALSE"`. From now on, back up
   `./data` as in section 6.
4. Once you're satisfied, delete the bucket's contents, including the database replica in
   `litestream/`, which stopped being updated. The migration never deletes anything from
   the bucket. If you move back to S3 with the same bucket, Litestream sees that the old
   replica doesn't match the database and replicates the current one.

After the move, the container refuses to start if the `S3_*` variables are set again with
both migration variables `FALSE`: the bucket no longer has the files written since. To go
back to S3, use section 7.

## 9. Recovery without the server
A vault's keyring holds its vault keys, and can be decrypted with standard tools and the
vault's recovery key. The server stores it in `meta.db`; to extract the current version
(`sqlite3` on the host, with the vault's username and vault name):
```
sqlite3 ./data/meta.db "SELECT writefile('keyring.age', k.keyring) FROM keyrings k
  JOIN vaults v ON v.id = k.vault_id JOIN users u ON u.id = v.user_id
  WHERE u.username = 'alice' AND v.name = 'Personal' ORDER BY k.version DESC LIMIT 1"
age -d -i recovery.txt keyring.age
```
where `recovery.txt` holds the recovery key (`AGE-SECRET-KEY-1...`). The output is the
keyring JSON ([crypto.md](crypto.md), section 6). There is no export or decrypt tool for
file contents: the file and metadata format is specified in [crypto.md](crypto.md),
section 8.
