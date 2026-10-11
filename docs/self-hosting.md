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

      # The public address: scheme and host only, no path, e.g. https://notes.example.com.
      # Required when BEHIND_PROXY=FALSE. Optional when TRUE (the proxy's headers are used).
      URL: "https://notes.example.com"

      # Required. Needed only to create a new user or vault; joining an existing vault
      # doesn't need it. Give it only to people who may create vaults.
      # Generate one with: openssl rand -base64 24
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
```

| Variable | Required | Meaning |
|---|---|---|
| `BEHIND_PROXY` | yes | `FALSE`: the container gets its own certificate. `TRUE`: plain HTTP on 8080 for your proxy. |
| `URL` | when `BEHIND_PROXY=FALSE` | the public address, e.g. `https://notes.example.com` |
| `SHARED_SECRET` | yes | the secret people need to join the server (section 4) |
| `ADMIN_TOKEN` | yes | the token for the admin page, at least 32 characters (section 5) |
| `ADMIN_CONTACT` | no | how users can reach you (email, Slack, phone, ...): one line of free text, at most 500 characters. Shown on the server's `/` page and in `/health`, and in the plugin when the server is in maintenance or an account is disabled. |
| `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY` | all three or none | store data in S3 instead of `./data`. Leave them empty to use local storage. |
| `S3_ENDPOINT` | no | the provider's S3 endpoint, e.g. `https://s3.us-west-004.backblazeb2.com`, `https://<account>.r2.cloudflarestorage.com` or `http://minio:9000`. Empty means AWS. |
| `MIGRATE_TO_S3` | no | `TRUE` copies existing local data to S3 on startup (section 7) |

**Storage:** with the `S3_*` variables empty (the default), file contents are stored in
`./data/blobs` on the host and nothing else needs to be set up. Setting the three `S3_*`
variables stores them in S3 instead, which gives effectively unlimited storage. The
database always stays in `./data` (replicated to the bucket when S3 is used, section 6).
You can start locally and move to S3 later (section 7).

Generate a shared secret with, for example, `openssl rand -base64 24`, and an admin
token with `openssl rand -hex 32`.

The container refuses to start, with a message saying why, if `URL` is missing when
`BEHIND_PROXY=FALSE`, if `SHARED_SECRET` is empty, if `ADMIN_TOKEN` is
missing or shorter than 32 characters, if only some of the `S3_*`
variables are set, if `S3_ENDPOINT` is set without them, or if `MIGRATE_TO_S3=TRUE`
without S3.

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
- the endpoint URL
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
`https://notes.example.com/admin` lists every user with their vaults and each vault's
keys: the stored (encrypted) size of each vault, its number of files and of kept revisions, when it was created
and last changed, and each key's fingerprint, device name, status (pending, active or revoked),
whether it is a remote-only device and whether it is locked, and when it joined and was
last seen. Keys that registered to create a vault that doesn't exist yet are listed as
"being created". File names and contents stay encrypted, so the page can't show them.

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
  default is 24 hours. Enter a whole number of hours from 1 to 8760 in the vault's row, or
  leave it empty for the default. Devices get the new value at their next login.
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
```
The message is optional: `maintenance/on` also works without a body. `graceSeconds` is
3600 to 31536000, or `null` for the default. `GET /admin/api/status` returns the version,
maintenance state and `adminContact`. The API is
described in [protocol.md](protocol.md), sections 2 and 14.

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
2. `docker compose up -d` and watch the logs. Every blob is copied and checked before the
   server starts serving, so devices can't connect until it finishes and retry on their
   own. If it's interrupted, starting again continues where it stopped.
3. When the log says the migration is complete, set `MIGRATE_TO_S3` back to `"FALSE"`.
4. Once you're satisfied, delete `./data/blobs`. The migration never deletes it for you.

## 8. Recovery without the server
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
