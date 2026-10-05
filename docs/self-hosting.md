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
- Optional: an S3 bucket (AWS, MinIO, Backblaze B2, Cloudflare R2, ...) and an access key
  that can read, write, list and delete objects in it. Use a bucket for this server only:
  the database replica lives under `litestream/` in it, and two servers sharing a bucket
  would overwrite each other's replica.
- Obsidian 1.13 or later on every device.

## 2. Configure
Everything is in `docker-compose.yml`, with the variables written inline. There is no
`.env` file.

```yaml
services:
  vault-syncryption:
    image: ibehren1/vault-syncryption:latest
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./data:/data
    environment:
      BEHIND_PROXY: "FALSE"
      URL: "https://notes.example.com"
      SHARED_SECRET: "a-long-random-string"
      S3_BUCKET: ""
      S3_ACCESS_KEY: ""
      S3_SECRET_KEY: ""
      S3_ENDPOINT: ""
      MIGRATE_TO_S3: "FALSE"
```

| Variable | Required | Meaning |
|---|---|---|
| `BEHIND_PROXY` | yes | `FALSE`: the container gets its own certificate. `TRUE`: plain HTTP on 8080 for your proxy. |
| `URL` | when `BEHIND_PROXY=FALSE` | the public address, e.g. `https://notes.example.com` |
| `SHARED_SECRET` | yes | the secret people need to join the server (section 4) |
| `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY` | all three or none | store data in S3 instead of `./data` |
| `S3_ENDPOINT` | no | the provider's S3 endpoint, e.g. `https://s3.us-west-004.backblazeb2.com`, `https://<account>.r2.cloudflarestorage.com` or `http://minio:9000`. Empty means AWS. |
| `MIGRATE_TO_S3` | no | `TRUE` copies existing local data to S3 on startup (section 6) |

Generate a shared secret with, for example, `openssl rand -base64 24`.

The container refuses to start, with a message saying why, if `URL` is missing when
`BEHIND_PROXY=FALSE`, if `SHARED_SECRET` is empty, if only some of the `S3_*`
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

Check it's up: `curl https://notes.example.com/health`.

## 4. Giving people access
Anyone who has the **endpoint URL**, chooses a **username**, and knows the
**shared secret** can join. How you hand out the secret is up to you and your
organisation. Without it, the plugin tells people to contact their administrator.

- The secret is only needed the first time a key connects to the server. After that,
  people log in with their SSH key alone.
- Changing `SHARED_SECRET` (and restarting) stops new people from joining. It doesn't
  lock out anyone who has already joined.
- The secret controls who may use the server. It doesn't give access to anyone's notes:
  vaults are end-to-end encrypted and readable only by their members' keys.

In the plugin, each person sets:
- the endpoint URL
- their username
- a vault name (a new name creates the vault)
- an SSH key: import `~/.ssh/id_ed25519`, or let the plugin generate one

Adding another device to a vault: open the vault with the same username and vault name.
If the device uses a new key, it shows a pairing code, and someone approves it from a
device that already syncs that vault.

## 5. Data and backups
| Path | Contents |
|---|---|
| `./data/meta.db` (+ `-wal`, `-shm`) | SQLite: users, devices, vaults, revisions (encrypted metadata) |
| `./data/blobs/` | encrypted file chunks, when S3 is not used |
| `./data/caddy/` | TLS certificates |

Everything except the certificates is ciphertext or non-secret metadata, but back it up
anyway: losing it means devices have to push everything again.
- **Local storage:** stop the container, or use `sqlite3 ./data/meta.db ".backup meta.bak"`,
  and copy `./data`.
- **S3:** blobs live in the bucket, and Litestream continuously replicates `meta.db` to
  `s3://<bucket>/litestream/`. A new host with an empty `./data` restores the database
  from the bucket on first start.

Your notes are also on every device, so the server is never the only copy.

## 6. Moving from local storage to S3
1. Add the three `S3_*` variables and set `MIGRATE_TO_S3: "TRUE"`.
2. `docker compose up -d` and watch the logs. Every blob is copied and checked before the
   server starts serving, so devices can't connect until it finishes and retry on their
   own. If it's interrupted, starting again continues where it stopped.
3. When the log says the migration is complete, set `MIGRATE_TO_S3` back to `"FALSE"`.
4. Once you're satisfied, delete `./data/blobs`. The migration never deletes it for you.

## 7. Recovery without the server
Every vault's key file can be decrypted with standard tools:
```
age -d -i ~/.ssh/id_ed25519 keyring.age
```
or with the recovery key, if one was created. A standalone export and decrypt tool is
planned for M7.
