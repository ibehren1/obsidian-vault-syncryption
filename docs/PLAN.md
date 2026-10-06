# Vault Syncryption: Product & Design Plan

Source of truth for design.

## Context
This started as a greenfield repo. The goal is self-hosted Obsidian sync where:
- the whole vault is encrypted, including plugins and config
- the local copy stays usable offline
- many users share one server, each user syncs many devices and vaults, and users and vaults are tracked separately
- the backend is a single container, configured with a few environment variables and nothing else

The client is an Obsidian plugin with minimal setup.

Decisions the user made:
- **Identity:** a per-device encryption key, an Ed25519 key in OpenSSH format only (no RSA).
- **Merging:** the backend does locking but no merging.
- **Backend:** Python, managed with uv.
- **HTTPS:** built-in Caddy with Let's Encrypt, or plain HTTP behind the user's own proxy. No tunnels.
- **Configuration:** docker compose with the variables written inline. No `.env` file.
- **Storage:** a `./data` bind mount by default, with no configuration. S3 is optional, for effectively unlimited storage, and used if the user supplies credentials. `MIGRATE_TO_S3` moves local data to S3.

Prior art: Self-hosted LiveSync (CouchDB, complex setup), Remotely Save (S3, weak at syncing `.obsidian`), official Obsidian Sync (paid). What sets this apart: one compose file, standard Ed25519 key pairs as identity, a server that cannot read notes.

## Hosting (single container, docker compose)
`backend/docker/docker-compose.yml` holds the hosting setup, with every variable inline:
```yaml
services:
  vault-syncryption:
    image: ibehren1/vault-syncryption:latest
    restart: unless-stopped
    ports:
      - "80:80"      # ACME HTTP-01 + redirect   (BEHIND_PROXY=FALSE)
      - "443:443"    # HTTPS                      (BEHIND_PROXY=FALSE)
      # - "8080:8080" # plain HTTP               (BEHIND_PROXY=TRUE)
    volumes:
      - ./data:/data
    environment:
      BEHIND_PROXY: "FALSE"
      URL: "https://notes.example.com"   # required when BEHIND_PROXY=FALSE
      S3_BUCKET: ""
      S3_ACCESS_KEY: ""
      S3_SECRET_KEY: ""
      S3_ENDPOINT: ""                    # optional: MinIO, B2, R2, ...; empty means AWS
      MIGRATE_TO_S3: "FALSE"
      SHARED_SECRET: "change-me"         # required; given to people allowed to join
      ADMIN_TOKEN: ""                    # required: 32+ characters for /admin
      ADMIN_CONTACT: ""                  # optional: how users reach the admin
```
- **Variable naming:** `BEHIND_PROXY` uses an underscore, not the hyphen in "BEHIND-PROXY". Shells, and therefore `entrypoint.sh`, can't read environment variable names that contain a hyphen.
- **`BEHIND_PROXY=FALSE`:**
  - The entrypoint requires `URL` and exits with a clear error if it's missing.
  - Caddy runs with a generated Caddyfile (`{host} { reverse_proxy 127.0.0.1:8000 }`).
  - Caddy's automatic HTTPS handles the whole Let's Encrypt process: HTTP-01 file validation on port 80 (with TLS-ALPN-01 on 443 as a fallback), issuing, renewing, and redirecting HTTP to HTTPS.
  - Certificates are stored in `/data/caddy`, so they survive restarts.
- **`BEHIND_PROXY=TRUE`:**
  - Caddy isn't started, and uvicorn serves plain HTTP on `:8080`.
  - Trusted `X-Forwarded-*` headers are honoured.
  - `URL` is optional.
- **`SHARED_SECRET`:** required. The entrypoint exits with a clear error if it is empty. Anyone with the endpoint URL, a username and this secret can join the server. The secret is only checked when a new key creates something: a new user, or a new vault name (a new key that names an existing vault of an existing user joins as a pending device without it, and an existing member approves it; protocol.md 5.2). Without it, the plugin tells the user to contact their administrator. How the secret is handed out is up to the organisation running the server. Changing it doesn't affect keys that are already registered.
- **`ADMIN_TOKEN`:** required, at least 32 characters; the entrypoint exits otherwise. It opens the admin page `/admin` (see the M8 admin item), either as `Authorization: Bearer` or typed into the page's login form.
- **`ADMIN_CONTACT`:** optional, free-form single-line text (at most 500 characters) telling users how to reach the admin: email, Slack, phone, ... It is shown on the `/` page and in `/health`, and passed to the plugin in the maintenance and disabled-account errors so the plugin can show it.
- **Storage selection:**
  - Local storage is the default and needs no configuration. S3 is optional and is the way to get effectively unlimited storage.
  - If all three `S3_*` variables are set, file contents go to S3. The region is found automatically with `GetBucketLocation`.
  - `S3_ENDPOINT` (optional) points at an S3-compatible provider such as MinIO, Backblaze B2 or Cloudflare R2. It needs the three `S3_*` variables. If the provider doesn't implement `GetBucketLocation`, the region falls back to `us-east-1`. Litestream uses the same endpoint.
  - Otherwise they go to `/data/blobs` (the `./data` bind mount).
  - If only some of the variables are set, startup fails, so a typo can't silently fall back to local storage.
  - SQLite metadata always lives in `/data/meta.db`. When S3 is enabled, Litestream also replicates it continuously to `s3://bucket/litestream/` for redundancy. Use one bucket per server: two servers sharing a bucket would overwrite each other's replica.
- **`MIGRATE_TO_S3=TRUE`:** requires the S3 variables. On startup, before serving traffic:
  1. Walk `/data/blobs`.
  2. Upload any blob missing from S3, then verify it with HEAD (size) and its SHA-256 key. Blobs are content-addressed, so the migration is idempotent and can resume after interruption.
  3. Write `/data/.migrated_to_s3` and log a summary.
  - Local blobs are **not deleted automatically**. The log tells the user to delete `./data/blobs` and set the variable back to FALSE.
  - Running again once the marker exists does nothing.

## Crypto & Identity
- **Device encryption keys (Ed25519 in OpenSSH format only):**
  - Every device, including mobile, generates its own key. There is no import (removed in plugin 0.1.3): the key is only used to log in and to decrypt the VDK, and approving a new device re-encrypts the VDK to its key, so an existing key never needs to be brought in. Losing every device is covered by the recovery key.
  - The private key is stored only in Obsidian's `SecretStorage` (requires Obsidian 1.13+, no fallback), never in the vault folder. A local passphrase is an optional extra layer.
  - The OpenSSH private-key parser is our own code, about 150 lines: `bcrypt-pbkdf` (pure JS) plus WebCrypto AES-CTR. `sshpk` needs Node crypto, so it isn't usable on mobile.
- **Envelope:**
  - There is one random 32-byte vault data key (VDK).
  - `keyring.age` holds the VDK encrypted to every device's `ssh-ed25519` public key, using age's ssh-ed25519 stanza, plus an offline recovery key. The offline recovery path is `age -d -i recovery.txt keyring.age` with the recovery key.
  - The stanza is about 80 lines on top of `age-encryption` (typage) and `@noble/curves`/`@noble/hashes`, and is tested against Go `age`.
  - Each file is encrypted with XChaCha20-Poly1305 under `HKDF(VDK, fileId)`.
  - Paths are encrypted inside the file metadata. The server sees only `fileId = HMAC(VDK, path)`, size, timestamps and lock state.
  - Refined in `docs/crypto.md`: the HMAC key is `indexKey = HKDF(VDK of epoch 1)`, kept in the keyring and unchanged by rotation, so `fileId`s stay stable and revocation is ordinary re-encrypting commits. Every keyring upload is signed (sshsig, namespace `syncryption-keyring@v1`) by a device already in the keyring, because age alone doesn't authenticate the sender.
- **Users, devices and vaults:**
  - A user is a username on the server. A vault belongs to a user and is found by `(username, vault name)`; the server stores vault names in clear for that lookup. Blob storage is partitioned as `blobs/<userId>/<vaultId>/...`.
  - **One key per device per vault** (decided 2026-10-05): a key (a "device" on the server) is bound to one user and one vault at its first login, and a public key is registered only once per server. 1 user, 1 vault, 1 device = 1 key; 2 vaults on one device = 2 keys; 2 vaults with 2 devices each = 4 keys. The plugin keeps one key per server, username and vault on each device. Keys are shown by fingerprint (`SHA256:…`), with the device name, username and vault name as metadata. There is no separate membership: the key's status (`pending`, `active`, `revoked`) is its access to the vault.
  - Login names the vault (the signed challenge has a `vault:` line). A new key for an existing vault joins as pending without the shared secret, and an active key of the vault approves it. A new key for a vault name that doesn't exist needs `SHARED_SECRET`: it creates the user if needed and becomes the vault's first active key. A new key can never create a vault whose name already exists.
  - Replacing the key on a device that still has a working key hands over: the old key approves the new one, which then removes the old key. Without a working old key, the new key pairs like any new device.
  - Purging a vault removes all its keys.
  - Sharing a vault: each person uses the same username and vault name with their own key, approved by an existing member, so each person can be removed separately.
- **Adding a device to a vault:** a new key shows its public key and a pairing code. An active key of the vault approves it and rewraps the VDK to the new key.
- **Recovery key:** an optional offline age X25519 identity. The keyring is also encrypted to it, and an Ed25519 key derived from it (HKDF) may sign the next keyring version. So when every device is lost, a new key with the recovery key adds itself to the keyring and the server activates it (`POST /vaults/{id}/recover`). Only a device can set or change the recovery key, and the keyring records which device did; revoking that device removes the recovery key. Details in `docs/crypto.md` section 9.
- **Removing a key:** rotate the VDK and re-encrypt in the background. Settings list every key in the vault's keyring (fingerprint, device name, date added, status and last seen), and any device can remove any other key; the last active key can't be removed. The change feed carries the keyring version so other devices pick up the new epoch. Files a removed device already has stay on it.
- **Auth:** sshsig challenge–response.
  1. Client calls `POST /auth/challenge`.
  2. Server returns a single-use nonce that expires in 60s.
  3. Client signs it with namespace `syncryption-auth@v1`.
  4. Server verifies the sshsig itself with `cryptography` (ed25519 and sha512 only) and issues a short-lived session token.
  - Login and encryption use separate namespaces.
- **Transport:** TLS, either from Caddy or from the user's own proxy. File contents are end-to-end encrypted regardless, so the proxy only ever sees ciphertext.
- **Plugin settings:**
  - Endpoint URL
  - username
  - vault name
  - device name: a friendly label for lock warnings and the device lists. It starts as the OS hostname on desktop (without the domain) and as "iPhone", "iPad", "Android phone" or "Android tablet" on mobile, and the user can edit it; Generate asks for it (prefilled) before creating the key. The server keeps the name a key had when it first joined.
  - encryption key (setting "Encryption key"): generated on the device, one per vault, shown by fingerprint; the plugin offers a recovery key once per device while the vault has none
  - excluded paths (optional, per device)
  - an "Approve devices" button that opens the same dialog as the command, showing how many devices are waiting
  - shared secret: asked for only when the vault doesn't exist on the server yet, never stored

## Sync Scope (research outcome: full vault in place)
- **No nested pseudo-vault.** Obsidian advises against vaults inside vaults: links break and content is indexed twice. Mobile also can't open a nested vault from code.
- **Access:** the plugin syncs every file, including `app.vault.configDir`. Notes and attachments go through the Vault API so Obsidian's index stays current; the hidden `.obsidian*` folders go through `app.vault.adapter`. This works on desktop and on mobile.
- **Change detection:** the undocumented `vault.on('raw')` event, with periodic mtime/hash scans as a fallback.
- **Excluded by default:**
  - the plugin's own folder, `configDir/plugins/vault-syncryption`
  - `workspace.json`, `workspace-mobile.json`, `workspaces.json`
  - `.trash`, `.git`, `node_modules`, `.DS_Store`, `Thumbs.db`, `desktop.ini`
  - hidden files and folders outside the `.obsidian*` folders (Obsidian doesn't index them)
  - an exclude list the user can edit, per device (glob patterns, one per line)
- **Bootstrap and config changes:** write `community-plugins.json` last, then prompt the user to reload with `app:reload`. On a device's first sync, the vault's config files replace the local defaults without conflict copies.
- **Device profiles:** every `.obsidian*` folder is synced, so a device can use its own profile through Obsidian's "Override config folder" setting.

## Sync, Locking, Merge
- **Change log:** the server keeps a sequence number per vault. A commit is `PUT file {parentRev}` and returns 409 if the head has moved.
- **Locks:** lease locks with a TTL of about 2 minutes plus a heartbeat. The plugin takes one when a file is opened for editing and shows other devices' locks in the status bar. Locks are soft: the plugin warns but still allows editing.
- **Merge, client side only:** on a 409, the plugin does the following.
  1. It fetches the base revision.
  2. It decrypts base, local and remote.
  3. It runs `node-diff3`.
  4. A clean merge is committed. A dirty merge produces `name (conflict <device> <date>).md`.
  If retention already removed the base, the merge runs without it, which leaves a conflict copy more often.
- **History retention** (decided 2026-10-06, fixed values, no setting): the server keeps every revision for 30 days and at least the last 10 per file; 90 days after a file is deleted only its tombstone is left; 30 days after a file has a revision under a newer epoch, its revisions under older epochs go, even within the last 10. A file's head (tombstones included) is never removed. Pruning runs hourly before the blob GC; the server reads the epoch from the clear `meta` header (protocol.md 9.3). Old epochs stay in the keyring (crypto.md 6.4). Capacity: [scaling.md](scaling.md).
  - Binary files always get a conflict copy.
- **Live updates:** a long-poll of about 25 seconds. `requestUrl` can't stream, so SSE isn't an option.
- **Local state:** IndexedDB holds the sync cursor, the path table and an outbox of pending changes for offline work.

## Backend (Python 3.12, uv)
- **Tooling:**
  - `pyproject.toml` + `uv.lock`
  - `uv sync`, `uv run pytest`, `uv run ruff`
  - The Dockerfile uses `ghcr.io/astral-sh/uv` for the build stage and a slim runtime image that adds the `caddy` (2.11) and `litestream` (0.5.17) binaries. The Caddyfile and `litestream.yml` are generated at startup from the environment.
- **Stack:**
  - FastAPI + uvicorn
  - SQLite through stdlib `sqlite3`: one connection, used only from the event loop, WAL mode, `BEGIN IMMEDIATE` transactions
  - `aioboto3`
  - `cryptography` (sshsig verification is done in-house)
- **Storage interface:** `BlobStore` with two implementations, `LocalBlobStore` and `S3BlobStore`. The migration code calls both through the same interface.
- **Plugin types:** generated from FastAPI's OpenAPI with `openapi-typescript`.

All endpoints except `/`, `/health` and `/admin` sit under `/api/v1`. The full spec is in `docs/protocol.md`.

| Endpoint | Purpose |
|---|---|
| `POST /auth/challenge`, `POST /auth/verify` | sshsig login; joining; `SHARED_SECRET` only when a new key creates a user or vault |
| `POST /vaults/open`, `POST /vaults`, `/vaults/{id}/devices`, `GET /devices/self` | open or create the key's vault; list, approve and remove the vault's keys |
| `GET/PUT /vaults/{id}/keyring` | `keyring.age`, versioned and signed |
| `GET /vaults/{id}/changes?since=N` | change feed |
| `GET /vaults/{id}/wait?since=N` | long-poll |
| `PUT /vaults/{id}/files/{fileId}` | commit rev (`parentRev`); 409 if head moved |
| `GET /vaults/{id}/files/{fileId}/revs/{rev}` | history (merge base, restore) |
| `PUT/GET/HEAD /vaults/{id}/blobs/{hash}`, `POST /vaults/{id}/blobs/missing` | ciphertext blobs (4 MiB chunks), scoped per vault |
| `GET /vaults/{id}/locks`, `POST/DELETE /vaults/{id}/locks/{fileId}` | lease locks |
| `GET /devices`, `/devices/{id}/approve`, `DELETE /devices/{id}` | device management |
| `GET /` | HTML page for users: what the service is, how to connect, that joining needs the shared secret, the admin contact, maintenance state |
| `GET /health` | container healthcheck; reports `"status": "maintenance"` (still 200) while maintenance mode is on |
| `/admin`, `/admin/api/...` (outside `/api/v1`, not in the OpenAPI schema) | admin page and its JSON API (protocol.md 14) |

## Repo Layout
```
/
├── README.md, LICENSE (MIT), SECURITY.md
├── manifest.json, versions.json   # copies of plugin/'s, read by Obsidian for updates
├── docker-compose.dev.yml    # development (MinIO)
├── scripts/  build.sh (image), push-public-release.sh (private repo only)
├── docs/ architecture.md, protocol.md, crypto.md, self-hosting.md
├── backend/  pyproject.toml, uv.lock, Dockerfile, entrypoint.sh, container-checks.sh,
│             docker/docker-compose.yml (hosting; all vars inline, no .env),
│             src/syncryption_server/{app,auth,storage,sync,locks,migrate}/, tests/
├── plugin/   manifest.json, package.json, esbuild.config.mjs,
│             src/{main,settings,crypto,sync,api}/, tests/
└── testvectors/              # age ssh-ed25519 + file-encryption vectors
```
`docker-compose.dev.yml` adds MinIO (`cgr.dev/chainguard/minio`, since the upstream images are no longer published) for S3 tests and is used only for development.

## Milestones
- **M0, specs and scaffold:**
  - `docs/crypto.md` and `docs/protocol.md`
  - repo skeleton
  - CI: ruff, pytest, eslint, vitest, plugin build
- **M1, crypto core:**
  - OpenSSH Ed25519 parser
  - age ssh-ed25519 stanza
  - keyring and file encryption
  - test vectors
- **M2, backend core:**
  - sshsig auth
  - devices
  - keyring
  - `BlobStore` (local and S3)
  - revisions with 409 conflicts
  - change feed
- **M3, container:**
  - Dockerfile
  - entrypoint covering `BEHIND_PROXY`, `URL`, S3 selection and `MIGRATE_TO_S3`
  - Caddy and Litestream
  - `backend/docker/docker-compose.yml`
- **M4, plugin sync:**
  - settings
  - pairing
  - initial fetch and push
  - incremental sync
  - outbox
  - diff3 merge with conflict copies
- **M5, full vault:**
  - `configDir` sync with the exclude list
  - reload flow
  - `.obsidian*` profiles
- **M6, locks and live updates:**
  - lease locks
  - long-poll
  - status-bar UI
  - "Approve devices" button in the settings
- **M7, hardening:**
  - revision history and restore
  - recovery key
  - device revocation with VDK rotation
  - rate limiting
  - mobile QA (ships as beta in 0.1.0 and is finished after the release)
- **M8, release:**
  - public GitHub repo `ibehren1/obsidian-vault-syncryption`. `scripts/push-public-release.sh` pushes a snapshot of `main` with private files stripped (`scripts/`, `CLAUDE.md`, `STATUS.md`, `.gitea/`, `.claude/`), one commit per push, so the private history stays private.
  - plugin id `vault-syncryption`; `manifest.json` and `versions.json` are copied to the repo root (Obsidian reads them there), kept in sync by `npm version` and checked in CI.
  - `.github/workflows/release.yml` on the public repo creates the GitHub release (tag = version, `main.js`, `manifest.json`, `styles.css`) when `main` has a version that isn't released yet. BRAT works from these releases until the store listing is approved.
  - submission to the community plugin store
  - versioning: the plugin (`plugin/package.json`, both manifests) and the backend (`backend/pyproject.toml`, `__version__`, image tag) have independent `x.y.z` versions. Every commit that changes a component's code bumps its `z` (docs alone don't); `x` and `y` change only when the user says so. Compatibility is the separate protocol version (protocol.md 13), not the server version.
  - admin page `/admin`, opened with `ADMIN_TOKEN` (Bearer header, or a login form that starts a 12-hour HttpOnly, Secure, SameSite=Strict session cookie with CSRF tokens). It lists users with their devices and vaults (stored size, file count, created and last active). Users and vaults are disabled first (access blocked with 403 `user_disabled` / `vault_disabled`, data kept, can be enabled again), and only a disabled one can be purged, after typing its name. Wrong tokens are rate limited (5 per 15 minutes per IP) and admin actions are logged. The plugin stops syncing on these 403s; no protocol bump, since old plugins just see a 403.
  - `ADMIN_CONTACT` and the `/` page: an optional contact line (see Hosting), shown on an HTML `/` page that describes the service (self-hosted, end-to-end encrypted Obsidian sync; the server holds only ciphertext), how to connect (install the plugin; enter this URL, a username and a vault name; create an encryption key), that joining needs the shared secret from the admin, the admin contact, and whether the server is in maintenance.
  - maintenance mode: the admin turns it on (with an optional message) and off from the admin page or `POST /admin/api/maintenance/on` (optional body `{"message": "..."}`) and `POST /admin/api/maintenance/off`. It is stored in the database, so it persists across restarts. While on, the sync API answers 503 `maintenance` with `Retry-After`, and the plugin shows "maintenance" (sync paused, resumes by itself, contact the admin) and retries automatically. `/`, `/health` (200 with `"status": "maintenance"`) and `/admin` keep working. Details in protocol.md 2 and 14.

## Post-v1 Ideas
- **SSH agent unlock (desktop only; would bring back external keys, which 0.1.3 removed):** keep the private key in `ssh-agent` (macOS Keychain, gnome-keyring, KeePassXC, the Windows OpenSSH agent or Pageant) instead of `SecretStorage`.
  - Login already works through an agent, since it is just an sshsig signature.
  - An agent can't do the X25519 operation that the age `ssh-ed25519` stanza needs. Ed25519 signatures are deterministic, though, so the plugin can derive a second X25519 identity from an agent signature over a fixed message under its own namespace (`syncryption-unlock@v1`). The keyring is then also encrypted to that identity, and the standard stanza stays for `age -d -i` recovery.
  - Needs Node APIs (Unix socket or named pipe), so it goes in a desktop-only module. There is no agent on Android or iOS.
  - Risk: a forwarded agent (`ssh -A`) lets the remote host derive the vault key. Recommend confirm-on-use (`ssh-add -c`).

## Verification
- Crypto:
  - Vectors produced by Go `age` must decrypt in the plugin.
  - Plugin output must decrypt with `age -d -i id_ed25519`.
- Backend (`uv run pytest`, MinIO via `docker-compose.dev.yml`):
  - replayed challenges are rejected
  - a stale `parentRev` returns 409
  - locks expire
  - the change feed stays in order
  - `MIGRATE_TO_S3` copies every blob, can resume when killed partway, does nothing on a second run, and leaves local files in place
- Container:
  - `BEHIND_PROXY=FALSE` without `URL` exits with an error.
  - Partial `S3_*` variables exit with an error.
  - An empty `SHARED_SECRET` exits with an error.
  - A missing or short `ADMIN_TOKEN` exits with an error.
  - `BEHIND_PROXY=TRUE` serves `/health` over HTTP on 8080.
  - Let's Encrypt is tested against the staging CA, either on a VPS with a real domain or using Pebble in CI.
- Integration:
  - Two headless sync engines run concurrent and offline edits. They must converge, merge cleanly or produce conflict copies, and leave no plaintext in `./data`, MinIO or SQLite.
- Manual:
  - A desktop vault and a mobile vault point at a container on a real domain.
  - A fresh device is attached. Plugins, themes and hotkeys must arrive and work after the reload prompt.
