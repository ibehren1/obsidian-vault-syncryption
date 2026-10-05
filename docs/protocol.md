# Vault Syncryption HTTP Protocol (v1)

Status: draft for M0. The FastAPI app is the implementation of this document, and the
plugin's TypeScript types are generated from its OpenAPI schema. Crypto details live in
[crypto.md](crypto.md).

## 1. Conventions
- **Base URL:** the configured endpoint, e.g. `https://notes.example.com`. All paths
  below are under `/api/v1`, except `/health`.
- **Bodies:** JSON (`application/json`), except blob uploads and downloads, which are
  `application/octet-stream`.
- **Binary values in JSON:** `b64u` (base64url, no padding).
- **IDs:**
  - `userId`, `vaultId`: UUIDv4 strings.
  - `deviceId`: `d_` + 22 base62 characters.
  - `fileId`: `b64u` of the 32-byte HMAC (43 characters).
  - `blobId`: 64 lowercase hex characters (SHA-256 of the blob bytes).
- **Times:** RFC 3339 UTC strings (`2026-10-02T12:00:00Z`).
- **Sequence numbers:** integers. Each vault has its own counter, starting at 1.
- **Auth:** `Authorization: Bearer <token>` on every endpoint except those marked
  *public*.
- **Errors:** a non-2xx status with
  ```json
  { "error": "stale_parent", "message": "human readable", "details": { } }
  ```
  `error` is a stable machine code. `message` never contains plaintext, keys or tokens.

| Status | `error` codes |
|---|---|
| 400 | `bad_request`, `bad_signature_format` |
| 401 | `unauthenticated`, `token_expired`, `challenge_invalid` |
| 403 | `forbidden`, `join_required`, `device_pending`, `device_revoked` |
| 404 | `not_found` |
| 409 | `stale_parent`, `exists`, `keyring_version` |
| 413 | `too_large` |
| 422 | `missing_blobs`, `hash_mismatch` |
| 423 | `locked` |
| 429 | `rate_limited` (with `Retry-After`) |

## 2. Health
`GET /health` (*public*) returns `200 {"status": "ok", "version": "0.1.0"}` once the
database is open and the blob store is reachable, and `503` otherwise. It is used by the
container healthcheck.

## 3. Model: users, devices, vaults
The server tracks identity and data separately:
- **User:** a `username`, unique on the server (`[a-z0-9._-]{1,32}`, lowercase).
- **Device:** one registered Ed25519 public key belonging to a user. The same key can be
  used for any number of that user's vaults. Several installations that share one key
  (for example people sharing a vault by sharing the username, vault and key) are a single
  device to the server. Each installation also sends a random `clientId` (kept in the
  app's local storage, so it is never synced), used only to tell installations apart in locks (section 11).
- **Vault:** belongs to one user and is identified by `(username, vault name)`. The vault
  name is unique per user (1 to 64 characters, NFC, trimmed, compared exactly). The server
  stores the name in clear, because it needs it to look the vault up.
- **Membership:** a device's access to a vault, `pending` or `active`. Membership on the
  server is the access-control list. The keyring ([crypto.md](crypto.md) section 6) is
  what actually grants the ability to decrypt, and the two are kept in step by clients.

Every vault endpoint (`/api/v1/vaults/{vaultId}/...`) requires an active membership of
the caller's device in that vault, otherwise `403 forbidden`.

## 4. Joining the server (shared secret)
The server is configured with a `SHARED_SECRET` environment variable. It is handed out by
whoever runs the server, through whatever channel the organisation uses. The secret is
needed only the **first time a key connects** to the server: to create a user, or to add a
new key to an existing user. Logging in later with a known key never needs it.

The plugin asks for it only when the server says it is needed (`join_required`), and
doesn't store it.

## 5. Auth

### 5.1 Challenge
`POST /api/v1/auth/challenge` (*public*)
```json
{ "username": "alice", "publicKey": "ssh-ed25519 AAAA..." }
```
Response `200`:
```json
{
  "challengeId": "<b64u 16 bytes>",
  "message": "syncryption-auth@v1\norigin: https://notes.example.com\nusername: alice\nkey: SHA256:...\nnonce: <b64u 32 bytes>\nexpires: 2026-10-02T12:01:00Z\n",
  "expiresAt": "2026-10-02T12:01:00Z"
}
```
- A challenge is issued for any well-formed Ed25519 key and any valid username, whether or
  not they are registered.
- `origin` is `URL` if it is set, otherwise the scheme and host the request arrived on
  (honouring `X-Forwarded-Proto`/`X-Forwarded-Host` when `BEHIND_PROXY=TRUE`).
- The challenge is single-use and expires after 60 s.

The client must check, before signing, that `origin` equals its configured endpoint's
origin, `username` and `key` are its own, and the message has exactly these lines in this
order. That stops a malicious server from relaying a challenge from another server.

### 5.2 Verify (log in or join)
`POST /api/v1/auth/verify` (*public*)
```json
{
  "challengeId": "...",
  "signature": "-----BEGIN SSH SIGNATURE-----\n...",
  "deviceName": "MacBook",
  "sharedSecret": "only when joining"
}
```
The signature is an sshsig over `message` (UTF-8) with namespace `syncryption-auth@v1`
([crypto.md](crypto.md) section 7). The server checks, in order:
1. The challenge exists, hasn't expired and hasn't been used. It is then marked used,
   whatever the outcome.
2. The signature parses, uses namespace `syncryption-auth@v1`, and its public key equals
   the challenge's key.
3. The signature verifies. Failures in steps 1 to 3 return `401 challenge_invalid`, with
   no further detail.
4. It then looks up the key and username:

| Situation | `sharedSecret` | Result |
|---|---|---|
| Key is an active device of `username` | ignored | log in, `status: "active"` |
| Key is a pending device of `username` | ignored | log in, `status: "pending"` |
| Key is a revoked device of `username` | ignored | `403 device_revoked` |
| `username` doesn't exist | required | create the user and the key as an **active** device |
| `username` exists, key unknown | required | add the key as a **pending** device |
| Secret missing or wrong in the two cases above | | `403 join_required` |

The secret is compared in constant time. The `join_required` message is generic: "This
server needs an access secret to join. Contact your administrator." Its rate limit is
strict (section 12): only a secret that was sent and is wrong counts as a failure, so a
client that first tries without one (and then asks the user) isn't penalised. Adding a
pending device when the user already has 5 returns `429 rate_limited`.

Response `200`:
```json
{ "token": "<b64u 32 bytes>", "expiresAt": "...", "deviceId": "d_...", "status": "active", "created": true }
```
- `created` is true when this request created the user or the device.
- A pending device is approved by an active device of the same user, either directly
  (section 6) or by approving its vault membership (section 7.3). Until then its token only
  works for `GET /api/v1/devices/self`, `POST /api/v1/vaults/open` and the recovery
  endpoints (section 7.4), and everything else
  returns `403 device_pending`. Status is checked on every request, so the same token gains
  access as soon as it is approved.
- Tokens are random, stored as `SHA-256(token)`, and expire after 1 hour. The client logs
  in again on `401 token_expired`.

## 6. Devices
| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/v1/devices` | the user's devices |
| `GET` | `/api/v1/devices/self` | pending tokens allowed |
| `POST` | `/api/v1/devices/{deviceId}/approve` | pending to active, without a vault |
| `DELETE` | `/api/v1/devices/{deviceId}` | revoke |

`GET /devices` returns `{"devices": [<device object>, ...]}`, oldest first. The other
three return the device object. Approving a revoked device returns `400 bad_request`.

**Device object:**
```json
{
  "id": "d_...",
  "name": "MacBook",
  "publicKey": "ssh-ed25519 AAAA...",
  "fingerprint": "SHA256:...",
  "pairingCode": "XXXXX-XXXXX",
  "status": "pending",
  "createdAt": "...",
  "lastSeenAt": "..."
}
```
- `status` is `pending`, `active` or `revoked`. A user has at most 5 pending devices, and
  a pending device that isn't approved expires after 24 h.
- `pairingCode` is computed from the public key ([crypto.md](crypto.md) section 6.5). The
  approving client recomputes it from `publicKey` and never trusts the server's value.
- **Revoke** sets `revoked`, removes all its vault memberships, deletes its sessions and
  releases its locks. Clients then rotate the keyring of every affected vault
  ([crypto.md](crypto.md) section 8.4). The last active device of a user can't be revoked
  (`409 exists`).

## 7. Vaults, members and keyring

### 7.1 Opening a vault
`POST /api/v1/vaults/open` (pending tokens allowed)
```json
{ "name": "Personal" }
```
| Situation | Result |
|---|---|
| Vault exists, caller is an active member | `200 {"vault": <vault object>, "membership": "active"}` |
| Vault exists, caller isn't a member yet | create a pending membership, `200 {"vault": ..., "membership": "pending"}` |
| Vault doesn't exist | `404 not_found`, the client then creates it (7.2) |

The pending case is how a device joins a vault, whether it is a new key or an existing
key opening one of the user's other vaults. The plugin shows its pairing code and polls
`/vaults/open` (or long-polls `/devices/self`) until the membership is active.

**Vault object:**
```json
{ "id": "<uuid>", "name": "Personal", "keyringVersion": 7, "seq": 1042, "createdAt": "..." }
```

### 7.2 Endpoints
| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/v1/vaults` | the user's vaults, with the caller's membership in each |
| `POST` | `/api/v1/vaults` | create: `{"id", "name", "keyring": <keyring object>}`, caller must be active |
| `GET` | `/api/v1/vaults/{id}/members` | members and their status |
| `POST` | `/api/v1/vaults/{id}/members/{deviceId}/approve` | activates the membership (and the device, if pending) |
| `DELETE` | `/api/v1/vaults/{id}/members/{deviceId}` | remove from this vault only |
| `GET` | `/api/v1/vaults/{id}/keyring[?version=N]` | latest, or a specific version |
| `PUT` | `/api/v1/vaults/{id}/keyring` | upload the next version |

- `POST /vaults` returns `201` with the vault object, or `409 exists` if the name is
  taken. The `vaultId` is chosen by the client (UUIDv4, also inside the keyring plaintext)
  so the first keyring can be built before the request.
- Approving a membership is the server half of pairing. The approving client must also
  add the device to the keyring ([crypto.md](crypto.md) section 6.5). Approval can't
  grant decryption by itself, since the server never changes a keyring.
- Removing a member is followed by a keyring rotation, as with revocation. It returns
  `204` and releases the device's locks in that vault. The last active member can't be
  removed (`409 exists`).

Response shapes:
- `GET /vaults`: `{"vaults": [{"vault": <vault object>, "membership": "active" | "pending" | null}]}`.
- `GET .../members`: `{"members": [{"device": <device object>, "status": "active" | "pending", "createdAt": "..."}]}`.
  Approving a member returns one such entry.

### 7.3 Keyring object
GET response, PUT body, and the `keyring` field of `POST /vaults`:
```json
{
  "version": 7,
  "keyring": "<b64u keyring.age>",
  "signature": "-----BEGIN SSH SIGNATURE-----...",
  "signer": "d_...",
  "recoverySigner": "ssh-ed25519 AAAA...",
  "byRecovery": false,
  "createdAt": "..."
}
```
- `POST /vaults` takes `version: 1`. `PUT` must have `version` = current + 1, otherwise
  `409 keyring_version` with the current version in `details`.
- The server checks that `signer` is the caller's device (otherwise `403 forbidden`), that
  it is an active member, and that the signature verifies with namespace
  `syncryption-keyring@v1` under the caller's key (otherwise `400 bad_signature_format`).
  It doesn't (and can't) check the plaintext.
- `recoverySigner` is a copy of the keyring's recovery signing key
  ([crypto.md](crypto.md) section 9), or `null` without a recovery key. Clients send it with
  every upload, and the server uses it to check recovery uploads (7.4). An invalid or
  non-Ed25519 key gives `400 bad_request`.
- `byRecovery` (responses only) is true for a version uploaded through `/recover`.
- `PUT` returns `201` with the stored keyring object.
- Every version is kept, so clients can verify the chain
  ([crypto.md](crypto.md) section 6.4). Maximum size is 1 MiB.

### 7.4 Recovery
A device that holds the vault's recovery key adds itself when no device is left to
approve it ([crypto.md](crypto.md) section 9). Both endpoints need a pending or active
membership (from `/vaults/open`, otherwise `403 forbidden`), and pending tokens are allowed.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/v1/vaults/{id}/recovery` | the current keyring object |
| `POST` | `/api/v1/vaults/{id}/recover` | upload the next version, signed by the recovery key |

- Both return `404 no_recovery` if the current version has no `recoverySigner`.
- The `POST` body is a keyring object, as for `PUT .../keyring`, with `signer` the caller's
  device. The signature must verify under the current version's `recoverySigner`
  (otherwise `400 bad_signature_format`), and the upload must keep the same
  `recoverySigner` (otherwise `400 bad_request`). `version` must be current + 1
  (otherwise `409 keyring_version`).
- On success the server stores the version with `byRecovery: true`, activates the caller's
  membership and the device itself if it is pending, and returns `201` with the keyring
  object.

## 8. Blobs
Blobs are encrypted chunks ([crypto.md](crypto.md) section 8.2), at most
4 MiB + 45 bytes.

| Method | Path | Notes |
|---|---|---|
| `PUT` | `/api/v1/vaults/{id}/blobs/{blobId}` | raw bytes. `201` if new, `200` if it already exists, both with `{"id", "size"}` |
| `HEAD` | `/api/v1/vaults/{id}/blobs/{blobId}` | `200` or `404` |
| `GET` | `/api/v1/vaults/{id}/blobs/{blobId}` | raw bytes |
| `POST` | `/api/v1/vaults/{id}/blobs/missing` | `{"ids": [...]}` returns `{"missing": [...]}`, at most 1000 ids |

- On `PUT`, the server hashes the body and returns `422 hash_mismatch` if it doesn't
  equal `blobId`, or `413 too_large` if it exceeds the limit.
- Blobs are partitioned by user and vault. The store key is
  `blobs/<userId>/<vaultId>/<blobId[0:2]>/<blobId>`, using ids rather than names so a
  rename doesn't move data. The layout is the same in `LocalBlobStore` and
  `S3BlobStore`, which keeps `MIGRATE_TO_S3` a straight copy.
- Blobs that no revision references are deleted by a periodic garbage collector after a
  grace period of 24 h, so an upload in progress isn't lost.

## 9. Files and revisions

### 9.1 Revision object
```json
{
  "fileId": "<43 chars>",
  "rev": 1042,
  "parentRev": 1017,
  "deleted": false,
  "meta": "<b64u encrypted metadata>",
  "blobs": ["<blobId>", "..."],
  "size": 1279,
  "device": "d_...",
  "createdAt": "..."
}
```
- `rev` is the vault sequence number assigned at commit, so it is unique in the vault and
  increases with every commit.
- `size` is the total ciphertext size (`meta` + blobs).
- `deleted` is in clear so the server can garbage collect. The encrypted metadata repeats
  it, and the client trusts only the encrypted value.

### 9.2 Endpoints
| Method | Path | Notes |
|---|---|---|
| `PUT` | `/api/v1/vaults/{id}/files/{fileId}` | commit a revision |
| `GET` | `/api/v1/vaults/{id}/files/{fileId}` | head revision |
| `GET` | `/api/v1/vaults/{id}/files/{fileId}/revs?before=REV&limit=50` | history, newest first |
| `GET` | `/api/v1/vaults/{id}/files/{fileId}/revs/{rev}` | one revision (merge base, restore) |

**Commit.** `PUT /api/v1/vaults/{id}/files/{fileId}`
```json
{ "parentRev": 1017, "deleted": false, "meta": "...", "blobs": ["..."] }
```
In a single SQLite transaction, the server:
1. Compares `parentRev` with the current head. `null` means "the file must not exist yet".
   If it doesn't match, it returns `409 stale_parent` with
   `details: {"head": <revision object>}`, so the client has the remote side for its
   merge without another round trip.
2. Checks that every id in `blobs` exists, or returns `422 missing_blobs` with
   `details: {"missing": [...]}`.
3. Increments the vault `seq`, inserts the revision with `rev = seq`, moves the head and
   appends to the change feed.

Response `201`: the revision object.

Other checks: `meta` is at most 64 KiB once decoded (`413 too_large`), a revision has at
most 10,000 blobs, and a deletion must have an empty `blobs` list (`400 bad_request`).

`GET .../revs` returns `{"revisions": [<revision object>, ...], "more": bool}`. `limit` is
at most 100 (default 50). To page back, pass the last `rev` as `before`.

Re-creating a deleted file uses the tombstone's `rev` as `parentRev`. Locks are never
checked here: they are advisory (section 11).

## 10. Change feed and long-poll

### 10.1 Changes
`GET /api/v1/vaults/{id}/changes?since=N&limit=500`
```json
{
  "changes": [ { "...revision object..." } ],
  "cursor": 1042,
  "more": false,
  "keyringVersion": 4
}
```
- `changes` lists, in ascending `rev` order, every revision with `rev > since`, including
  `meta`, so a client can apply the feed without one request per file.
- `cursor` is the highest `rev` returned (or `since` if there are none). The client stores
  it in IndexedDB after it has applied the batch.
- `limit` is at most 1000.
- The feed isn't compacted in v1.
- `keyringVersion` is the vault's current keyring version. A client with an older one
  fetches the keyring before it applies the batch, so it knows a new epoch first (crypto.md
  8.4).

### 10.2 Wait (long-poll)
`GET /api/v1/vaults/{id}/wait?since=N&locksSince=M&keyringSince=K&timeout=25`
```json
{ "seq": 1042, "locksSeq": 88, "keyringVersion": 4, "changed": true }
```
- Returns as soon as vault `seq > since`, `locksSeq > locksSince` or, if `keyringSince` is
  given, the keyring version `> keyringSince`, or after `timeout` seconds (at most 25)
  with `changed: false`.
- The client then calls `/changes` or `/locks` as needed and loops.
- On network errors it backs off exponentially, from 1 s up to 60 s. It also backs off
  when a sync after a wake-up didn't reach `seq`, so a failing sync doesn't spin.
- Implemented with an in-process `asyncio.Condition` per vault. There is only one
  container, so no cross-process notification is needed.

## 11. Locks
Locks are **soft lease locks**: they warn other devices and never block a commit.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/v1/vaults/{id}/locks` | active locks, plus `locksSeq` |
| `POST` | `/api/v1/vaults/{id}/locks/{fileId}` | acquire or renew |
| `DELETE` | `/api/v1/vaults/{id}/locks/{fileId}` | release |

**Lock object:**
```json
{ "fileId": "...", "device": "d_...", "clientId": "<b64u 16 bytes>", "deviceName": "Pixel", "expiresAt": "..." }
```
- The holder is the pair `(device, clientId)`, so installations that share a key still
  see each other's locks.
- **Acquire or renew:** body `{"clientId": "...", "ttl": 120}` (seconds, 30 to 300,
  default 120). Returns `200` with the lock object if it is free, expired or already held
  by the caller (which renews it). Returns `423 locked` with
  `details: {"lock": <lock object>}` if another holder has it. The plugin shows the
  warning and the user may edit anyway.
- **Heartbeat:** the plugin renews every `ttl / 2` while the file is open in the active
  editor. It locks only text files it can merge, releases the lock when another file
  opens or Obsidian goes to the background, and takes it again when Obsidian comes back.
- **Release:** `DELETE` with `?clientId=...`, returns `204`. It is idempotent, and only the holder can release.
- Expired locks are treated as absent and swept lazily.
- Taking a lock (not renewing one), a release, an expiry seen by the sweeper, or a
  revocation increments the vault's `locksSeq`. Renewals don't, so they wake no one.

## 12. Limits and rate limiting
| Limit | Value |
|---|---|
| Blob size | 4 MiB + 45 bytes |
| `meta` size | 64 KiB |
| Keyring size | 1 MiB |
| Other request bodies | 2 MiB, checked before the body is read (`413 too_large`) |
| `/auth/*` | 10 requests/min per client address |
| Wrong shared secrets | 5 per hour per client address, and 50 per hour from all addresses together, then `429`, to stop guessing `SHARED_SECRET`. The server logs a warning when joining pauses. |
| Pending devices | 5 per user; they expire after 24 hours |
| `POST /vaults/{id}/recover` | 10 requests/min per device |
| Concurrent `/wait` per device | 2. The oldest is answered with `changed: false`. |

- A client address is the connecting IP (the last `X-Forwarded-For` entry with
  `BEHIND_PROXY=TRUE`). IPv6 addresses count by their /64, since one host usually has a
  whole /64.
- There is no per-username login limit: anyone who knows a username could use it to lock
  that user's devices out, and sshsig signatures can't be guessed.
- Requests of active devices aren't rate limited otherwise. Only devices approved by the
  user reach them, and a first sync of a large vault makes many requests in a short time.
- `429` responses carry `Retry-After` in seconds.

## 13. Versioning
- The path prefix `/api/v1` changes only on a breaking change.
- Every response carries `X-Syncryption-Version: <server version>`.
- The plugin refuses to sync with a server whose major version differs, and tells the
  user to update one side.
