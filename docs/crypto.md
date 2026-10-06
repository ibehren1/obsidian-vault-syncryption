# Vault Syncryption Crypto Specification (v1)

Status: v1, implemented in the plugin and backend since M1–M4. Parts that aren't built yet
are marked with their milestone. Both the plugin (TypeScript) and the backend (Python)
implement against this document, and every primitive below has a vector in `testvectors/`.

## Overview
Each device has its own encryption key, an Ed25519 key in OpenSSH format. A vault has one
random vault data key (`VDK`) per key epoch. The `VDK`s live in the **keyring**, an age
file encrypted to every device's encryption key (age `ssh-ed25519` stanza) and signed by the device that last changed it. File paths and contents are encrypted
under keys derived from the `VDK`, so the server only stores the keyring, opaque file ids
and ciphertext.

```mermaid
flowchart TD
    subgraph device["Each device (private key never leaves it)"]
        ssh["Encryption key: Ed25519, OpenSSH format<br/>(SecretStorage)"]
        x["X25519 key<br/>(converted, 3.4)"]
        ssh --> x
    end
    subgraph keyring["keyring.age (section 6)"]
        vdk["VDK per epoch"]
        idx["indexKey"]
        devs["devices list"]
    end
    x -- "age ssh-ed25519 stanza (4)<br/>unwraps" --> keyring
    ssh -- "sshsig signs (6.3)" --> keyring
    idx -- "HMAC(path)" --> fid["fileId"]
    vdk -- "HKDF(fileId)" --> fk["fileKey"]
    fid --> fk
    fk -- "XChaCha20-Poly1305" --> meta["metadata object<br/>(path, size, times, chunk list)"]
    fk -- "XChaCha20-Poly1305" --> chunks["chunk objects<br/>(4 MiB each)"]
```

What each side holds:

```mermaid
flowchart LR
    subgraph client["Client (trusted)"]
        c1["private encryption key"]
        c2["decrypted keyring: VDKs, indexKey"]
        c3["plaintext paths and files"]
    end
    subgraph server["Server and storage (untrusted)"]
        s1["username, vault names,<br/>device names and public keys"]
        s2["keyring.age and its signature"]
        s3["fileId, revision numbers,<br/>encrypted metadata"]
        s4["encrypted chunk blobs"]
    end
    client -- "only ciphertext, public keys,<br/>and signatures" --> server
```

## 1. Goals and threat model
- The server, its storage (local disk, S3, Litestream replicas) and any reverse proxy are
  **untrusted for confidentiality and integrity**. They may read, drop, replay, reorder or
  forge anything they store or relay.
- The server must never learn: file contents, file paths, file names, or any key
  material.
- The server does learn: the username, **vault names** (needed to look vaults up, see
  protocol.md section 3), device names and public keys, which devices belong to which
  vault, file count, the ciphertext size of each revision and chunk, timestamps and the
  order of commits, lock state, and which `fileId`s change together. This leakage is
  accepted.
- The `SHARED_SECRET` only controls who may register on the server. It is not key
  material and protects no data: a user who knows it still can't read any vault they
  aren't a keyring member of.
- People who share a vault by sharing one key are one identity to this design. They can't
  be told apart or revoked separately. Sharing through separate keys under the same
  username (each paired into the vault) avoids that.
- A device whose key leaks can read everything that device could read. Revocation
  (section 8) protects data written **after** the revocation.
- A malicious server can deny service or roll the whole vault back to an older state it
  has seen. Clients detect rollback of the keyring (section 6.4). Detecting rollback of
  individual files is out of scope for v1.

## 2. Notation and primitives
- `||` is byte concatenation. `u32be(n)` is a 4-byte big-endian integer.
- `utf8(s)` is the UTF-8 encoding of string `s`.
- `b64u(x)` is base64url **without** padding (RFC 4648 section 5). Every binary value in
  the JSON documents and API of this project uses `b64u` unless stated otherwise.
- `hex(x)` is lowercase hexadecimal.
- `HKDF(ikm, salt, info, L)` is HKDF-SHA256 (RFC 5869). An empty salt means 32 zero bytes,
  as in the RFC.
- `HMAC(k, m)` is HMAC-SHA256.
- `AEAD(k, n, m, ad)` is XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) with a 32-byte key,
  a 24-byte nonce and a 16-byte tag appended to the ciphertext.
- `RAND(n)` is `n` bytes from a CSPRNG (`crypto.getRandomValues` in the plugin,
  `secrets.token_bytes` in the backend).

Libraries (plugin): `@noble/ciphers` (XChaCha20-Poly1305, AES-CTR fallback),
`@noble/hashes` (SHA-2, HKDF, HMAC), `bcrypt-pbkdf` (pure JS), `@noble/curves`
(Ed25519, X25519), `age-encryption` (typage). WebCrypto may be used where it is available
and faster, but results must match the noble implementations byte for byte. No Node APIs.

Libraries (backend): `cryptography`. The backend verifies sshsig signatures itself
(ed25519 and sha512 only, section 7) rather than through a general sshsig package, so it
accepts exactly the format below. It never encrypts or decrypts vault data.

## 3. Identity keys
The user-facing name is **encryption key**: one key per device, used both to log in
(sshsig, section 7) and to unwrap the keyring (age `ssh-ed25519` stanza, section 4).

### 3.1 Key type
Only **Ed25519** keys in OpenSSH format are accepted (`ssh-ed25519`). Any other key type (RSA, ECDSA,
`sk-ssh-ed25519@openssh.com`) is rejected with a clear message.

Public key wire format (RFC 8709):
```
pubWire = string("ssh-ed25519") || string(pk32)
string(x) = u32be(len(x)) || x
```
The text form is `ssh-ed25519 <base64(pubWire)> [comment]`, with standard base64 and
padding, as in `authorized_keys`.

The fingerprint is `"SHA256:" + base64(SHA-256(pubWire))` with standard base64 and the
padding stripped, which is what `ssh-keygen -l` prints.

### 3.2 OpenSSH private key parsing
The plugin parses the `openssh-key-v1` format itself (see `docs/PLAN.md` for why `sshpk`
is not used).

```
-----BEGIN OPENSSH PRIVATE KEY-----
base64( "openssh-key-v1\0"
        string ciphername        "none" | "aes256-ctr"
        string kdfname           "none" | "bcrypt"
        string kdfoptions        "" | string(salt) || u32be(rounds)
        u32be  nkeys             must be 1
        string publickey         pubWire
        string encrypted_section )
-----END OPENSSH PRIVATE KEY-----
```
- If `ciphername` is `aes256-ctr`, derive `kiv = bcrypt_pbkdf(passphrase, salt, rounds, 48)`.
  The key is `kiv[0:32]` and the counter IV is `kiv[32:48]`. Decrypt the section with
  AES-256-CTR.
- Other ciphers (`aes256-gcm@openssh.com`, `chacha20-poly1305@openssh.com`, ...) are
  rejected with "unsupported key cipher, re-encrypt with `ssh-keygen -p -Z aes256-ctr`".
- The decrypted section is:
  ```
  u32be checkint1
  u32be checkint2          must equal checkint1, otherwise the passphrase is wrong
  string "ssh-ed25519"
  string pk32
  string sk64              seed32 || pk32
  string comment
  padding                  bytes 1, 2, 3, ... up to the block size (8 or 16)
  ```
- Checks: `checkint1 == checkint2`; `sk64[32:64] == pk32`; `pk32` matches the outer
  `publickey`; Ed25519 public key derived from `seed32` equals `pk32`; padding is
  `1, 2, 3, ...`. Any failure is a hard error.
- The only secret the plugin keeps is `seed32`.

### 3.3 Generated device keys and local storage
- Every device generates its own key: `seed32 = RAND(32)`. There is no import (removed in
  plugin 0.1.3): a new device pairs, and the recovery key (section 9) covers losing every
  device.
- The private key is stored **only** in Obsidian's
  `SecretStorage` (`app.secretStorage`, Obsidian 1.11.4 and later), **in OpenSSH format**
  (so it stays compatible with `age -d -i` and `ssh-keygen`, though the plugin doesn't export it). It is
  never written to `data.json` or anywhere else in the vault folder, so backups and other
  sync tools that copy the vault can't pick it up.
- The plugin requires `SecretStorage` (`minAppVersion` 1.13.0 in `manifest.json`, which also brings the declarative settings API). There
  is no fallback: if the API is missing, the plugin refuses to set up a key and asks the
  user to update Obsidian.
- One key per device per vault (protocol.md 3): a key is bound to one user and one vault
  when it first logs in, and a public key can be registered only once per server.
- Secret id: `syncryption-key-` + `hex(SHA-256(utf8(origin + "\n" + username + "\n" + vaultName))[0:8])`
  (`vaultName` NFC-normalised and trimmed), so each vault on a device has its own key. `data.json`
  keeps only the public key and this id.
- Optional local passphrase, as an extra layer on top of `SecretStorage`:
  `ciphername = aes256-ctr`, `kdfname = bcrypt`, `salt = RAND(16)`, `rounds = 16` (the
  `ssh-keygen` default). Without one: `none`/`none`. The key writer supports it, but the
  settings' Generate button doesn't ask for a passphrase. Keys imported by plugin versions
  before 0.1.3 were stored as imported and may have one; the plugin still unlocks them.
- The unlocked seed
  is kept only in memory for the lifetime of the Obsidian session. Session tokens and
  decrypted VDKs are also memory only.
- Whether `SecretStorage` is backed by the iOS Keychain and Android Keystore, and whether
  other plugins can read it, is checked during mobile QA (M7). Any Obsidian plugin runs
  with full access to the app, so no storage choice protects against a malicious plugin.

### 3.4 Ed25519 to X25519 conversion
Used by the age stanza (section 4).
- Public: `pkX = edwardsToMontgomery(pk32)` (the birational map `u = (1 + y) / (1 - y)`).
- Private: `skX = SHA-512(seed32)[0:32]`. Clamping is done by the X25519 function.

## 4. age `ssh-ed25519` recipient
This is the stanza from age (`filippo.io/age/agessh`), reimplemented as a typage
`Recipient`/`Identity` pair. It must be interoperable with Go `age` and `rage` in both
directions.

Constants:
```
label = "age-encryption.org/v1/ssh-ed25519"
tag   = b64std_nopad( SHA-256(pubWire)[0:4] )
```

Wrap (encrypt the 16-byte age file key to a recipient):
```
tweak     = HKDF(ikm = "", salt = pubWire, info = label, 32)
eSk       = RAND(32)
ePk       = X25519(eSk, basepoint)
shared    = X25519(tweak, X25519(eSk, pkX))
wrapKey   = HKDF(ikm = shared, salt = ePk || pkX, info = label, 32)
body      = ChaCha20-Poly1305(wrapKey, nonce = 0^12, fileKey, ad = "")
stanza    = "-> ssh-ed25519 " tag " " b64std_nopad(ePk) "\n" b64std_nopad(body)
```
Unwrap:
- Skip stanzas whose type is not `ssh-ed25519` or whose `tag` doesn't match.
- Require exactly two arguments, `len(ePk) == 32` and `len(body) == 32`.
- `shared = X25519(tweak, X25519(skX, ePk))`. If `shared` is all zero, fail.
- Derive `wrapKey` as above and open `body`. A failed open means "not for us".

Note: the stanza uses plain ChaCha20-Poly1305 (12-byte zero nonce), not XChaCha. That is
age's choice and must not be changed.

## 5. Vault keys

### 5.1 Key hierarchy
```
VDK[e]       32 random bytes, one per key epoch e = 1, 2, 3, ...
indexKey     HKDF(ikm = VDK[1], salt = "", info = "syncryption/v1/index", 32)
             derived once when the vault is created, then stored in the keyring,
             and kept unchanged across rotations
fileId       HMAC(indexKey, utf8(normPath))                      32 bytes
fileKey[e]   HKDF(ikm = VDK[e], salt = "", info = "syncryption/v1/file" || fileId, 32)
```
- `fileId` is sent to the server as `b64u(fileId)` (43 characters).
- The same `fileKey` is used for every revision of a file. Nonces are random 24-byte
  XChaCha nonces, so nonce reuse is not a concern.
- `indexKey` is stable on purpose: rotating it would change every `fileId` and turn
  rotation into a rename of the whole vault. See section 8 for the trade-off.

```mermaid
flowchart LR
    vdk1["VDK[1]"] -- "HKDF info=syncryption/v1/index<br/>(once, at vault creation)" --> idx["indexKey"]
    path["normPath"] --> hmac(("HMAC"))
    idx --> hmac
    hmac --> fid["fileId"]
    vdke["VDK[e]<br/>(current epoch)"] --> hkdf(("HKDF"))
    fid -- "info=syncryption/v1/file || fileId" --> hkdf
    hkdf --> fk["fileKey[e]"]
```

### 5.2 Path normalisation (`normPath`)
1. Path relative to the vault root, as returned by `app.vault.adapter`.
2. Separator `/`. No leading or trailing `/`. No `.` or `..` segments.
3. Unicode NFC.
4. Case is preserved. Two paths that differ only in case are different files. (On
   case-insensitive file systems the client reports such pairs as conflicts.)

The client must check `HMAC(indexKey, utf8(meta.path)) == fileId` after decrypting any
metadata, so the server can't move metadata between `fileId`s.

## 6. Keyring

### 6.1 Plaintext
The keyring plaintext is UTF-8 JSON:
```json
{
  "v": 1,
  "vaultId": "8f6c0e9e-...",
  "version": 7,
  "name": "Personal",
  "indexKey": "<b64u 32 bytes>",
  "currentEpoch": 2,
  "keys": [
    { "epoch": 1, "vdk": "<b64u 32 bytes>" },
    { "epoch": 2, "vdk": "<b64u 32 bytes>" }
  ],
  "devices": [
    { "id": "d_...", "name": "MacBook", "publicKey": "ssh-ed25519 AAAA...", "added": "2026-10-02T12:00:00Z" }
  ],
  "recovery": "age1...",
  "recoverySigner": "ssh-ed25519 AAAA...",
  "recoverySetBy": "d_...",
  "updatedBy": "d_...",
  "updatedAt": "2026-10-02T12:00:00Z"
}
```
- `version` increases by exactly 1 on every update and matches the server's keyring version.
- `keys` keeps every past epoch so old revisions stay readable.
- `devices` is the **authoritative recipient list**. When a client rewrites the keyring it
  takes recipients from the decrypted `devices` (plus any device being added) and never
  from the server's device list, so the server can't add its own key.
- `recovery` is an optional native age X25519 recipient, `recoverySigner` the Ed25519 key
  derived from the same recovery key, and `recoverySetBy` the device that set it
  (section 9). The three are either all present or all absent.

### 6.2 Encryption
`keyring.age` is a standard age v1 file whose payload is the plaintext above. Its
recipients are an `ssh-ed25519` stanza for every entry in `devices`, plus an X25519 stanza
for `recovery` if it is set. Anyone holding one of those keys can decrypt it with standard
tools. Device keys stay in each device's `SecretStorage`, so in practice that is the recovery
key (section 9):
```
age -d -i recovery.txt keyring.age
```

### 6.3 Signature
age doesn't authenticate the sender, and the server knows every recipient's public key.
So every keyring upload is also signed:
```
signature = sshsig_sign(device key, namespace = "syncryption-keyring@v1",
                        hash = "sha512", message = keyring.age bytes)
```
(sshsig format: section 7.1.) The keyring is accepted only if:
- the signature verifies, and
- the signing key is in the `devices` list of the **previously trusted** keyring, or is
  its `recoverySigner` (section 9). On first use (the device that created the vault, a
  device that attaches through pairing, section 6.5, or one that used the recovery key)
  the signer must be in the keyring's own `devices` or be its own `recoverySigner`, and
  the client trusts it on first use.

The server also verifies the signature and checks that the signer is an active member of
the vault, or the current version's recovery signer for a recovery upload (defence in
depth, not a security boundary).

### 6.4 Rollback and consistency checks
On every keyring fetch the client checks:
- the plaintext `vaultId` equals the requested vault, and `name` equals the vault name the
  client asked for (so the server can't swap one vault for another of the same user)
- the plaintext `version` equals the server's version and is `>=` the version the client
  has pinned locally
- if the version is higher, the signer was in the pinned keyring's `devices`. If the
  client is several versions behind, it walks the history (`GET .../keyring?version=N`)
  and checks each link in turn.
- `currentEpoch` is in `keys`, and no epoch has changed its `vdk`
- if `recovery`, `recoverySigner` or `recoverySetBy` differ from the previous version, the
  new version was signed by a device (not by the recovery signer), and the fields are
  either all absent or `recoverySetBy` is that signing device's `id`. So a recovery key
  can't replace itself, and the device that set it is always known (section 9).

The client then pins `{version, sha256(keyring.age)}`.

Each version must be signed by a device listed in the version before it (or by its
recovery signer), so a client that
pinned version 1 can check every later version link by link:

```mermaid
flowchart LR
    k1["v1 (genesis)<br/>devices: Laptop<br/>signed by Laptop"]
    k2["v2<br/>devices: Laptop, Phone<br/>signed by Laptop"]
    k3["v3<br/>devices: Laptop, Phone, Tablet<br/>signed by Phone"]
    k1 -- "signer in v1.devices" --> k2
    k2 -- "signer in v2.devices" --> k3
    pin["pinned {version, sha256}"] -. "re-fetched and compared<br/>on every connect" .-> k1
```

### 6.5 Adding a device to a vault (pairing)
Every new key of an existing vault pairs: a key belongs to one vault, so a new device, or a
new vault on a known device, always brings a new key.
1. The joining device shows its pairing code: the first 50 bits of `SHA-256(pubWire)`, in
   Crockford base32, grouped `XXXXX-XXXXX`.
2. The server lists the pending key to the vault's active devices.
3. The user compares the codes on both screens and approves on an active member, which
   recomputes the code from the public key itself.
4. The approving device decrypts the keyring, adds the new device to `devices`, increments
   `version`, re-encrypts to all `devices` (+ `recovery`), uploads it signed, and approves
   the key on the server.

The new device trusts the first keyring that is signed by an existing member and contains
its own key. That trust rests on the user having compared pairing codes.

```mermaid
sequenceDiagram
    actor User
    participant New as New device
    participant S as Server
    participant Old as Active device
    New->>S: login and POST /vaults/open (pending key)
    New->>User: shows pairing code of its own key
    Old->>S: list the vault's devices
    S-->>Old: new device's public key
    Old->>User: shows pairing code computed from that key
    User->>Old: codes match, approve
    Old->>Old: decrypt keyring, add device,<br/>version + 1, encrypt to all devices, sign
    Old->>S: PUT keyring (version, signature)
    Old->>S: approve the key
    New->>S: poll, then GET keyring
    New->>New: check signature and signer,<br/>decrypt with own key, pin
```

## 7. Signatures (sshsig)

### 7.1 Format
OpenSSH `PROTOCOL.sshsig`, ed25519 only, hash `sha512`:
```
signedData = "SSHSIG" || string(namespace) || string("") || string("sha512")
             || string(SHA-512(message))
sigBlob    = string("ssh-ed25519") || string(Ed25519_sign(seed32, signedData))
sshsig     = "SSHSIG" || u32be(1) || string(pubWire) || string(namespace)
             || string("") || string("sha512") || string(sigBlob)
armored    = "-----BEGIN SSH SIGNATURE-----\n" base64 wrapped at 70 cols
             "\n-----END SSH SIGNATURE-----\n"
```
Output must verify with `ssh-keygen -Y verify` and with the backend's verifier.

### 7.2 Namespaces
Each use has its own namespace, so a signature from one context can never be replayed in
another:

| Namespace | Signed message | Section |
|---|---|---|
| `syncryption-auth@v1` | login challenge text | protocol.md, Auth |
| `syncryption-keyring@v1` | `keyring.age` bytes, signed by a device or the recovery signer | 6.3, 9 |

Encryption never reuses a signing operation: the age stanza uses the X25519-converted key.

## 8. Files

### 8.1 Encrypted object framing
Metadata and chunks share one framing:
```
header = 0x01 (format version) || u32be(epoch)                   5 bytes
nonce  = RAND(24)
ct     = AEAD(fileKey[epoch], nonce, plaintext, ad = header || domain)
object = header || nonce || ct                                   overhead 45 bytes
```
| Object | `domain` |
|---|---|
| metadata | `utf8("syncryption/v1/meta") || fileId` |
| chunk `i` | `utf8("syncryption/v1/chunk") || fileId || u32be(i)` |

The `epoch` is in clear so the reader knows which `VDK` to use. It is bound by the AD.

### 8.2 Chunks
- The plaintext is split into chunks of exactly 4 MiB (4,194,304 bytes), the last one
  shorter. An empty file has zero chunks.
- Each chunk is encrypted as above and stored as a blob with id `hex(SHA-256(object))`.
  The server checks the hash on upload.
- An unchanged chunk at the same index in the same epoch may be reused by a later
  revision by referencing the same blob id.

### 8.3 Metadata
Plaintext UTF-8 JSON, at most 64 KiB once encrypted:
```json
{
  "v": 1,
  "path": "Notes/Projects/Plan.md",
  "deleted": false,
  "size": 1234,
  "mtime": 1790000000000,
  "ctime": 1790000000000,
  "sha256": "<hex SHA-256 of the full plaintext>",
  "chunks": [ { "id": "<blob id>", "size": 1234 } ],
  "device": "d_..."
}
```
- `mtime` and `ctime` are milliseconds since the epoch, from `adapter.stat`.
- `size` and `chunks[].size` are plaintext sizes.
- A deletion is a revision with `"deleted": true`, an empty `chunks` list and the last
  known `path`.
- After decrypting, the client checks: `path` hashes to `fileId` (5.2), each downloaded
  object hashes to its blob id and decrypts to its listed size, the chunk list matches
  `size`, and after reassembly `sha256` matches.

The ordered `chunks` list inside authenticated metadata fixes chunk order and
completeness. The per-chunk AD stops chunks from being swapped between files or
positions.

Writing a file:

```mermaid
flowchart TD
    file["plaintext file at normPath"] --> split["split into 4 MiB chunks"]
    split --> enc["encrypt chunk i<br/>AEAD(fileKey[e], RAND(24), chunk,<br/>ad = header || chunk domain || i)"]
    enc --> blob["blob id = hex(SHA-256(object))"]
    file --> m["metadata JSON: path, size, times,<br/>sha256, chunk ids"]
    blob --> m
    m --> menc["encrypt metadata<br/>AEAD(fileKey[e], RAND(24), meta,<br/>ad = header || meta domain)"]
    blob -- "upload missing blobs" --> srv[("server")]
    menc -- "commit {fileId, parentRev, meta, blob ids}" --> srv
```

Reading a revision, every check must pass or the revision is skipped:

```mermaid
flowchart TD
    rev["revision: fileId, encrypted meta"] --> open["decrypt meta with fileKey[epoch from header]"]
    open --> c1{"HMAC(indexKey, meta.path)<br/>== fileId?"}
    c1 -- yes --> get["download blobs in meta.chunks order"]
    get --> c2{"each blob id matches,<br/>each chunk decrypts with its index?"}
    c2 -- yes --> c3{"sizes and sha256<br/>of the whole file match?"}
    c3 -- yes --> ok["write to the vault"]
    c1 -- no --> skip["skip with a warning"]
    c2 -- no --> skip
    c3 -- no --> skip
```

### 8.4 Key rotation (device revocation)
1. Revoke the device on the server (protocol.md). Its sessions end immediately.
2. Create epoch `e + 1` with `VDK[e+1] = RAND(32)`, remove the device from `devices`, set
   `currentEpoch = e + 1`, and upload the signed keyring.
3. All new writes from all devices use the new epoch. Other devices learn about the new
   version from `keyringVersion` in the change feed and long-poll (protocol.md 10), and a
   device that meets a revision under an epoch it doesn't know fetches the keyring once
   before it rejects the revision.
4. In the background, a device re-encrypts every live file whose head is an older epoch,
   committing it as a normal new revision (`parentRev` = head). A 409 here just means
   someone else already wrote it, so the device moves on. Files with local changes aren't
   re-encrypted; their next upload uses the new epoch anyway.

If step 2 doesn't happen (the device that revoked went offline), every device removes
keyring devices that are no longer active on the server when it connects, with the same
rotation.

Because `indexKey` doesn't rotate, `fileId`s stay stable and rotation is ordinary commits.
The trade-off: a revoked device that later obtains server data can still test path
guesses against `fileId`s. It can't decrypt anything written under the new epoch.

```mermaid
flowchart LR
    subgraph before["epoch e"]
        a["VDK[e]<br/>known to the revoked device"]
    end
    subgraph after["epoch e + 1"]
        b["VDK[e+1] = RAND(32)<br/>keyring no longer encrypted<br/>to the revoked device"]
    end
    before -- "revoke, rotate" --> after
    old["old revisions"] -.-> a
    new["new writes and re-encrypted files"] -.-> b
```

If the revoked device is the keyring's `recoverySetBy`, step 2 also removes the recovery
key (all three fields), and the plugin asks the user to create a new one: the revoked
device may have kept a copy of it.

The server removes a file's revisions under the old epoch 30 days after the file has one
under the new epoch (protocol.md 9.3), so the old copies don't stay on the server. The
keyring keeps every epoch (6.4): a VDK is 32 bytes, and once the old ciphertext is gone it
opens nothing on the server.

Status: implemented. The epochs and the chain checks are tested with `keyring.json`, and
the revocation flow and background re-encryption against the real backend
(`plugin/tests/revocation.test.ts`).

## 9. Recovery key
- Optional, offered when the vault is created and in settings.
- It is a native age X25519 identity (`AGE-SECRET-KEY-1...`) generated by the plugin and
  shown once for the user to store offline. Only public keys are kept, in the keyring.
- The same 32-byte X25519 secret (the bech32 payload of the identity) also gives an
  Ed25519 signing key:
  ```
  recoverySeed   = HKDF-SHA256(ikm = secret, salt = "", info = "syncryption/v1/recovery-signing", L = 32)
  recoverySigner = Ed25519 public key of recoverySeed, as "ssh-ed25519 AAAA..."
  ```
- Setting, replacing or removing the recovery key is a keyring update by a device, which
  sets `recovery`, `recoverySigner` and `recoverySetBy` (its own `id`) together (6.4).
  Replacing or removing one also starts a new epoch as in 8.4 (without removing a device),
  because the old key can still open the older keyring versions on the server.
- Manual recovery: `age -d -i recovery.txt keyring.age` gives the keyring JSON.
- Recovery in the plugin, when no device is left to approve a new one:
  1. The new device logs in to the vault with a new key, which joins as a pending key.
  2. It fetches the current keyring (`GET /vaults/{id}/recovery`), decrypts it with the
     recovery identity, and checks `vaultId`, `name`, the signer (first-use rule, 6.3),
     and that the derived `recoverySigner` equals the keyring's.
  3. It adds itself to `devices`, increments `version`, sets `updatedBy` to its own `id`,
     re-encrypts to all `devices` and `recovery`, and signs with `recoverySeed`.
  4. `POST /vaults/{id}/recover` stores the version and activates the key. The
     device then pins that version as any other first use.
- The recovery signer can only add versions that keep the recovery fields as they are. A
  device that set the recovery key and is later revoked takes it with it (8.4).

## 10. Test vectors (`testvectors/`)
Every vector is JSON with hex inputs and outputs. Deterministic vectors take the random
values (nonces, ephemeral keys, salts) as inputs.

| File | Covers | Source |
|---|---|---|
| `openssh-keys.json` | unencrypted and `aes256-ctr`/bcrypt keys, wrong passphrase, bad checkint | `ssh-keygen` |
| `ed25519-to-x25519.json` | public and private conversion | libsodium (`pynacl`) |
| `age-ssh-ed25519.json` | deterministic wraps, malformed and foreign stanzas, files encrypted by rage and Go `age` to known keys; plugin output (files and keyrings) checked by `age -d` in CI | reference script, rage (`pyrage`), Go `age` |
| `sshsig.json` | signatures in both namespaces, plus wrong-namespace, wrong-hash, wrong-key-type and tampered cases; plugin signatures checked by `ssh-keygen -Y verify` | `ssh-keygen -Y sign`, reference script |
| `kdf.json` | `indexKey`, `fileId` (including NFC cases), `fileKey`, invalid paths, pairing codes | reference script |
| `objects.json` | meta and chunk objects with fixed nonces, and tampered-header cases | reference script |
| `keyring.json` | a keyring chain (genesis, recovery key set, pairing, rotation, recovery) with the recovery key and its signing key, and rollback, chain-gap, wrong-vault, wrong-signer and inconsistency cases | reference script, rage (`pyrage`) |

The reference script is a small Python program (`testvectors/generate.py`) using
`cryptography`, `bcrypt`, `pynacl` and `pyrage`, independent of the plugin code. The Go `age`
files need the `age` binary, from `$AGE` or `PATH`.
