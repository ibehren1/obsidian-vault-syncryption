# Vault Syncryption

Self-hosted, end-to-end encrypted sync for Obsidian.

- **Full vault sync:** notes, attachments, settings, themes and plugins. Attaching a new device brings over your whole setup.
- **Zero-knowledge server:** everything is encrypted on your devices, so the server stores only ciphertext. Each device has its own encryption key for each vault (a standard Ed25519 key pair), used both to log in and to decrypt the vault key. Any device of a vault can see every key by fingerprint and remove one. Ed25519 is a very well documented and widely implemented form of public key cryptography. The server is reached over HTTPS only.
- **Offline-first:** each device keeps a full local copy and syncs when it's back online.
- **Shared vaults:** share a vault with someone by sharing its username and vault name. When they connect, they generate a new encryption key and pair it with the vault. An existing user must approve the connection.
- **One Container Backend Self-hosted Server:**
  - Configured with a few environment variables in [`backend/docker/docker-compose.yml`](backend/docker/docker-compose.yml).
  - Built-in Let's Encrypt, or plain HTTP behind your own proxy.
  - Storage is local disk (the `./data` folder, no configuration needed) by default, or optionally S3 for effectively unlimited storage.
  - An admin page to manage users and vaults, and a maintenance mode.

> **Status:** early release (0.1). Desktop is the main target. **Mobile (iOS and Android) is in beta:** it is enabled but still being tested, so keep a backup of your vault.

## Requirements
- A Vault Syncryption server that you run yourself. See [docs/self-hosting.md](docs/self-hosting.md). The plugin does nothing without one.
- Obsidian 1.13 or later. The plugin keeps your encryption key in Obsidian's secret storage.

## Install the plugin
- **Community plugins:** search for "Vault Syncryption" in Settings → Community plugins (once the listing is approved).
- **Until then, with [BRAT](https://github.com/TfTHacker/obsidian42-brat):** add the beta plugin `ibehren1/obsidian-vault-syncryption`. This works on desktop and mobile.
- **By hand:** download `main.js`, `manifest.json` and `styles.css` from the [latest release](https://github.com/ibehren1/obsidian-vault-syncryption/releases/latest) into `<vault>/.obsidian/plugins/vault-syncryption/`.

Then open the plugin settings. Enter the server URL, your username and the vault name, check the device name (it starts as your computer's hostname), and generate an encryption key. Each device has its own key for each vault; a device that already syncs the vault approves new ones. Create a recovery key when the plugin offers it: it is the only way back in if you lose every device. Creating a vault asks for the server's shared secret; a new device joining an existing vault doesn't need it, since a device that already syncs the vault approves it. The server admin must supply the shared secret. It keeps random individuals from joining the server; for an organization, it can be treated as an internal configuration value rather than a secret, as it is not used to secure the data. Opening the server URL in a browser shows how to connect and how to contact the admin.

## Network use and privacy
- The plugin connects **only to the server URL you enter**. There is no telemetry, no analytics, and no other network traffic.
- File contents, file paths and the vault key are encrypted on your device before upload. The server sees ciphertext plus some metadata: usernames, vault and device names, file counts, sizes and timestamps (the full list is in [docs/crypto.md](docs/crypto.md), section 1).
- Your private encryption key stays in Obsidian's secret storage on each device. It is never written to the plugin's `data.json` or sent to the server.
- An account on the server is needed. It is created when you create your first vault, with the shared secret from the server's administrator.

## How it reads your vault
The plugin syncs the whole vault in place, including the config folder (`.obsidian`, or whichever folder you set): settings, themes and other plugins. The Vault API doesn't cover the config folder, so the plugin uses `app.vault.adapter` for those files. Its own folder and `workspace*.json` are never synced, and each device can exclude more paths in the settings.

## Documentation
- [docs/self-hosting.md](docs/self-hosting.md): running the server
- [docs/architecture.md](docs/architecture.md), [docs/protocol.md](docs/protocol.md) and [docs/crypto.md](docs/crypto.md): how it works
- [docs/PLAN.md](docs/PLAN.md): the design
- [SECURITY.md](SECURITY.md): reporting a vulnerability

## Repository
| Path | Contents |
|---|---|
| `plugin/` | Obsidian plugin (TypeScript) |
| `backend/` | Sync server (Python, uv, FastAPI) and container |
| `docs/` | Design and specifications |

## License
[MIT](LICENSE)
