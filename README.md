# Vault Syncryption

Self-hosted, end-to-end encrypted sync for Obsidian.

- **Full vault sync:** notes, attachments, settings, themes and plugins. Attaching a new device brings over your whole setup.
- **Zero-knowledge server:** everything is encrypted on your devices with your SSH (Ed25519) key, so the server stores only ciphertext.
- **Offline-first:** each device keeps a full local copy and syncs when it's back online.
- **Shared vaults:** share a vault with someone by sharing its username, vault name and SSH key.
- **One container:**
  - Configured with a few environment variables in [`backend/docker/docker-compose.yml`](backend/docker/docker-compose.yml).
  - Built-in Let's Encrypt, or plain HTTP behind your own proxy.
  - Storage is local disk or S3.

> **Status:** early release (0.1). Desktop is the main target. **Mobile (iOS and Android) is in beta:** it is enabled but still being tested, so keep a backup of your vault.

## Requirements
- A Vault Syncryption server that you run yourself. See [docs/self-hosting.md](docs/self-hosting.md). The plugin does nothing without one.
- Obsidian 1.13 or later. The plugin keeps your SSH key in Obsidian's secret storage.

## Install the plugin
- **Community plugins:** search for "Vault Syncryption" in Settings → Community plugins (once the listing is approved).
- **Until then, with [BRAT](https://github.com/TfTHacker/obsidian42-brat):** add the beta plugin `ibehren1/obsidian-vault-syncryption`. This works on desktop and mobile.
- **By hand:** download `main.js`, `manifest.json` and `styles.css` from the [latest release](https://github.com/ibehren1/obsidian-vault-syncryption/releases/latest) into `<vault>/.obsidian/plugins/vault-syncryption/`.

Then open the plugin settings. Enter the server URL, your username and the vault name, and generate or import an SSH key. The first time a key joins the server, you'll be asked for the server's shared secret.

## Network use and privacy
- The plugin connects **only to the server URL you enter**. There is no telemetry, no analytics, and no other network traffic.
- File contents, file paths and the vault key are encrypted on your device before upload. The server sees ciphertext plus some metadata: usernames, vault and device names, file counts, sizes and timestamps (the full list is in [docs/crypto.md](docs/crypto.md), section 1).
- Your private SSH key stays in Obsidian's secret storage on each device. It is never written to the plugin's `data.json` or sent to the server.
- An account on the server is needed. It is created the first time you connect, with the shared secret from the server's administrator.

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
