# Vault Syncryption

**Your vault, on every device, readable only by you.**

Vault Syncryption is self-hosted, end-to-end encrypted sync for Obsidian. You run the server, your devices hold the keys, and the server stores only ciphertext. There's no subscription, no third-party cloud and no telemetry, and it works on desktop, iPhone, iPad and Android.

## Why Vault Syncryption
- **Your whole setup, everywhere.** Notes, attachments, settings, themes and plugins all sync. Connect a new device and your whole Obsidian setup arrives with it.
- **A server that can't read your notes.** Everything is encrypted on your devices before upload, including file names and folder paths, so the server stores only ciphertext. Each device has its own Ed25519 encryption key for each vault. It is used both to log in and to unlock the vault, and it never leaves the device.
- **You decide who gets in.** A new device joins only when a device that already syncs the vault approves it. Every key is listed by fingerprint, and any device can remove a lost or old one. A recovery key gets you back in even if you lose every device.
- **Conflicts that resolve themselves.** Edits to different parts of the same note from two devices are merged automatically. When the same lines change on both, both versions are kept, so nothing is overwritten silently.
- **Time travel for every file.** The server keeps your file history: every version for 30 days and at least the last 10, and a deleted file's versions for 90 days. Restore any of them from "Show file history".
- **Offline-first and fast.** Each device keeps a full local copy and syncs as soon as it's back online. Live updates bring changes from your other devices within moments.
- **You're in control.** A status window shows what's synced, what's waiting to upload and what's being edited on another device. On a slow or metered connection, pause sync with one click: changes keep queuing and upload when you resume.
- **Share a vault, not a password.** Share a vault by sharing its username and vault name. The other person generates their own key and joins once an existing device approves them.

## A server you'll actually enjoy running
- **One container**, configured with a few environment variables in [`backend/docker/docker-compose.yml`](backend/docker/docker-compose.yml).
- **HTTPS out of the box** with built-in Let's Encrypt, or plain HTTP behind your own reverse proxy.
- **Storage your way:** local disk by default (the `./data` folder, nothing to configure), or S3 and S3-compatible storage for effectively unlimited space.
- **An admin page** to manage users and vaults, plus a maintenance mode for upgrades.

See [docs/self-hosting.md](docs/self-hosting.md) to get it running.

## Requirements
- A Vault Syncryption server that you run yourself. The plugin does nothing without one.
- Obsidian 1.13 or later. The plugin keeps your encryption key in Obsidian's secret storage.

## Install the plugin
- **Community plugins:** search for "Vault Syncryption" in Settings → Community plugins (once the listing is approved).
- **Until then, with [BRAT](https://github.com/TfTHacker/obsidian42-brat):** add the beta plugin `ibehren1/obsidian-vault-syncryption`. This works on desktop and mobile.
- **By hand:** download `main.js`, `manifest.json` and `styles.css` from the [latest release](https://github.com/ibehren1/obsidian-vault-syncryption/releases/latest) into `<vault>/.obsidian/plugins/vault-syncryption/`.

## Get started
1. Open the plugin settings and enter the server URL, your username and the vault name.
2. Check the device name (it starts as your computer's hostname), then generate an encryption key.
3. Connect. Creating a new vault asks for the server's shared secret, which the server admin provides. A device joining an existing vault doesn't need it: a device that already syncs the vault approves it instead.
4. Create a recovery key when the plugin offers it. It is the only way back in if you lose every device.

The shared secret keeps strangers from creating accounts on your server. It doesn't protect your data (your encryption keys do), so an organization can treat it as an internal configuration value. Opening the server URL in a browser shows how to connect and how to contact the admin.

## Network use and privacy
- The plugin connects **only to the server URL you enter**. There is no telemetry, no analytics, and no other network traffic.
- File contents, file paths and the vault key are encrypted on your device before upload. The server sees ciphertext plus some metadata: usernames, vault and device names, file counts, sizes and timestamps (the full list is in [docs/crypto.md](docs/crypto.md), section 1).
- Your private encryption key stays in Obsidian's secret storage on each device. It is never written to the plugin's `data.json` or sent to the server.
- An account on the server is needed. It is created when you create your first vault, with the shared secret from the server's administrator.

## How it reads your vault
The plugin syncs the whole vault in place, including the config folder (`.obsidian`, or whichever folder you set): settings, themes and other plugins. The Vault API doesn't cover the config folder, so the plugin uses `app.vault.adapter` for those files. Its own folder and `workspace*.json` are never synced, and each device can exclude more paths in the settings.

## Documentation
- [docs/self-hosting.md](docs/self-hosting.md): running the server
- [docs/scaling.md](docs/scaling.md): storage growth and capacity
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
