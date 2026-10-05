# Security Policy

Vault Syncryption is end-to-end encrypted sync, so security bugs matter more than most. Thank
you for reporting them responsibly.

## Reporting a vulnerability
- Please **don't** open a public issue or pull request for a vulnerability.
- Email **isaac@behrenshome.com** with a description, the affected version or commit, and
  steps to reproduce if you have them.
- You should get a reply within 7 days. Once a fix is available, we'll credit you in the
  release notes unless you'd rather stay anonymous.

## Scope
In scope:
- anything that lets the server, its storage or a network attacker read or undetectably
  change vault contents, paths or keys (see the threat model in
  [docs/crypto.md](docs/crypto.md), section 1)
- authentication bypasses, session or challenge replay, and access to another user's or
  vault's data
- ways to join a server without `SHARED_SECRET`
- the plugin leaking keys, tokens or plaintext into logs, `data.json` or the synced vault

Out of scope:
- the metadata the design accepts as visible to the server (crypto.md section 1)
- attacks that need a malicious Obsidian plugin installed alongside Vault Syncryption
- denial of service by the server operator

## Supported versions
Vault Syncryption is in early development. Only the latest commit on `main` is supported.
