# Mobile QA (iOS and Android)

The plugin is built for mobile (no Node APIs, `requestUrl`, WebCrypto and `@noble/*`,
SecretStorage). This page lists what a code review found, what was fixed, what is still
open, and the manual checks to run on a real iPhone and Android phone.

## Fixed after the review
- A request that never answers (the app suspended mid-request) is abandoned after 60 s,
  so it can't stall later syncs and the long-poll.
- Coming back to the foreground or getting the network back ends the long-poll backoff
  and syncs. If connecting failed because there was no network (started offline, or the
  screen locked while pairing), the plugin connects again by itself.
- A remote change that can't be written here (for example a name that differs only in
  case from another file on a case-insensitive file system) no longer stops every sync.
  It is kept, warned about once, and tried again on every sync.
- "Show sync status" command, since the status bar isn't shown on mobile.
- Copy buttons handle a refused clipboard; the recovery key text can be selected on iOS.
- Encryption key, secret and recovery key fields turn off autocapitalize, autocorrect and spellcheck.

## Known limitations
- **Large files:** a file is read, hashed, encrypted and decrypted whole, on the main
  thread. Peak memory is about 2× the file size when uploading and about 4× when
  downloading, so files of a few hundred MB may get the app killed on a phone. Streaming
  one chunk at a time, or a per-device size limit, is a later change.
- **Unicode normalization:** `fileId` uses the NFC form of a path, but files are written
  under the name as sent. A file named in NFD on one device and NFC on another (rare:
  macOS keeps both) can show up twice on Android.
- **Device names:** every phone joins as "iOS" or "Android", which makes approvals,
  conflict copies and "is editing" notices ambiguous with several phones.
- **Scans:** every sync scans the vault and the config folders (one `stat` per config
  file), which costs battery on large vaults.
- **Encryption keys with a passphrase** ask for the passphrase on every cold start, and iOS restarts apps
  often. A key without a passphrase (kept in SecretStorage) avoids this.

## Check on a device
- Whether `vault.on("raw")` fires for `.obsidian` changes on mobile. If it doesn't,
  config edits sync on the 2-minute timer instead.
- Whether `requestUrl` fails or hangs after a suspend, and whether `visibilitychange`
  fires when the app is backgrounded and resumed.
- Whether the lock release finishes before the app is suspended.
- IndexedDB on the oldest supported iOS, and whether iOS evicts it (a full rehash on the
  next start; it shouldn't create conflict copies).
- Whether `app:reload` exists on mobile, and how `trashFile` behaves.
- Vaults stored in iCloud Drive (placeholder files, iCloud syncing at the same time).

## Manual checklist
Run on an iPhone and an Android phone, with a desktop as the other device.

1. **Setup:** fresh install, fill in the settings, generate an encryption key, copy the
   public key.
2. **Join:** the shared-secret prompt appears once; check the secret isn't stored in
   `data.json`.
3. **Pairing:** start pairing, lock the screen for a minute, approve on the desktop,
   unlock. It should finish or reconnect by itself.
4. **First sync** of a vault with 5,000+ files: time it, and check the UI stays usable.
5. **Attachments:** 50, 200 and 500 MB files in both directions. Note any crash.
6. **Config folder:** change a theme or plugin setting on each side; check the reload
   prompt. `workspace-mobile.json` must stay local.
7. **Live updates:** edit on the desktop with the phone in the foreground; the change
   should arrive within a few seconds.
8. **Background and resume:** background the app for 1 and 10 minutes, edit on the
   desktop, resume. The change should arrive within seconds, and the status shouldn't
   stay on "syncing".
9. **Locks:** open the same note on both devices; check the notice, and that the lock is
   released when the phone app goes to the background.
10. **Conflicts:** edit offline on both devices, then reconnect; check the merge or the
    conflict copy. Rename a file changing only its case.
11. **History:** preview, restore a revision, restore a deleted file.
12. **Recovery key:** create one, test Copy and selecting the text, then recover a new
    device with it.
13. **Remove a device:** check the rotation, and that re-encryption finishes across app
    restarts.
14. **Offline:** start in airplane mode, then turn the network on: it should connect
    without "Connect again" and push queued edits. Also cut the network during an upload.
