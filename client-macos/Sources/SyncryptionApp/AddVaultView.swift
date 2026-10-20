import AppKit
import SwiftUI
import SyncryptionAppCore

/// Link this Mac to a vault: the server, the username and vault name, and this Mac's device
/// name. A new encryption key is created for it, then the window walks through the shared
/// secret (a new vault) or the pairing code (an existing one), and then the folders.
struct AddVaultView: View {
    let model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var endpoint = ""
    @State private var username = ""
    @State private var vaultName = ""
    @State private var deviceName = defaultDeviceName()
    @State private var error: String?
    @State private var addedId: UUID?

    var body: some View {
        Group {
            if let id = addedId, let vault = model.vaults.first(where: { $0.id == id }) {
                ConnectProgress(vault: vault) { dismiss(); reset() }
            } else {
                form
            }
        }
        .padding(20)
        .frame(width: 520)
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Logo(size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Add a Vault").font(.title2.weight(.semibold))
                    Text("Connect this Mac to a vault on your Vault Syncryption server.").font(.callout).foregroundStyle(.secondary)
                }
            }
            Form {
                TextField("Server", text: $endpoint, prompt: Text(verbatim: "https://sync.example.com"))
                TextField("Username", text: $username)
                TextField("Vault name", text: $vaultName)
                TextField("Device name", text: $deviceName)
            }
            Text("Connect creates a new encryption key for this vault and keeps it in this Mac's Keychain. If the vault doesn't exist yet, you'll be asked for the server's shared secret to create it; if it does, another device of the vault approves this Mac. Then choose which folders to sync.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let error { Text(error).foregroundStyle(.red).font(.callout).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Connect") { connect() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(endpoint.isEmpty || username.isEmpty || vaultName.isEmpty || deviceName.isEmpty)
            }
        }
    }

    private func connect() {
        do {
            let c = try model.addVault(endpoint: endpoint, username: username, vaultName: vaultName, deviceName: deviceName)
            addedId = c.id
            error = nil
        } catch {
            self.error = "\(error)"
        }
    }

    private func reset() {
        addedId = nil
        vaultName = ""
    }
}

/// What happens after Connect: the key, the shared secret or the pairing code, then the
/// vault's folders to map or add.
struct ConnectProgress: View {
    let vault: VaultController
    let done: () -> Void

    private var connected: Bool {
        switch vault.status {
        case .synced, .syncing: vault.session != nil
        default: false
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Logo(size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(connected ? "Connected to \(vault.config.vaultName)" : vault.config.vaultName).font(.title2.weight(.semibold))
                    Text(host(vault.config.endpoint)).font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                StatePill(text: vault.statusName, kind: vault.statusKind)
            }
            if connected {
                folders
            } else {
                GroupBox("Encryption key") {
                    KeySummary(vault: vault).frame(maxWidth: .infinity, alignment: .leading)
                }
                Label(vault.statusText, systemImage: vault.statusSymbol).fixedSize(horizontal: false, vertical: true)
                StatusActions(vault: vault, open: { _ in })
            }
            HStack {
                if connected { Button("Add Folder…") { FolderActions.add(vault) } }
                Spacer()
                if connected { Button("Done") { done() }.keyboardShortcut(.defaultAction) } else { Button("Close") { done() } }
            }
            if case .pairing = vault.status {
                Text("You can close this window: the vault connects once it is approved, and its folders are in Settings → Folders.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .task(id: vault.lastSync) { await vault.refreshFolders() }
    }

    private var folders: some View {
        VStack(alignment: .leading, spacing: 8) {
            let list = vault.vaultFolders
            Text(list.isEmpty ? "This vault has no folders yet. Add a folder on this Mac to start."
                : "This vault has \(plural(list.count, "folder")). Choose which to sync on this Mac, or add a new one. You can change this any time in Settings → Folders.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if !list.isEmpty {
                VStack(spacing: 0) {
                    ForEach(list) { f in
                        HStack(spacing: 8) {
                            Image(systemName: f.mapping == nil ? "folder" : "folder.fill").foregroundStyle(Color.accentColor.opacity(0.85))
                            Text(f.name).font(.body.weight(.medium))
                            Spacer()
                            if let m = f.mapping {
                                Text((m.path as NSString).abbreviatingWithTildeInPath).font(.caption.monospaced()).foregroundStyle(.secondary)
                                    .lineLimit(1).truncationMode(.middle)
                            } else {
                                Text(where_(f)).font(.caption).foregroundStyle(.secondary)
                                Button("Map…") { FolderActions.map(vault, f.name) }.controlSize(.small)
                            }
                        }
                        .padding(.vertical, 6).padding(.horizontal, 10)
                        Divider()
                    }
                }
                .background(CardBackground())
            }
        }
    }

    private func where_(_ f: VaultController.VaultFolder) -> String {
        let names = vault.otherDevices.filter { f.elsewhere[$0.id] != nil }.map(\.name)
        return names.isEmpty ? "on no device" : "on " + names.joined(separator: ", ")
    }
}

/// This vault's key on this Mac: fingerprint, pairing code and the public key.
struct KeySummary: View {
    let vault: VaultController

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let k = vault.keyInfo {
                LabeledContent("Fingerprint") { Text(k.fingerprint).font(.caption.monospaced()).textSelection(.enabled) }
                LabeledContent("Pairing code") { Text(k.pairingCode).font(.body.monospaced()).textSelection(.enabled) }
                HStack {
                    Text("Ed25519, in this Mac's Keychain").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Copy Public Key") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(vault.config.publicKey, forType: .string)
                    }.font(.caption)
                }
            } else {
                Text("No key yet.").foregroundStyle(.secondary)
            }
        }
    }
}
