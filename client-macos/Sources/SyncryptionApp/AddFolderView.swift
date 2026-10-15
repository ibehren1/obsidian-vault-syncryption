import AppKit
import SwiftUI
import SyncryptionAppCore

/// Link a folder to a vault: the folder, the server, the username and vault name, and this
/// Mac's device name. A new encryption key is created for it, then the window walks through
/// the shared secret (a new vault) or the pairing code (an existing one).
struct AddFolderView: View {
    let model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var path = ""
    @State private var endpoint = ""
    @State private var username = ""
    @State private var vaultName = ""
    @State private var deviceName = defaultDeviceName()
    @State private var error: String?
    @State private var addedId: UUID?

    var body: some View {
        Group {
            if let id = addedId, let folder = model.folders.first(where: { $0.id == id }) {
                ConnectProgress(folder: folder) { dismiss(); reset() }
            } else {
                form
            }
        }
        .padding(20)
        .frame(width: 480)
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Logo(size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Add a Folder").font(.title2.weight(.semibold))
                    Text("Sync a folder with a vault on your Vault Syncryption server.").font(.callout).foregroundStyle(.secondary)
                }
            }
            Form {
                LabeledContent("Folder") {
                    HStack {
                        Text(path.isEmpty ? "None chosen" : path).foregroundStyle(path.isEmpty ? .secondary : .primary)
                            .lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button("Choose…") { choose() }
                    }
                }
                TextField("Server", text: $endpoint, prompt: Text(verbatim: "https://sync.example.com"))
                TextField("Username", text: $username)
                TextField("Vault name", text: $vaultName)
                TextField("Device name", text: $deviceName)
            }
            Text("Connect creates a new encryption key for this folder and keeps it in this Mac's Keychain. If the vault doesn't exist yet, you'll be asked for the server's shared secret to create it; if it does, another device of the vault approves this Mac. Files already in the folder are merged with the vault.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let error { Text(error).foregroundStyle(.red).font(.callout).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Connect") { connect() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(path.isEmpty || endpoint.isEmpty || username.isEmpty || vaultName.isEmpty || deviceName.isEmpty)
            }
        }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Choose"
        if panel.runModal() == .OK, let url = panel.url { path = url.path }
    }

    private func connect() {
        do {
            let c = try model.addFolder(path: path, endpoint: endpoint, username: username, vaultName: vaultName, deviceName: deviceName)
            addedId = c.id
            error = nil
        } catch {
            self.error = "\(error)"
        }
    }

    private func reset() {
        addedId = nil
        path = ""
        vaultName = ""
    }
}

/// What happens after Connect: the key, the shared secret or the pairing code, then the first sync.
struct ConnectProgress: View {
    let folder: FolderController
    let done: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Logo(size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(folder.config.title).font(.title2.weight(.semibold))
                    Text("\(folder.config.vaultName) · \(host(folder.config.endpoint))").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                StatePill(text: folder.statusName, kind: folder.statusKind)
            }
            GroupBox("Encryption key") {
                KeySummary(folder: folder).frame(maxWidth: .infinity, alignment: .leading)
            }
            Label(folder.statusText, systemImage: folder.statusSymbol).fixedSize(horizontal: false, vertical: true)
            StatusActions(folder: folder, open: { _ in })
            HStack {
                Spacer()
                switch folder.status {
                case .synced, .syncing: Button("Done") { done() }.keyboardShortcut(.defaultAction)
                default: Button("Close") { done() }
                }
            }
            if case .pairing = folder.status {
                Text("You can close this window: the folder starts syncing once it is approved.").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

/// This folder's key: fingerprint, pairing code and the public key.
struct KeySummary: View {
    let folder: FolderController

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let k = folder.keyInfo {
                LabeledContent("Fingerprint") { Text(k.fingerprint).font(.caption.monospaced()).textSelection(.enabled) }
                LabeledContent("Pairing code") { Text(k.pairingCode).font(.body.monospaced()).textSelection(.enabled) }
                HStack {
                    Text("Ed25519, in this Mac's Keychain").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Copy Public Key") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(folder.config.publicKey, forType: .string)
                    }.font(.caption)
                }
            } else {
                Text("No key yet.").foregroundStyle(.secondary)
            }
        }
    }
}
