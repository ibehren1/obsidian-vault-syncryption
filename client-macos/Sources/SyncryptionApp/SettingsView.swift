import AppKit
import SwiftUI
import SyncryptionAppCore
import SyncryptionCrypto
import SyncryptionSync

enum SettingsTab: Hashable {
    case general, key, devices, recovery, history
}

/// Which folder and tab the Settings window shows, so the menu can open it at a place.
@MainActor @Observable
final class SettingsSelection {
    static let shared = SettingsSelection()
    var folder: UUID?
    var tab: SettingsTab = .general

    func select(_ folder: UUID, tab: SettingsTab) {
        self.folder = folder
        self.tab = tab
    }
}

struct SettingsView: View {
    let model: AppModel
    @State private var selection = SettingsSelection.shared

    var body: some View {
        NavigationSplitView {
            List(model.folders, selection: $selection.folder) { f in
                HStack(spacing: 8) {
                    Image(systemName: "folder.fill").foregroundStyle(Color.accentColor.opacity(0.85))
                    VStack(alignment: .leading, spacing: 1) {
                        Text(f.config.title)
                        Text(f.config.vaultName).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    StatusDot(kind: f.statusKind, size: 7)
                }
                .padding(.vertical, 2)
                .tag(f.id)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 210)
        } detail: {
            if let f = model.folders.first(where: { $0.id == selection.folder }) ?? model.folders.first {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Logo(size: 36)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(f.config.title).font(.title3.weight(.semibold))
                            Text("\(f.config.vaultName) · \(host(f.config.endpoint))").font(.callout).foregroundStyle(.secondary)
                        }
                        StatePill(text: f.statusName, kind: f.statusKind)
                        Spacer()
                    }
                    .padding(.horizontal, 20).padding(.top, 16).padding(.bottom, 12)
                    Picker("", selection: $selection.tab) {
                        Text("General").tag(SettingsTab.general)
                        Text("Encryption Key").tag(SettingsTab.key)
                        Text("Devices").tag(SettingsTab.devices)
                        Text("Recovery Key").tag(SettingsTab.recovery)
                        Text("History").tag(SettingsTab.history)
                    }
                    .pickerStyle(.segmented).labelsHidden().padding(.horizontal, 20).padding(.bottom, 8)
                    Divider()
                    Group {
                        switch selection.tab {
                        case .general: GeneralTab(folder: f, model: model)
                        case .key: KeyTab(folder: f)
                        case .devices: DevicesTab(folder: f).padding(20)
                        case .recovery: RecoveryTab(folder: f)
                        case .history: HistoryTab(folder: f).padding(20)
                        }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
                }
                .id(f.id)
            } else {
                VStack(spacing: 12) {
                    Logo(size: 56)
                    Text("No folders yet. Add one from the menu bar.").foregroundStyle(.secondary)
                }
            }
        }
        .frame(minWidth: 800, minHeight: 560)
    }
}

/// An error line that a view sets from a failed action.
struct ErrorText: View {
    let text: String?
    var body: some View {
        if let text { Text(text).foregroundStyle(.red).font(.callout).fixedSize(horizontal: false, vertical: true).textSelection(.enabled) }
    }
}

struct GeneralTab: View {
    let folder: FolderController
    let model: AppModel
    @State private var exclude = ""
    @State private var confirmRemove = false
    @State private var finderExtensionOn = true

    var body: some View {
        Form {
            Section("Status") {
                Label(folder.statusText, systemImage: folder.statusSymbol).fixedSize(horizontal: false, vertical: true)
                StatusActions(folder: folder, open: { SettingsSelection.shared.tab = $0 })
                if let r = folder.lastReport, folder.lastSync != nil {
                    Text("Last sync: \(r.pushed) sent, \(r.pulled) received, \(r.merged) merged, \(r.conflicts.count) conflict copies")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Section("Connection") {
                LabeledContent("Folder") {
                    HStack {
                        Text(folder.config.path).textSelection(.enabled)
                        Button("Show") { NSWorkspace.shared.activateFileViewerSelecting([folder.config.url]) }
                    }
                }
                LabeledContent("Server", value: folder.config.endpoint)
                LabeledContent("Username", value: folder.config.username)
                LabeledContent("Vault", value: folder.config.vaultName)
                LabeledContent("Device name", value: folder.config.deviceName)
            }
            Section {
                TextEditor(text: $exclude).font(.body.monospaced()).frame(minHeight: 80)
                HStack {
                    Spacer()
                    Button("Save") { folder.updateExclude(exclude) }.disabled(exclude == folder.config.exclude)
                }
            } header: {
                Text("Exclude list")
            } footer: {
                Text("One pattern per line, relative to the folder. `*` and `?` match within a name, `**` across folders; a pattern also excludes everything inside it. Lines starting with # are comments. Excluded files stay where they are, here and on other devices.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !folder.warnings.isEmpty {
                Section("Recent problems") {
                    ForEach(Array(folder.warnings.suffix(10).enumerated()), id: \.offset) { Text($0.element).font(.caption) }
                }
            }
            Section {
                Toggle("Show the Vault Syncryption icon on the folder in Finder",
                       isOn: Binding(get: { folder.config.showsFolderIcon }, set: { folder.setShowsFolderIcon($0) }))
                if folder.config.showsFolderIcon && !finderExtensionOn {
                    HStack {
                        Text("Finder's sidebar shows the icon only with the Vault Syncryption Finder extension on.")
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button("Finder Extensions…") { FinderExtension.showSettings() }
                    }
                }
                Toggle("Paused", isOn: Binding(get: { folder.config.paused }, set: { folder.setPaused($0) }))
                Button("Remove Folder…", role: .destructive) { confirmRemove = true }
            }
        }
        .formStyle(.grouped)
        .onAppear {
            exclude = folder.config.exclude
            finderExtensionOn = FinderExtension.isEnabled
        }
        // Back from System Settings.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            finderExtensionOn = FinderExtension.isEnabled
        }
        .confirmationDialog("Stop syncing \(folder.config.title)?", isPresented: $confirmRemove) {
            Button("Remove Folder", role: .destructive) { Task { await model.removeFolder(folder) } }
        } message: {
            Text("This Mac's key is removed from the vault and from the Keychain. The files stay in the folder, and the vault keeps them on the server.")
        }
    }
}

struct KeyTab: View {
    let folder: FolderController
    @State private var confirmReplace = false
    @State private var busy = false
    @State private var error: String?
    @State private var done: String?

    var body: some View {
        Form {
            Section("This Mac's encryption key for \(folder.config.vaultName)") {
                KeySummary(folder: folder)
                Text(folder.config.publicKey).font(.caption.monospaced()).textSelection(.enabled).foregroundStyle(.secondary)
            }
            Section {
                Button("Replace Key…") { confirmReplace = true }.disabled(folder.session == nil || busy)
                if busy { ProgressView().controlSize(.small) }
                if let done { Text(done).font(.callout) }
                ErrorText(text: error)
            } footer: {
                Text("Replacing creates a new key: this key approves it, the new key takes over and removes this one, and the vault key is rotated, so the old key can't open anything new. Every device re-encrypts its files in the background.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .confirmationDialog("Replace this Mac's key?", isPresented: $confirmReplace) {
            Button("Replace Key") { replace() }
        }
    }

    private func replace() {
        busy = true
        Task {
            do {
                try await folder.replaceKey()
                done = "The new key is in use."
                error = nil
            } catch {
                self.error = "\(error)"
            }
            busy = false
        }
    }
}

/// A key the server reports removed that this Mac didn't remove: the user removes or keeps it.
struct StaleKeyRow: View {
    let key: FolderController.StaleKey
    let remove: () -> Void
    let keep: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "person.badge.minus").font(.title3).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("The server reports \(key.name)'s key removed").font(.body.weight(.medium))
                Text("This Mac didn't remove it. If you removed it on another device, remove it here too, so the vault gets a new key. If you didn't, keep it: the server alone can't decide who is in the vault.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button("Keep", action: keep)
            Button("Remove", role: .destructive, action: remove)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.orange.opacity(0.08)))
    }
}

struct DevicesTab: View {
    let folder: FolderController
    @State private var keys: [FolderController.VaultKey] = []
    @State private var error: String?
    @State private var info: String?
    @State private var loading = false
    @State private var approving: FolderController.PendingDevice?
    @State private var removing: FolderController.VaultKey?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                if folder.session == nil {
                    Text("Connect the folder to manage the keys of its vault.").foregroundStyle(.secondary)
                }
                ForEach(folder.pendingApprovals) { p in
                    HStack(spacing: 12) {
                        Image(systemName: "person.badge.plus").font(.title3).foregroundStyle(.orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(p.name) is waiting for approval").font(.body.weight(.medium))
                            Text("Pairing code \(p.code)").font(.callout.monospaced()).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Approve…") { approving = p }.buttonStyle(.borderedProminent)
                    }
                    .padding(12)
                    .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.orange.opacity(0.08)))
                }
                ForEach(folder.unconfirmedRemovals) { s in
                    StaleKeyRow(key: s, remove: { act { try await folder.confirmRemoval([s.id]) } },
                                keep: { act { try await folder.keepKeys([s.id]) } })
                }
                Card(title: "Keys of \(folder.config.vaultName)", count: keys.isEmpty ? nil : plural(keys.count, "key")) {
                    HStack(spacing: 8) {
                        if loading { ProgressView().controlSize(.small) }
                        Button { Task { await load() } } label: { Image(systemName: "arrow.clockwise") }.help("Refresh")
                    }
                } content: {
                    Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 0) {
                        GridRow {
                            ForEach(["Device", "Status", "Fingerprint", "Pairing code", "Last seen", ""], id: \.self) {
                                Text($0).font(.caption.weight(.medium)).foregroundStyle(.secondary)
                            }
                        }
                        .padding(.bottom, 6)
                        Divider().gridCellUnsizedAxes(.horizontal)
                        ForEach(keys) { k in
                            GridRow(alignment: .center) {
                                HStack(spacing: 6) {
                                    Text(k.name).lineLimit(1)
                                    if k.isThisMac { Tag(text: "This Mac", color: .accentColor) }
                                    if k.remoteOnly { Tag(text: "Remote-only", color: .purple) }
                                }
                                HStack(spacing: 6) {
                                    StatusDot(kind: k.serverKind, size: 7)
                                    Text(k.serverLabel)
                                }
                                Fingerprint(value: k.fingerprint)
                                Text(k.pairingCode).font(.callout.monospaced()).foregroundStyle(.secondary)
                                Text(k.isThisMac ? "Now" : isoDate(k.lastSeenAt).map { relative($0, capitalized: true) } ?? "—").foregroundStyle(.secondary)
                                actions(k)
                            }
                            .font(.callout)
                            .padding(.vertical, 8)
                            Divider().gridCellUnsizedAxes(.horizontal)
                        }
                    }
                    if let info { Text(info).font(.callout).foregroundStyle(.secondary) }
                    ErrorText(text: error)
                }
                Text("Removing a key rotates the vault key; every device re-encrypts in the background. Remote-only devices keep the vault only encrypted on the device: the Obsidian plugin supports them, the macOS client doesn't.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .task { await load() }
        .sheet(item: $approving) { p in ApproveSheet(device: p, folder: folder) { approving = nil; Task { await load() } } }
        .confirmationDialog("Remove \(removing?.name ?? "")'s key?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })) {
            Button("Remove Key", role: .destructive) {
                if let k = removing { act { try await folder.removeKey(k.id) } }
            }
        } message: {
            Text("That device can no longer sync this vault. Files it already has stay on it, unless it is remote-only.")
        }
    }

    @ViewBuilder
    private func actions(_ k: FolderController.VaultKey) -> some View {
        // A revoked key still in the keyring was kept (or not decided yet): it can still be removed.
        if !k.isThisMac && (k.status != "revoked" || k.inKeyring) {
            Menu {
                if k.status == "active" && k.inKeyring {
                    Button(k.remoteOnly ? "Make Full Device" : "Make Remote-Only") { act { try await folder.setRemoteOnly(k.id, !k.remoteOnly) } }
                    if k.remoteOnly {
                        Button(k.locked ? "Unlock" : "Lock") { act { try await folder.setLocked(k.id, !k.locked) } }
                    }
                    Divider()
                }
                Button("Remove Key…", role: .destructive) { removing = k }
            } label: { Image(systemName: "ellipsis.circle") }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        } else {
            Text("")
        }
    }

    private func load() async {
        guard folder.session != nil else { return }
        loading = true
        do {
            keys = try await folder.vaultKeys()
            error = nil
        } catch {
            self.error = "\(error)"
        }
        loading = false
    }

    private func act(_ f: @escaping () async throws -> Void) {
        Task {
            do {
                info = nil
                try await f()
                error = nil
            } catch {
                self.error = "\(error)"
            }
            await load()
        }
    }
}

func shortDate(_ iso: String) -> String {
    let f = ISO8601DateFormatter()
    if let d = f.date(from: iso) { return d.formatted(date: .abbreviated, time: .shortened) }
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f.date(from: iso)?.formatted(date: .abbreviated, time: .shortened) ?? iso
}

struct ApproveSheet: View {
    let device: FolderController.PendingDevice
    let folder: FolderController
    let close: () -> Void
    @State private var matches = false
    @State private var remoteOnly = false
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Approve \(device.name)?").font(.title2).bold()
            Text("Check that the new device shows exactly this code. Only approve a device you set up yourself.")
                .fixedSize(horizontal: false, vertical: true)
            Text(device.code).font(.system(size: 30, weight: .semibold, design: .monospaced)).textSelection(.enabled)
            Text(device.fingerprint).font(.caption.monospaced()).foregroundStyle(.secondary)
            Toggle("The codes match", isOn: $matches)
            Toggle("Approve as remote-only (the device keeps the vault only encrypted; Obsidian plugin only)", isOn: $remoteOnly)
            ErrorText(text: error)
            HStack {
                Spacer()
                Button("Cancel") { close() }
                Button("Approve") { approve() }.keyboardShortcut(.defaultAction).disabled(!matches || busy)
            }
        }
        .padding(20)
        .frame(width: 440)
    }

    private func approve() {
        busy = true
        Task {
            do {
                try await folder.approve(device, remoteOnly: remoteOnly)
                close()
            } catch {
                self.error = "\(error)"
            }
            busy = false
        }
    }
}

struct RecoveryTab: View {
    let folder: FolderController
    @State private var pending: RecoveryKey?
    @State private var stored = false
    @State private var busy = false
    @State private var error: String?
    @State private var confirmRemove = false

    var body: some View {
        Form {
            Section("Recovery key") {
                if let state = folder.recoveryState {
                    if state.isSet {
                        Label("This vault has a recovery key\(state.setBy.map { ", set by \($0)" } ?? "").", systemImage: "checkmark.shield")
                    } else {
                        Label("This vault has no recovery key. If every device is lost, nothing can open it.", systemImage: "exclamationmark.shield")
                    }
                } else {
                    Text("Connect the folder to manage its recovery key.").foregroundStyle(.secondary)
                }
                Text("A recovery key adds a new device when no device of the vault is left to approve it. It is shown once: keep it somewhere safe, away from this Mac.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let key = pending {
                Section("Your new recovery key") {
                    Text(key.identity).font(.body.monospaced()).textSelection(.enabled)
                    Button("Copy") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(key.identity, forType: .string)
                    }
                    Toggle("I stored this key somewhere safe", isOn: $stored)
                    HStack {
                        Button("Cancel") { pending = nil; stored = false }
                        Button("Use This Key") { run { try await folder.setRecovery(key) } }.disabled(!stored || busy)
                    }
                }
            } else if let state = folder.recoveryState {
                Section {
                    Button(state.isSet ? "Replace Recovery Key…" : "Create Recovery Key…") {
                        pending = folder.newRecoveryKey()
                        stored = false
                    }
                    if state.isSet { Button("Remove Recovery Key…", role: .destructive) { confirmRemove = true } }
                } footer: {
                    if state.isSet {
                        Text("Replacing or removing it rotates the vault key, so the old recovery key can't open anything new.").font(.caption)
                    }
                }
            }
            if busy { ProgressView().controlSize(.small) }
            ErrorText(text: error)
        }
        .formStyle(.grouped)
        .confirmationDialog("Remove the recovery key?", isPresented: $confirmRemove) {
            Button("Remove", role: .destructive) { run { try await folder.setRecovery(nil) } }
        }
    }

    private func run(_ f: @escaping () async throws -> Void) {
        busy = true
        Task {
            do {
                try await f()
                error = nil
                pending = nil
                stored = false
            } catch {
                self.error = "\(error)"
            }
            busy = false
        }
    }
}
