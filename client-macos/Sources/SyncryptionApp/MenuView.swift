import AppKit
import SwiftUI
import SyncryptionAPI
import SyncryptionAppCore

struct MenuView: View {
    let model: AppModel
    let updater: Updater
    @Environment(\.openWindow) private var openWindow
    @State private var opensAtLogin = false
    @State private var loginError: String?
    @State private var dock = DockIcon.isOn

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header.padding(.horizontal, 14).padding(.vertical, 12)
            Divider()
            if let e = model.loadError { Text(e).foregroundStyle(.red).font(.caption).padding(14) }
            if model.vaults.isEmpty {
                Text("No vaults yet. Add a vault, then the folders to sync with it, end-to-end encrypted.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    .padding(14)
            } else {
                ScrollView {
                    VStack(spacing: 2) {
                        ForEach(model.vaults) { f in
                            VaultRow(vault: f) { open(f, $0) }
                        }
                    }
                    .padding(6)
                }
                .frame(maxHeight: 420)
                .fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            VStack(spacing: 0) {
                item("Sync All Now", "arrow.triangle.2.circlepath") { for f in model.vaults { f.syncNow() } }
                    .disabled(model.vaults.isEmpty)
                item("Sync Status…", "gauge.with.dots.needle.33percent", shortcut: "0") { showWindow("status") }
                item("Add Vault…", "plus.rectangle.on.folder", shortcut: "n") { showWindow("add") }
                item("Settings…", "gearshape", shortcut: ",") { showWindow("settings") }
                Toggle(isOn: Binding(get: { opensAtLogin }, set: { on in
                    do {
                        try model.setOpensAtLogin(on)
                        loginError = nil
                    } catch { loginError = "\(error)" }
                    opensAtLogin = model.opensAtLogin
                })) {
                    Text("Open at Login").padding(.leading, 4)
                }
                .toggleStyle(.checkbox).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10).padding(.vertical, 5)
                if let loginError { Text(loginError).font(.caption).foregroundStyle(.red).padding(.horizontal, 10) }
                Toggle(isOn: Binding(get: { dock }, set: { dock = $0; DockIcon.set($0) })) {
                    Text("Show in Dock").padding(.leading, 4)
                }
                .toggleStyle(.checkbox).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10).padding(.vertical, 5)
                if updater.isEnabled { updates }
            }
            .padding(6)
            Divider()
            item("Quit Vault Syncryption Client", "power", shortcut: "q") { NSApp.terminate(nil) }.padding(6)
        }
        .frame(width: 380)
        .onAppear { opensAtLogin = model.opensAtLogin }
    }

    @ViewBuilder private var updates: some View {
        Toggle(isOn: Binding(get: { updater.installsAutomatically }, set: { updater.installsAutomatically = $0 })) {
            Text("Install Updates Automatically").padding(.leading, 4)
        }
        .toggleStyle(.checkbox).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10).padding(.vertical, 5)
        switch updater.state {
        case .available(let v):
            item("Install Version \(v)", "arrow.down.circle") { Task { await updater.install() } }
        case .cantInstall(let reason, let dmg):
            updateNote(reason)
            item("Open the Download", "arrow.down.circle") { NSWorkspace.shared.open(dmg) }
        default:
            item("Check for Updates", "arrow.down.circle") { Task { await updater.checkNow() } }
                .disabled(updater.state == .checking)
            if let note = updateText { updateNote(note) }
        }
    }

    private var updateText: String? {
        switch updater.state {
        case .checking: "Checking for updates…"
        case .downloading(let v): "Downloading version \(v)…"
        case .waiting(let v): "Version \(v) installs once nothing is syncing."
        case .installing(let v): "Installing version \(v)…"
        case .failed(let e): e
        default: updater.lastCheck.map { "Version \(clientVersion), checked \($0.formatted(date: .omitted, time: .shortened))" }
        }
    }

    private func updateNote(_ text: String) -> some View {
        Text(text).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10).padding(.bottom, 4)
    }

    private var header: some View {
        HStack(spacing: 10) {
            Logo(size: 30)
            VStack(alignment: .leading, spacing: 1) {
                Text("Vault Syncryption Client").font(.headline)
                Text(summary).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            StatePill(text: model.overallName, kind: model.overallKind)
        }
    }

    private var summary: String {
        let n = model.vaults.count
        if n == 0 { return "No vaults" }
        let attention = model.vaults.filter {
            [.warn, .error].contains($0.statusKind) || !$0.pendingApprovals.isEmpty || !$0.unconfirmedRemovals.isEmpty || !$0.folderProblems.isEmpty
        }.count
        let files = model.vaults.reduce(0) { $0 + $1.fileCount }
        let folders = model.vaults.reduce(0) { $0 + $1.config.folders.count }
        if attention == 1 { return "1 vault needs attention" }
        if attention > 1 { return "\(attention) vaults need attention" }
        return "\(plural(n, "vault")) · \(plural(folders, "folder")) · \(plural(files, "file"))"
    }

    private func item(_ title: String, _ symbol: String, shortcut: KeyEquivalent? = nil, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: symbol).frame(width: 18)
                Text(title)
                Spacer()
                if let shortcut { Text("⌘\(String(shortcut.character).uppercased())").foregroundStyle(.secondary).font(.callout) }
            }
        }
        .buttonStyle(MenuRowStyle())
        .modifier(OptionalShortcut(key: shortcut))
    }

    private func showWindow(_ id: String) {
        openWindow(id: id)
        activate()
    }

    private func open(_ f: VaultController, _ tab: SettingsTab?) {
        if let tab {
            SettingsSelection.shared.select(f.id, tab: tab)
            showWindow("settings")
        } else {
            StatusSelection.shared.vault = f.id
            showWindow("status")
        }
    }
}

struct OptionalShortcut: ViewModifier {
    let key: KeyEquivalent?
    func body(content: Content) -> some View {
        if let key { content.keyboardShortcut(key, modifiers: .command) } else { content }
    }
}

/// One vault in the menu: its state, its folders, what it needs, and its actions.
struct VaultRow: View {
    let vault: VaultController
    /// nil: the status window; else a Settings tab.
    let open: (SettingsTab?) -> Void
    @State private var hover = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "lock.rotation").font(.title2).foregroundStyle(Color.accentColor.opacity(0.85))
                    .overlay(alignment: .bottomTrailing) {
                        StatusDot(kind: vault.statusKind, size: 9)
                            .overlay(Circle().strokeBorder(Color(nsColor: .windowBackgroundColor), lineWidth: 1.5))
                            .offset(x: 3, y: 2)
                    }
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(vault.config.title).font(.body.weight(.semibold)).lineLimit(1)
                        Spacer(minLength: 6)
                        VaultPausePill(vault: vault)
                    }
                    Text(host(vault.config.endpoint)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    Text(line).font(.caption).foregroundStyle(.secondary).lineLimit(3).fixedSize(horizontal: false, vertical: true)
                }
                Menu {
                    Button("Sync Status…") { open(nil) }
                    Button("Sync Now") { vault.syncNow() }.disabled(vault.config.paused)
                    Button(vault.config.paused ? "Resume Vault" : "Pause Vault") { vault.setPaused(!vault.config.paused) }
                    Divider()
                    Button("Folders…") { open(.folders) }
                    Button("Add Folder…") { FolderActions.add(vault) }.disabled(vault.session == nil)
                    Button("Devices…") { open(.devices) }
                    Button("History…") { open(.history) }
                    Button("Settings…") { open(.general) }
                } label: { Image(systemName: "ellipsis.circle").foregroundStyle(.secondary) }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            }
            VStack(alignment: .leading, spacing: 3) {
                ForEach(vault.config.folders) { f in folderLine(f) }
                ForEach(vault.vaultFolders.filter { $0.mapping == nil }) { f in
                    Button { FolderActions.map(vault, f.name) } label: {
                        HStack(spacing: 7) {
                            Image(systemName: "folder").foregroundStyle(.tertiary).frame(width: 16)
                            Text(f.name).foregroundStyle(.secondary).frame(minWidth: 70, alignment: .leading)
                            Text("not on this Mac").foregroundStyle(.tertiary)
                            Spacer()
                        }
                        .font(.caption)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain).help("Map \(f.name) to a folder on this Mac")
                }
            }
            .padding(.leading, 34)
            StatusActions(vault: vault, open: { open($0) }).padding(.leading, 34)
            if !vault.pendingApprovals.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "person.badge.plus").foregroundStyle(.orange)
                    Text(vault.pendingApprovals.count == 1 ? "\(vault.pendingApprovals[0].name) is waiting for approval"
                        : "\(vault.pendingApprovals.count) devices are waiting for approval").font(.caption)
                    Spacer()
                    Button("Review…") { open(nil) }.controlSize(.small)
                }
                .padding(.leading, 34)
            }
            if !vault.unconfirmedRemovals.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "person.badge.minus").foregroundStyle(.orange)
                    Text(vault.unconfirmedRemovals.count == 1 ? "The server reports \(vault.unconfirmedRemovals[0].name) removed"
                        : "The server reports \(vault.unconfirmedRemovals.count) devices removed").font(.caption)
                    Spacer()
                    Button("Review…") { open(.devices) }.controlSize(.small)
                }
                .padding(.leading, 34)
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(hover ? Color.primary.opacity(0.05) : .clear))
        .contentShape(Rectangle())
        .onHover { hover = $0 }
        .onTapGesture { open(nil) }
    }

    private func folderLine(_ f: FolderMapping) -> some View {
        HStack(spacing: 7) {
            Image(systemName: "folder.fill").foregroundStyle(Color.accentColor.opacity(0.75)).frame(width: 16)
            Text(f.name).frame(minWidth: 70, alignment: .leading)
            Text((f.path as NSString).abbreviatingWithTildeInPath).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            Spacer()
            FolderPausePill(vault: vault, name: f.name)
        }
        .font(.caption)
    }

    /// The status line under the vault name.
    private var line: String {
        switch vault.status {
        case .synced(let at):
            return "Synced \(relative(at)) · \(plural(vault.fileCount, "file")) · \(vault.sizeText)" + (vault.pendingCount > 0 ? " · \(vault.pendingCount) waiting" : "")
        default:
            return vault.statusText
        }
    }
}

/// What the user can do about the vault's status, shown under it in the menu and in Add Vault.
struct StatusActions: View {
    let vault: VaultController
    let open: (SettingsTab) -> Void
    @State private var secret = ""
    @State private var recoveryKey = ""
    @State private var recoveryError: String?
    @State private var busy = false
    @State private var keyError: String?

    var body: some View {
        switch vault.status {
        case .needsSecret:
            VStack(alignment: .leading, spacing: 6) {
                Text("The vault \(vault.config.vaultName) doesn't exist yet. Enter the server's shared secret (from its admin) to create it. It is used once and not stored.")
                    .font(.caption).fixedSize(horizontal: false, vertical: true)
                HStack {
                    SecureField("Shared secret", text: $secret).textFieldStyle(.roundedBorder).onSubmit { submit() }
                    Button("Create Vault") { submit() }.disabled(secret.isEmpty)
                    Button("Cancel") { vault.provideSecret(nil) }
                }
            }
        case .pairing(let code, let canRecover):
            VStack(alignment: .leading, spacing: 6) {
                Text("Approve this Mac from another device of the vault, after checking that it shows this code:")
                    .font(.caption).fixedSize(horizontal: false, vertical: true)
                Text(code).font(.system(size: 22, weight: .semibold, design: .monospaced)).textSelection(.enabled)
                if canRecover {
                    DisclosureGroup("No other device? Use the recovery key") {
                        HStack {
                            SecureField("AGE-SECRET-KEY-1…", text: $recoveryKey).textFieldStyle(.roundedBorder)
                            Button("Recover") { recover() }.disabled(recoveryKey.isEmpty || busy)
                        }
                        if let recoveryError { Text(recoveryError).foregroundStyle(.red).font(.caption) }
                    }.font(.caption)
                }
            }
        case .error, .offline:
            Button("Try Again") { vault.tryAgain() }
        case .keyProblem, .revoked:
            HStack {
                if case .keyProblem = vault.status { Button("Try Again") { vault.tryAgain() } }
                Button("Create New Key") {
                    do { try vault.resetKey() } catch { keyError = "\(error)" }
                }
            }
            if let keyError { Text(keyError).foregroundStyle(.red).font(.caption) }
        case .refused:
            Button("Try Again") { vault.tryAgain() }
        default:
            EmptyView()
        }
    }

    private func submit() {
        guard !secret.isEmpty else { return }
        vault.provideSecret(secret)
        secret = ""
    }

    private func recover() {
        busy = true
        Task {
            do {
                try await vault.recover(identity: recoveryKey)
                recoveryError = nil
                recoveryKey = ""
            } catch {
                recoveryError = "\(error)"
            }
            busy = false
        }
    }
}
