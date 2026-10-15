import AppKit
import SwiftUI
import SyncryptionAppCore

struct MenuView: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow
    @State private var opensAtLogin = false
    @State private var loginError: String?
    @State private var dock = DockIcon.isOn

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header.padding(.horizontal, 14).padding(.vertical, 12)
            Divider()
            if let e = model.loadError { Text(e).foregroundStyle(.red).font(.caption).padding(14) }
            if model.folders.isEmpty {
                Text("No folders yet. Add a folder to sync it, end-to-end encrypted, with a vault on your server.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    .padding(14)
            } else {
                ScrollView {
                    VStack(spacing: 2) {
                        ForEach(model.folders) { f in
                            FolderRow(folder: f) { open(f, $0) }
                        }
                    }
                    .padding(6)
                }
                .frame(maxHeight: 420)
                .fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            VStack(spacing: 0) {
                item("Sync All Now", "arrow.triangle.2.circlepath") { for f in model.folders { f.syncNow() } }
                    .disabled(model.folders.isEmpty)
                item("Sync Status…", "gauge.with.dots.needle.33percent", shortcut: "0") { showWindow("status") }
                item("Add Folder…", "folder.badge.plus", shortcut: "n") { showWindow("add") }
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
            }
            .padding(6)
            Divider()
            item("Quit Vault Syncryption", "power", shortcut: "q") { NSApp.terminate(nil) }.padding(6)
        }
        .frame(width: 380)
        .onAppear { opensAtLogin = model.opensAtLogin }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Logo(size: 30)
            VStack(alignment: .leading, spacing: 1) {
                Text("Vault Syncryption").font(.headline)
                Text(summary).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            StatePill(text: model.overallName, kind: model.overallKind)
        }
    }

    private var summary: String {
        let n = model.folders.count
        if n == 0 { return "No folders" }
        let attention = model.folders.filter { [.warn, .error].contains($0.statusKind) || !$0.pendingApprovals.isEmpty || !$0.unconfirmedRemovals.isEmpty }.count
        let files = model.folders.reduce(0) { $0 + $1.fileCount }
        if attention == 1 { return "1 folder needs attention" }
        if attention > 1 { return "\(attention) folders need attention" }
        return "\(plural(n, "folder")) · \(plural(files, "file"))"
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

    private func open(_ f: FolderController, _ tab: SettingsTab?) {
        if let tab {
            SettingsSelection.shared.select(f.id, tab: tab)
            showWindow("settings")
        } else {
            StatusSelection.shared.folder = f.id
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

/// One folder in the menu: its state, what it needs, and its actions.
struct FolderRow: View {
    let folder: FolderController
    /// nil: the status window; else a Settings tab.
    let open: (SettingsTab?) -> Void
    @State private var hover = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "folder.fill").font(.title2).foregroundStyle(Color.accentColor.opacity(0.85))
                    .overlay(alignment: .bottomTrailing) {
                        StatusDot(kind: folder.statusKind, size: 9)
                            .overlay(Circle().strokeBorder(Color(nsColor: .windowBackgroundColor), lineWidth: 1.5))
                            .offset(x: 3, y: 2)
                    }
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(folder.config.title).font(.body.weight(.semibold)).lineLimit(1)
                        Spacer(minLength: 6)
                        Text(folder.statusName).font(.caption.weight(.medium)).foregroundStyle(folder.statusKind.color)
                    }
                    Text("\(folder.config.vaultName) · \(host(folder.config.endpoint))").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    Text(line).font(.caption).foregroundStyle(.secondary).lineLimit(3).fixedSize(horizontal: false, vertical: true)
                }
                Menu {
                    Button("Sync Status…") { open(nil) }
                    Button("Sync Now") { folder.syncNow() }.disabled(folder.config.paused)
                    Button(folder.config.paused ? "Resume" : "Pause") { folder.setPaused(!folder.config.paused) }
                    Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([folder.config.url]) }
                    Divider()
                    Button("Devices…") { open(.devices) }
                    Button("History…") { open(.history) }
                    Button("Settings…") { open(.general) }
                } label: { Image(systemName: "ellipsis.circle").foregroundStyle(.secondary) }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            }
            StatusActions(folder: folder, open: { open($0) }).padding(.leading, 34)
            if !folder.pendingApprovals.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "person.badge.plus").foregroundStyle(.orange)
                    Text(folder.pendingApprovals.count == 1 ? "\(folder.pendingApprovals[0].name) is waiting for approval"
                        : "\(folder.pendingApprovals.count) devices are waiting for approval").font(.caption)
                    Spacer()
                    Button("Review…") { open(nil) }.controlSize(.small)
                }
                .padding(.leading, 34)
            }
            if !folder.unconfirmedRemovals.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "person.badge.minus").foregroundStyle(.orange)
                    Text(folder.unconfirmedRemovals.count == 1 ? "The server reports \(folder.unconfirmedRemovals[0].name) removed"
                        : "The server reports \(folder.unconfirmedRemovals.count) devices removed").font(.caption)
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

    /// The status line under the folder name.
    private var line: String {
        switch folder.status {
        case .synced(let at):
            return "Synced \(relative(at)) · \(plural(folder.fileCount, "file")) · \(folder.sizeText)" + (folder.pendingCount > 0 ? " · \(folder.pendingCount) waiting" : "")
        default:
            return folder.statusText
        }
    }
}

/// What the user can do about the folder's status, shown under it in the menu and in Add Folder.
struct StatusActions: View {
    let folder: FolderController
    let open: (SettingsTab) -> Void
    @State private var secret = ""
    @State private var recoveryKey = ""
    @State private var recoveryError: String?
    @State private var busy = false
    @State private var keyError: String?

    var body: some View {
        switch folder.status {
        case .needsSecret:
            VStack(alignment: .leading, spacing: 6) {
                Text("The vault \(folder.config.vaultName) doesn't exist yet. Enter the server's shared secret (from its admin) to create it. It is used once and not stored.")
                    .font(.caption).fixedSize(horizontal: false, vertical: true)
                HStack {
                    SecureField("Shared secret", text: $secret).textFieldStyle(.roundedBorder).onSubmit { submit() }
                    Button("Create Vault") { submit() }.disabled(secret.isEmpty)
                    Button("Cancel") { folder.provideSecret(nil) }
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
            Button("Try Again") { folder.tryAgain() }
        case .keyProblem, .revoked:
            HStack {
                if case .keyProblem = folder.status { Button("Try Again") { folder.tryAgain() } }
                Button("Create New Key") {
                    do { try folder.resetKey() } catch { keyError = "\(error)" }
                }
            }
            if let keyError { Text(keyError).foregroundStyle(.red).font(.caption) }
        case .refused:
            Button("Try Again") { folder.tryAgain() }
        default:
            EmptyView()
        }
    }

    private func submit() {
        guard !secret.isEmpty else { return }
        folder.provideSecret(secret)
        secret = ""
    }

    private func recover() {
        busy = true
        Task {
            do {
                try await folder.recover(identity: recoveryKey)
                recoveryError = nil
                recoveryKey = ""
            } catch {
                recoveryError = "\(error)"
            }
            busy = false
        }
    }
}
