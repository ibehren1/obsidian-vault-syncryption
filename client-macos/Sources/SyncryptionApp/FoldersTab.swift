import AppKit
import SwiftUI
import SyncryptionAppCore

/// The folder actions, with the questions they ask first. Shared by Settings, the menu and
/// Add Vault.
@MainActor
enum FolderActions {
    /// Errors go in an alert: the actions run from menus as well as windows.
    private static func fail(_ error: any Error) {
        let alert = NSAlert()
        alert.messageText = "That didn't work"
        alert.informativeText = "\(error)"
        alert.runModal()
    }

    /// Add a local folder to the vault as a new top-level folder with the same name.
    static func add(_ vault: VaultController) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Add Folder"
        panel.message = "Choose a folder to add to \(vault.config.vaultName). It becomes a top-level folder of the vault with the same name."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try vault.addFolder(path: url.path) } catch { fail(error) }
    }

    /// Sync the vault folder `name` on this Mac, in a folder named after it inside the chosen one.
    static func map(_ vault: VaultController, _ name: String) {
        while true {
            let panel = NSOpenPanel()
            panel.canChooseDirectories = true
            panel.canChooseFiles = false
            panel.canCreateDirectories = true
            panel.prompt = "Map Here"
            panel.message = "Choose where “\(name)” goes. A folder named “\(name)” is created inside the folder you choose."
            guard panel.runModal() == .OK, let parent = panel.url else { return }
            let path = VaultController.mappedPath(name, in: parent.path)
            if VaultController.hasFiles(path) {
                let alert = NSAlert()
                alert.messageText = "“\((path as NSString).abbreviatingWithTildeInPath)” already has files"
                alert.informativeText = "Merge them with the vault? Files that differ are merged, and when they can't be, a conflict copy is kept next to the file. Files only here are uploaded."
                alert.addButton(withTitle: "Merge with the Vault")
                alert.addButton(withTitle: "Choose Another Location")
                alert.addButton(withTitle: "Cancel")
                switch alert.runModal() {
                case .alertFirstButtonReturn: break
                case .alertSecondButtonReturn: continue
                default: return
                }
            }
            do { try vault.mapFolder(name, parent: parent.path) } catch { fail(error) }
            return
        }
    }

    /// Stop syncing `name` on this Mac, keeping its files or moving them to the Trash.
    static func unmap(_ vault: VaultController, _ name: String) {
        guard let f = vault.config.folder(name) else { return }
        let alert = NSAlert()
        alert.messageText = "Unmap “\(name)” from this Mac?"
        alert.informativeText = "Syncing stops on this Mac. The folder stays in the vault and on other devices. Keep the files in \((f.path as NSString).abbreviatingWithTildeInPath), or move that folder to the Trash?"
        alert.addButton(withTitle: "Keep the Files")
        alert.addButton(withTitle: "Move to Trash")
        alert.addButton(withTitle: "Cancel")
        let keep: Bool
        switch alert.runModal() {
        case .alertFirstButtonReturn: keep = true
        case .alertSecondButtonReturn: keep = false
        default: return
        }
        Task {
            do { try await vault.unmapFolder(name, keepFiles: keep) } catch { fail(error) }
        }
    }

    /// Delete a folder no device syncs from the vault, after asking.
    static func delete(_ vault: VaultController, _ folder: VaultController.VaultFolder) {
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Delete “\(folder.name)” from the vault?"
        alert.informativeText = "No device syncs this folder. Its \(plural(folder.files, "file")) are deleted from the vault for every device. Their old versions stay in History until the server prunes them."
        alert.addButton(withTitle: "Delete from Vault")
        alert.addButton(withTitle: "Cancel")
        alert.buttons.first?.hasDestructiveAction = true
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        Task {
            do { try await vault.deleteFromVault(folder.name) } catch { fail(error) }
        }
    }

    static func show(_ f: FolderMapping) { NSWorkspace.shared.activateFileViewerSelecting([f.url]) }
}

/// The vault's folders and where each device syncs them.
struct FoldersTab: View {
    let vault: VaultController
    @State private var editing: FolderMapping?
    @State private var finderExtensionOn = true

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if vault.session == nil && vault.vaultFolders.isEmpty {
                Text(vault.config.folders.isEmpty ? "Connect to see the folders of this vault." : "Connect to see the folders on other devices.")
                    .foregroundStyle(.secondary)
            }
            table
            HStack(spacing: 10) {
                Button("Add Folder…") { FolderActions.add(vault) }.buttonStyle(.borderedProminent)
                Text("Adds a folder on this Mac to the vault, as a new top-level folder with the same name.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Toggle("Pause vault", isOn: Binding(get: { vault.config.paused }, set: { vault.setPaused($0) }))
                    .toggleStyle(.checkbox)
            }
            ForEach(vault.config.folders.filter { vault.folderProblems[$0.name] != nil }) { f in
                Label(vault.folderProblems[f.name] ?? "", systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.callout)
            }
            if vault.config.folders.contains(where: \.showsFolderIcon) && !finderExtensionOn {
                HStack {
                    Text("Finder's sidebar shows the synced-folder icon only with the Vault Syncryption Client Finder extension on.")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Finder Extensions…") { FinderExtension.showSettings() }.controlSize(.small)
                }
            }
        }
        .task(id: vault.lastSync) { await vault.refreshFolders() }
        .onAppear { finderExtensionOn = FinderExtension.isEnabled }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            finderExtensionOn = FinderExtension.isEnabled
        }
        .sheet(item: $editing) { f in FolderSettingsSheet(vault: vault, folder: f) { editing = nil } }
    }

    /// This Mac's folders first while not connected, then every folder of the vault.
    private var rows: [VaultController.VaultFolder] {
        var rows = vault.vaultFolders
        for f in vault.config.folders where !rows.contains(where: { $0.name == f.name }) {
            rows.append(.init(name: f.name, files: 0, size: 0, mapping: f, elsewhere: [:]))
        }
        return rows.map { r in .init(name: r.name, files: r.files, size: r.size, mapping: vault.config.folder(r.name), elsewhere: r.elsewhere) }
    }

    private var table: some View {
        let devices = vault.otherDevices
        return ScrollView(.horizontal) {
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 0) {
                GridRow {
                    header("State")
                    header("Vault folder")
                    header("This Mac", sub: vault.config.deviceName)
                    ForEach(devices) { d in
                        header(d.name, sub: isoDate(d.lastSeenAt).map { "seen \(relative($0))" })
                    }
                }
                .padding(.bottom, 6)
                Divider().gridCellUnsizedAxes(.horizontal)
                ForEach(rows) { r in
                    GridRow(alignment: .center) {
                        stateCell(r)
                        VStack(alignment: .leading, spacing: 1) {
                            Label(r.name, systemImage: r.mapping == nil ? "folder" : "folder.fill").font(.body.weight(.medium))
                            Text(r.files == 0 ? "No files" : "\(plural(r.files, "file")) · \(r.size.formatted(.byteCount(style: .file)))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        // This Mac's cell carries the actions, so they stay in view however many devices there are.
                        HStack(spacing: 8) {
                            pathCell(r.mapping?.path)
                            Spacer(minLength: 4)
                            actions(r)
                        }
                        .frame(minWidth: 280)
                        ForEach(devices) { d in pathCell(r.elsewhere[d.id]) }
                    }
                    .padding(.vertical, 8)
                    Divider().gridCellUnsizedAxes(.horizontal)
                }
            }
            .padding(14)
        }
        .background(CardBackground())
    }

    private func header(_ title: String, sub: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title).font(.caption.weight(.semibold)).foregroundStyle(.secondary).lineLimit(1)
            if let sub { Text(sub).font(.caption2).foregroundStyle(.tertiary).lineLimit(1) }
        }
    }

    @ViewBuilder private func stateCell(_ r: VaultController.VaultFolder) -> some View {
        if vault.folderState(r.name) == .notMapped {
            Text("-").foregroundStyle(.tertiary).help("Not on this Mac")
        } else {
            FolderPausePill(vault: vault, name: r.name)
        }
    }

    @ViewBuilder private func pathCell(_ path: String?) -> some View {
        if let path {
            Text((path as NSString).abbreviatingWithTildeInPath).font(.callout.monospaced()).lineLimit(1).truncationMode(.middle)
                .frame(maxWidth: 190, alignment: .leading).help(path)
        } else {
            Text("-").foregroundStyle(.tertiary)
        }
    }

    @ViewBuilder private func actions(_ r: VaultController.VaultFolder) -> some View {
        if let f = r.mapping {
            HStack(spacing: 6) {
                Menu {
                    Button("Show in Finder") { FolderActions.show(f) }
                    Button("Folder Settings…") { editing = f }
                    Toggle("Show Folder Icon", isOn: Binding(get: { f.showsFolderIcon }, set: { vault.setShowsFolderIcon(f.name, $0) }))
                    Divider()
                    Button("Unmap from This Mac…", role: .destructive) { FolderActions.unmap(vault, f.name) }
                } label: { Image(systemName: "ellipsis.circle") }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            }
        } else {
            HStack(spacing: 6) {
                Button("Map…") { FolderActions.map(vault, r.name) }.controlSize(.small).disabled(vault.session == nil)
                if r.isUnmapped {
                    Button("Delete from Vault…", role: .destructive) { FolderActions.delete(vault, r) }.controlSize(.small)
                        .disabled(vault.engine == nil)
                }
            }
        }
    }
}

/// One folder's settings on this Mac: its exclude list and Finder icon.
struct FolderSettingsSheet: View {
    let vault: VaultController
    let folder: FolderMapping
    let done: () -> Void
    @State private var exclude = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Folder “\(folder.name)” in \(vault.config.vaultName)").font(.title3.weight(.semibold))
            Text("Settings for this folder on this Mac only.").font(.callout).foregroundStyle(.secondary)
            Form {
                LabeledContent("Local folder") {
                    HStack {
                        Text(folder.path).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                        Button("Show") { FolderActions.show(folder) }
                    }
                }
                Toggle("Show the synced-folder icon in Finder",
                       isOn: Binding(get: { vault.config.folder(folder.name)?.showsFolderIcon ?? true },
                                     set: { vault.setShowsFolderIcon(folder.name, $0) }))
                Section {
                    TextEditor(text: $exclude).font(.body.monospaced()).frame(minHeight: 90)
                } header: {
                    Text("Exclude list")
                } footer: {
                    Text("One pattern per line, relative to this folder. `*` and `?` match within a name, `**` across folders; a pattern also excludes everything inside it. Lines starting with # are comments. Excluding stops syncing without deleting anywhere.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            HStack {
                Button("Unmap from This Mac…", role: .destructive) {
                    done()
                    FolderActions.unmap(vault, folder.name)
                }
                Spacer()
                Button("Cancel") { done() }
                Button("Save") {
                    vault.updateExclude(folder.name, exclude)
                    done()
                }
                .keyboardShortcut(.defaultAction).disabled(exclude == folder.exclude)
            }
        }
        .padding(20)
        .frame(width: 560, height: 480)
        .onAppear { exclude = folder.exclude }
    }
}

/// A folder's state pill (Synced, Syncing, Paused, Missing…): clicking it pauses or resumes
/// the folder on this Mac, or resumes the vault when the whole vault is paused.
struct FolderPausePill: View {
    let vault: VaultController
    let name: String

    var body: some View {
        if let s = vault.folderStatus(name) {
            let pill = StatePill(text: s.name, kind: s.kind)
            switch vault.folderState(name) {
            case .missing, .notMapped:
                pill.help(vault.folderProblems[name] ?? "")
            case .paused:
                Button { vault.setFolderPaused(name, false) } label: { pill }
                    .buttonStyle(.plain).help("Resume this folder on this Mac")
            case .active where vault.config.paused:
                Button { vault.setPaused(false) } label: { pill }
                    .buttonStyle(.plain).help("The whole vault is paused: resume it on this Mac")
            case .active:
                Button { vault.setFolderPaused(name, true) } label: { pill }
                    .buttonStyle(.plain).help("Pause this folder on this Mac")
            }
        }
    }
}

/// A vault's state pill: clicking it pauses or resumes the whole vault on this Mac.
struct VaultPausePill: View {
    let vault: VaultController

    var body: some View {
        Button { vault.setPaused(!vault.config.paused) } label: { StatePill(text: vault.statusName, kind: vault.statusKind) }
            .buttonStyle(.plain).help(vault.config.paused ? "Resume this vault on this Mac" : "Pause this vault on this Mac")
    }
}
