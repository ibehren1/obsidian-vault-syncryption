import AppKit
import SwiftUI
import SyncryptionAppCore
import SyncryptionSync

/// Which vault the status window shows, so the menu can open it at one.
@MainActor @Observable
final class StatusSelection {
    static let shared = StatusSelection()
    var vault: UUID?
}

/// The sync status of a vault, like the plugin's status window: state and actions, the
/// figures, this Mac's folders, what waits to upload, this Mac, and the keys of the vault.
struct StatusWindow: View {
    let model: AppModel
    @State private var selection = StatusSelection.shared
    @Environment(\.openWindow) private var openWindow

    private var vault: VaultController? {
        model.vaults.first { $0.id == selection.vault } ?? model.vaults.first
    }

    var body: some View {
        Group {
            if let vault {
                ScrollView {
                    FolderStatus(vault: vault) { tab in
                        SettingsSelection.shared.select(vault.id, tab: tab)
                        openWindow(id: "settings")
                    }
                    .padding(24)
                }
                .id(vault.id)
            } else {
                VStack(spacing: 14) {
                    Logo(size: 72)
                    Text("No vaults yet").font(.title2.weight(.semibold))
                    Text("Add a vault, then the folders to sync with it, end-to-end encrypted.").foregroundStyle(.secondary)
                    Button("Add Vault…") { openWindow(id: "add") }.buttonStyle(.borderedProminent).controlSize(.large)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 860, minHeight: 640)
        .toolbar {
            if model.vaults.count > 1 {
                ToolbarItem(placement: .principal) {
                    Picker("Vault", selection: Binding(get: { vault?.id }, set: { selection.vault = $0 })) {
                        ForEach(model.vaults) { f in Text(f.config.title).tag(Optional(f.id)) }
                    }
                    .pickerStyle(.segmented)
                }
            }
        }
        .navigationTitle(vault.map { "Sync Status — \($0.config.title)" } ?? "Sync Status")
    }
}

struct FolderStatus: View {
    let vault: VaultController
    let openSettings: (SettingsTab) -> Void
    @State private var queue: [VaultController.QueuedChange] = []
    @State private var keys: [VaultController.VaultKey]?
    @State private var keysError: String?
    @State private var approving: VaultController.PendingDevice?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            header
            if let detail = vault.statusDetail { callout(detail) }
            TimelineView(.periodic(from: .now, by: 15)) { context in tiles(now: context.date) }
            HStack(alignment: .top, spacing: 16) {
                foldersCard
                deviceCard
            }
            queueCard
            keysCard
            if !vault.warnings.isEmpty || !(vault.lastReport?.conflicts.isEmpty ?? true) { problemsCard }
            HStack {
                Text("Approve, remove and change devices, set the recovery key and restore old versions in Settings.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Open Settings…") { openSettings(.devices) }
            }
        }
        .task(id: vault.lastSync) { await reload() }
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                queue = await vault.queuedChanges()
            }
        }
        .sheet(item: $approving) { p in ApproveSheet(device: p, vault: vault) { approving = nil; Task { await reload() } } }
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            Logo(size: 48)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 10) {
                    Text(vault.config.title).font(.title2.weight(.semibold))
                    StatePill(text: vault.statusName, kind: vault.statusKind)
                }
                Text("\(host(vault.config.endpoint)) · \(vault.config.username)")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            Button(vault.config.paused ? "Resume Sync" : "Pause Sync") { vault.setPaused(!vault.config.paused) }
                .controlSize(.large)
            Button(vault.session == nil ? "Connect" : "Sync Now") { vault.syncNow() }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(vault.config.paused || vault.statusKind == .busy)
        }
    }

    private func callout(_ text: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: vault.statusSymbol).foregroundStyle(vault.statusKind.color)
                Text(text).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
            }
            if let f = vault.currentFile {
                HStack(spacing: 8) {
                    FileProgressLine(fraction: f.fraction)
                    Text(f.path).font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(f.path)
                }
            }
            StatusActions(vault: vault, open: openSettings)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(vault.statusKind.color.opacity(0.08)))
    }

    // MARK: Tiles

    private func tiles(now: Date) -> some View {
        let r = vault.lastReport
        var extra: [String] = []
        if let r, r.merged > 0 { extra.append(plural(r.merged, "merge")) }
        if let r, !r.conflicts.isEmpty { extra.append(plural(r.conflicts.count, "conflict copy", "conflict copies")) }
        if let r, r.reencrypted > 0 { extra.append("\(r.reencrypted) re-encrypted") }
        let oldest = queue.map(\.queuedAt).min()
        return Grid(horizontalSpacing: 12) {
            GridRow {
                Tile(label: "Last sync", value: vault.lastSync.map { relative($0, to: now, capitalized: true) } ?? "Never",
                     detail: vault.lastSync?.formatted(date: .abbreviated, time: .standard) ?? "No sync on this Mac yet", systemImage: "clock")
                Tile(label: "Last run", value: r.map { "\($0.pushed) ↑  \($0.pulled) ↓" } ?? "—",
                     detail: runDetail(r, extra), systemImage: "arrow.up.arrow.down")
                Tile(label: "Files in sync", value: vault.session == nil && vault.fileCount == 0 ? "—" : vault.fileCount.formatted(),
                     detail: "\(plural(vault.config.folders.count, "folder")) · \(vault.sizeText)", systemImage: "doc.on.doc")
                Tile(label: "Waiting to upload", value: vault.engine == nil ? "—" : queue.count.formatted(),
                     detail: oldest.map { "Oldest \($0.formatted(date: .omitted, time: .shortened))" } ?? "", systemImage: "tray.and.arrow.up")
            }
        }
    }

    private func runDetail(_ r: SyncReport?, _ extra: [String]) -> String {
        guard r != nil else { return "Nothing run yet" }
        return extra.isEmpty ? "No merges or conflicts" : extra.joined(separator: " · ")
    }

    // MARK: Columns

    private var queueCard: some View {
        Card(title: "Waiting to upload", count: vault.engine == nil ? nil : plural(queue.count, "change")) {
            if vault.engine == nil {
                note("Connect to see the changes waiting on this Mac.")
            } else if queue.isEmpty {
                note("Nothing: every noted change is uploaded.")
            } else {
                VStack(spacing: 0) {
                    ForEach(queue.prefix(12)) { c in
                        HStack {
                            Image(systemName: c.files > 1 || c.note != nil ? "shippingbox" : "doc").foregroundStyle(.secondary)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(c.path).lineLimit(1).truncationMode(.middle)
                                if c.files > 1 || c.note != nil {
                                    Text([c.files > 1 ? "\(c.files) files" : nil, c.note].compactMap { $0 }.joined(separator: " · "))
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            Text(c.queuedAt.formatted(date: .omitted, time: .shortened)).foregroundStyle(.secondary).monospacedDigit()
                        }
                        .font(.callout)
                        .padding(.vertical, 5)
                        Divider()
                    }
                    if queue.count > 12 { note("and \(queue.count - 12) more").padding(.top, 6) }
                }
            }
            note("Changes made while the app wasn't running are found at the next sync. A package (a document Finder shows as one file, like a Quicken file) uploads whole, once nothing in it has changed for 30 seconds and no app has it open.")
        }
    }

    private var deviceCard: some View {
        Card(title: "This Mac") {
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 8) {
                KeyValue(label: "Device") { Text(vault.config.deviceName) }
                KeyValue(label: "Server") { Text(vault.config.endpoint).lineLimit(1).truncationMode(.middle) }
                KeyValue(label: "Vault") { Text(vault.config.vaultName) }
                KeyValue(label: "Encryption key") {
                    if let k = vault.keyInfo { Fingerprint(value: k.fingerprint) } else { Text("None").foregroundStyle(.secondary) }
                }
                KeyValue(label: "Mode") { Text("Full device") }
                KeyValue(label: "Recovery key") {
                    if let r = vault.recoveryState {
                        HStack(spacing: 6) {
                            StatusDot(kind: r.isSet ? .ok : .warn, size: 7)
                            Text(r.isSet ? "Set\(r.setBy.map { " by \($0)" } ?? "")" : "Not set")
                            if !r.isSet { Button("Create…") { openSettings(.recovery) }.controlSize(.small) }
                        }
                    } else {
                        Text("—").foregroundStyle(.secondary)
                    }
                }
            }
            .font(.callout)
        }
    }

    private var foldersCard: some View {
        Card(title: "Folders on This Mac", count: plural(vault.config.folders.count, "folder")) {
            if vault.config.folders.isEmpty {
                note("None yet. Add or map a folder in Settings → Folders.")
            }
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 8) {
                ForEach(vault.config.folders) { f in
                    GridRow(alignment: .firstTextBaseline) {
                        Text(f.name).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                        HStack(spacing: 6) {
                            Text((f.path as NSString).abbreviatingWithTildeInPath).lineLimit(1).truncationMode(.middle).help(f.path)
                            FolderPausePill(vault: vault, name: f.name)
                            Button { FolderActions.show(f) } label: { Image(systemName: "arrow.up.forward.square") }
                                .buttonStyle(.borderless).help("Show in Finder")
                        }
                    }
                }
                ForEach(vault.vaultFolders.filter { $0.mapping == nil }) { f in
                    GridRow(alignment: .firstTextBaseline) {
                        Text(f.name).foregroundStyle(.tertiary).gridColumnAlignment(.trailing)
                        Text("-").foregroundStyle(.tertiary)
                    }
                }
            }
            .font(.callout)
            HStack {
                Spacer()
                Button("Folders…") { openSettings(.folders) }.controlSize(.small)
            }
        }
    }

    // MARK: Keys

    private var keysCard: some View {
        Card(title: "Vault keys", count: keys.map { plural($0.count, "key") }) {
            if !vault.pendingApprovals.isEmpty {
                ForEach(vault.pendingApprovals) { p in
                    HStack(spacing: 10) {
                        StatusDot(kind: .warn)
                        Text("\(p.name) is waiting for approval").font(.callout.weight(.medium))
                        Text(p.code).font(.callout.monospaced()).foregroundStyle(.secondary)
                        Spacer()
                        Button("Approve…") { approving = p }.buttonStyle(.borderedProminent).controlSize(.small)
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.orange.opacity(0.08)))
                }
            }
            if let keys {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 0) {
                    GridRow {
                        ForEach(["Device", "Fingerprint", "Added", "Server"], id: \.self) {
                            Text($0).font(.caption.weight(.medium)).foregroundStyle(.secondary)
                        }
                        Text("Last seen").font(.caption.weight(.medium)).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                    .padding(.bottom, 6)
                    Divider().gridCellUnsizedAxes(.horizontal)
                    ForEach(keys) { k in
                        GridRow(alignment: .firstTextBaseline) {
                            HStack(spacing: 6) {
                                Text(k.name).lineLimit(1)
                                if k.isThisMac { Tag(text: "This Mac", color: .accentColor) }
                                if k.remoteOnly { Tag(text: "Remote-only", color: .purple) }
                            }
                            Fingerprint(value: k.fingerprint)
                            Text(isoDate(k.added)?.formatted(date: .abbreviated, time: .omitted) ?? "—").foregroundStyle(.secondary)
                            HStack(spacing: 6) {
                                StatusDot(kind: k.serverKind, size: 7)
                                Text(k.serverLabel)
                            }
                            Text(k.isThisMac ? "Now" : isoDate(k.lastSeenAt).map { relative($0, capitalized: true) } ?? "—").foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                        }
                        .font(.callout)
                        .padding(.vertical, 7)
                        Divider().gridCellUnsizedAxes(.horizontal)
                    }
                }
            } else if let keysError {
                note(keysError)
            } else {
                note(vault.session == nil ? "Connect to see the keys of this vault." : "Loading…")
            }
        }
    }

    private var problemsCard: some View {
        Card(title: "Recent problems", count: nil) {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(vault.lastReport?.conflicts ?? [], id: \.self) { c in
                    Label("Conflict copy: \(c)", systemImage: "doc.on.doc").font(.callout)
                }
                ForEach(Array(vault.warnings.suffix(8).enumerated()), id: \.offset) {
                    Label($0.element, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.secondary)
                }
            }
        }
    }

    private func note(_ s: String) -> some View {
        Text(s).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }

    private func reload() async {
        queue = await vault.queuedChanges()
        guard vault.session != nil else { return }
        do {
            keys = try await vault.vaultKeys()
            keysError = nil
        } catch {
            keysError = "\(error)"
        }
    }
}

/// How far the current file is: a light blue line, about an inch long, that fills dark blue
/// from the left.
struct FileProgressLine: View {
    let fraction: Double

    var body: some View {
        ZStack(alignment: .leading) {
            Capsule().fill(Color.blue.opacity(0.25))
            Capsule().fill(Color.blue).frame(width: 72 * fraction)
        }
        .frame(width: 72, height: 4)
        .animation(.linear(duration: 0.2), value: fraction)
    }
}
