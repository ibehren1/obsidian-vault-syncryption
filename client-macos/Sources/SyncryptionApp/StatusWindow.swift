import AppKit
import SwiftUI
import SyncryptionAppCore
import SyncryptionSync

/// Which folder the status window shows, so the menu can open it at one.
@MainActor @Observable
final class StatusSelection {
    static let shared = StatusSelection()
    var folder: UUID?
}

/// The sync status of a folder, like the plugin's status window: state and actions, the
/// figures, what waits to upload, this Mac, and the keys of the vault.
struct StatusWindow: View {
    let model: AppModel
    @State private var selection = StatusSelection.shared
    @Environment(\.openWindow) private var openWindow

    private var folder: FolderController? {
        model.folders.first { $0.id == selection.folder } ?? model.folders.first
    }

    var body: some View {
        Group {
            if let folder {
                ScrollView {
                    FolderStatus(folder: folder) { tab in
                        SettingsSelection.shared.select(folder.id, tab: tab)
                        openWindow(id: "settings")
                    }
                    .padding(24)
                }
                .id(folder.id)
            } else {
                VStack(spacing: 14) {
                    Logo(size: 72)
                    Text("No folders yet").font(.title2.weight(.semibold))
                    Text("Add a folder to sync it, end-to-end encrypted, with a vault on your server.").foregroundStyle(.secondary)
                    Button("Add Folder…") { openWindow(id: "add") }.buttonStyle(.borderedProminent).controlSize(.large)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 860, minHeight: 640)
        .toolbar {
            if model.folders.count > 1 {
                ToolbarItem(placement: .principal) {
                    Picker("Folder", selection: Binding(get: { folder?.id }, set: { selection.folder = $0 })) {
                        ForEach(model.folders) { f in Text(f.config.title).tag(Optional(f.id)) }
                    }
                    .pickerStyle(.segmented)
                }
            }
        }
        .navigationTitle(folder.map { "Sync Status — \($0.config.title)" } ?? "Sync Status")
    }
}

struct FolderStatus: View {
    let folder: FolderController
    let openSettings: (SettingsTab) -> Void
    @State private var queue: [FolderController.QueuedChange] = []
    @State private var keys: [FolderController.VaultKey]?
    @State private var keysError: String?
    @State private var approving: FolderController.PendingDevice?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            header
            if let detail = folder.statusDetail { callout(detail) }
            TimelineView(.periodic(from: .now, by: 15)) { context in tiles(now: context.date) }
            HStack(alignment: .top, spacing: 16) {
                queueCard
                deviceCard
            }
            keysCard
            if !folder.warnings.isEmpty || !(folder.lastReport?.conflicts.isEmpty ?? true) { problemsCard }
            HStack {
                Text("Approve, remove and change devices, set the recovery key and restore old versions in Settings.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Open Settings…") { openSettings(.devices) }
            }
        }
        .task(id: folder.lastSync) { await reload() }
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                queue = await folder.queuedChanges()
            }
        }
        .sheet(item: $approving) { p in ApproveSheet(device: p, folder: folder) { approving = nil; Task { await reload() } } }
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            Logo(size: 48)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 10) {
                    Text(folder.config.title).font(.title2.weight(.semibold))
                    StatePill(text: folder.statusName, kind: folder.statusKind)
                }
                Text("\(folder.config.vaultName) · \(host(folder.config.endpoint)) · \(folder.config.username)")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            Button(folder.config.paused ? "Resume Sync" : "Pause Sync") { folder.setPaused(!folder.config.paused) }
                .controlSize(.large)
            Button(folder.session == nil ? "Connect" : "Sync Now") { folder.syncNow() }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(folder.config.paused || folder.statusKind == .busy)
        }
    }

    private func callout(_ text: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: folder.statusSymbol).foregroundStyle(folder.statusKind.color)
                Text(text).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
            }
            StatusActions(folder: folder, open: openSettings)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(folder.statusKind.color.opacity(0.08)))
    }

    // MARK: Tiles

    private func tiles(now: Date) -> some View {
        let r = folder.lastReport
        var extra: [String] = []
        if let r, r.merged > 0 { extra.append(plural(r.merged, "merge")) }
        if let r, !r.conflicts.isEmpty { extra.append(plural(r.conflicts.count, "conflict copy", "conflict copies")) }
        if let r, r.reencrypted > 0 { extra.append("\(r.reencrypted) re-encrypted") }
        let oldest = queue.map(\.queuedAt).min()
        return Grid(horizontalSpacing: 12) {
            GridRow {
                Tile(label: "Last sync", value: folder.lastSync.map { relative($0, to: now, capitalized: true) } ?? "Never",
                     detail: folder.lastSync?.formatted(date: .abbreviated, time: .standard) ?? "No sync on this Mac yet", systemImage: "clock")
                Tile(label: "Last run", value: r.map { "\($0.pushed) ↑  \($0.pulled) ↓" } ?? "—",
                     detail: runDetail(r, extra), systemImage: "arrow.up.arrow.down")
                Tile(label: "Files in sync", value: folder.session == nil && folder.fileCount == 0 ? "—" : folder.fileCount.formatted(),
                     detail: "Full device", systemImage: "doc.on.doc")
                Tile(label: "Waiting to upload", value: folder.engine == nil ? "—" : queue.count.formatted(),
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
        Card(title: "Waiting to upload", count: folder.engine == nil ? nil : plural(queue.count, "change")) {
            if folder.engine == nil {
                note("Connect to see the changes waiting on this Mac.")
            } else if queue.isEmpty {
                note("Nothing: every noted change is uploaded.")
            } else {
                VStack(spacing: 0) {
                    ForEach(queue.prefix(12)) { c in
                        HStack {
                            Image(systemName: "doc").foregroundStyle(.secondary)
                            Text(c.path).lineLimit(1).truncationMode(.middle)
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
            note("Changes made while the app wasn't running are found at the next sync.")
        }
    }

    private var deviceCard: some View {
        Card(title: "This Mac") {
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 8) {
                KeyValue(label: "Device") { Text(folder.config.deviceName) }
                KeyValue(label: "Folder") {
                    HStack(spacing: 6) {
                        Text(folder.config.path).lineLimit(1).truncationMode(.middle).help(folder.config.path)
                        Button { NSWorkspace.shared.activateFileViewerSelecting([folder.config.url]) } label: {
                            Image(systemName: "arrow.up.forward.square")
                        }.buttonStyle(.borderless).help("Show in Finder")
                    }
                }
                KeyValue(label: "Server") { Text(folder.config.endpoint).lineLimit(1).truncationMode(.middle) }
                KeyValue(label: "Vault") { Text(folder.config.vaultName) }
                KeyValue(label: "Encryption key") {
                    if let k = folder.keyInfo { Fingerprint(value: k.fingerprint) } else { Text("None").foregroundStyle(.secondary) }
                }
                KeyValue(label: "Mode") { Text("Full device") }
                KeyValue(label: "Recovery key") {
                    if let r = folder.recoveryState {
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

    // MARK: Keys

    private var keysCard: some View {
        Card(title: "Vault keys", count: keys.map { plural($0.count, "key") }) {
            if !folder.pendingApprovals.isEmpty {
                ForEach(folder.pendingApprovals) { p in
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
                note(folder.session == nil ? "Connect to see the keys of this vault." : "Loading…")
            }
        }
    }

    private var problemsCard: some View {
        Card(title: "Recent problems", count: nil) {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(folder.lastReport?.conflicts ?? [], id: \.self) { c in
                    Label("Conflict copy: \(c)", systemImage: "doc.on.doc").font(.callout)
                }
                ForEach(Array(folder.warnings.suffix(8).enumerated()), id: \.offset) {
                    Label($0.element, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.secondary)
                }
            }
        }
    }

    private func note(_ s: String) -> some View {
        Text(s).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }

    private func reload() async {
        queue = await folder.queuedChanges()
        guard folder.session != nil else { return }
        do {
            keys = try await folder.vaultKeys()
            keysError = nil
        } catch {
            keysError = "\(error)"
        }
    }
}
