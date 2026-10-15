import AppKit
import SwiftUI
import SyncryptionAppCore
import SyncryptionSync

/// Browse a file's revisions, save an old version, or restore it on every device.
struct HistoryTab: View {
    let folder: FolderController
    @State private var paths: [String] = []
    @State private var deleted: [String] = []
    @State private var showDeleted = false
    @State private var search = ""
    @State private var selected: String?
    @State private var entries: [HistoryEntry] = []
    @State private var next: Int?
    @State private var rejected = 0
    @State private var names: [String: String] = [:]
    @State private var chosen: Int?
    @State private var error: String?
    @State private var info: String?
    @State private var busy = false

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 8) {
                TextField("Search files", text: $search).textFieldStyle(.roundedBorder)
                Picker("", selection: $showDeleted) {
                    Text("Files").tag(false)
                    Text("Deleted").tag(true)
                }
                .pickerStyle(.segmented).labelsHidden()
                List(filtered, id: \.self, selection: $selected) { p in
                    Label { Text(p).lineLimit(1).truncationMode(.middle) } icon: { Image(systemName: showDeleted ? "trash" : "doc") }
                }
                .listStyle(.bordered(alternatesRowBackgrounds: true))
                .frame(maxHeight: .infinity)
                Text(plural(filtered.count, "file")).font(.caption).foregroundStyle(.secondary)
            }
            .frame(width: 270)
            VStack(alignment: .leading, spacing: 10) {
                if let path = selected {
                    HStack {
                        Text(path).font(.headline).lineLimit(2)
                        Spacer()
                        Text(entries.isEmpty ? "" : plural(entries.count, "version")).foregroundStyle(.secondary)
                    }
                    Table(entries, selection: $chosen) {
                        TableColumn("Version") { Text(Date(timeIntervalSince1970: Double($0.mtime) / 1000).formatted(date: .abbreviated, time: .shortened)) }
                        TableColumn("Stored") { Text(shortDate($0.createdAt)) }
                        TableColumn("Size") { e in Text(e.deleted ? "deleted" : ByteCountFormatter.string(fromByteCount: Int64(e.size), countStyle: .file)) }
                        TableColumn("Device") { Text(names[$0.device] ?? $0.device) }
                    }
                    if rejected > 0 { Text("\(rejected) versions failed their integrity check and are left out.").font(.caption).foregroundStyle(.orange) }
                    HStack {
                        if next != nil { Button("Load Older") { Task { await loadHistory(path, more: true) } } }
                        Spacer()
                        Button("Save a Copy…") { saveCopy(path) }.disabled(chosenEntry.map { $0.deleted } ?? true || busy)
                        Button("Restore This Version") { restore(path) }.disabled(chosenEntry.map { $0.deleted } ?? true || busy)
                    }
                } else {
                    VStack(spacing: 8) {
                        Image(systemName: "clock.arrow.circlepath").font(.largeTitle).foregroundStyle(.tertiary)
                        Text("Choose a file to see its versions.").foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                if let info { Text(info).font(.callout) }
                ErrorText(text: error)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .task { await loadPaths() }
        .onChange(of: selected) { _, p in if let p { Task { await loadHistory(p, more: false) } } }
        .onChange(of: showDeleted) { _, _ in selected = nil }
    }

    private var filtered: [String] {
        let list = showDeleted ? deleted : paths
        return search.isEmpty ? list : list.filter { $0.localizedCaseInsensitiveContains(search) }
    }

    private var chosenEntry: HistoryEntry? { entries.first { $0.rev == chosen } }

    private func loadPaths() async {
        do {
            paths = try await folder.syncedPaths()
            deleted = try await folder.deletedPaths()
            names = await folder.deviceNames()
            error = nil
        } catch {
            self.error = "\(error)"
        }
    }

    private func loadHistory(_ path: String, more: Bool) async {
        do {
            let page = try await folder.history(path, before: more ? next : nil)
            entries = more ? entries + page.entries : page.entries
            rejected = more ? rejected + page.rejected : page.rejected
            next = page.next
            if !more { chosen = entries.first(where: { !$0.deleted })?.rev }
            error = nil
        } catch {
            self.error = "\(error)"
        }
    }

    private func saveCopy(_ path: String) {
        guard let rev = chosen else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = (path as NSString).lastPathComponent
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        Task {
            do {
                guard let data = try await folder.readRevision(path, rev: rev) else { throw NSError(domain: "deleted", code: 0) }
                try Data(data).write(to: url)
                info = "Saved."
                error = nil
            } catch {
                self.error = "\(error)"
            }
            busy = false
        }
    }

    private func restore(_ path: String) {
        guard let rev = chosen else { return }
        busy = true
        Task {
            do {
                try await folder.restore(path, rev: rev)
                info = "Restored on every device."
                error = nil
                await loadPaths()
                await loadHistory(path, more: false)
            } catch {
                self.error = "\(error)"
            }
            busy = false
        }
    }
}
