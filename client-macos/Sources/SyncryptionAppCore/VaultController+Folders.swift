import AppKit
import Foundation
import SyncryptionAPI
import SyncryptionCrypto
import SyncryptionStore
import SyncryptionSync

/// The vault's top-level folders, and which of them this Mac syncs where.
extension VaultController {
    /// Another active device of the vault: a column of the folder table.
    public struct OtherDevice: Identifiable, Equatable, Sendable {
        public let id: String
        public let name: String
        public let lastSeenAt: String?
    }

    /// One top-level folder of the vault.
    public struct VaultFolder: Identifiable, Equatable, Sendable {
        public var id: String { name }
        public let name: String
        /// Live files in the vault, and their plaintext size.
        public let files: Int
        public let size: Int
        /// This Mac's mapping, if it syncs the folder.
        public let mapping: FolderMapping?
        /// The local folder on each other device that syncs it, by device id.
        public let elsewhere: [String: String]

        public init(name: String, files: Int, size: Int, mapping: FolderMapping?, elsewhere: [String: String]) {
            self.name = name
            self.files = files
            self.size = size
            self.mapping = mapping
            self.elsewhere = elsewhere
        }

        /// No device syncs it: it can be deleted from the vault.
        public var isUnmapped: Bool { mapping == nil && elsewhere.isEmpty }
    }

    /// Whether one of this Mac's folders is synced here: `active` unless paused, missing or
    /// not mapped.
    public enum FolderState: Equatable, Sendable {
        case active, paused, missing, notMapped
    }

    public func folderState(_ name: String) -> FolderState {
        guard let f = config.folder(name) else { return .notMapped }
        if f.paused { return .paused }
        return folderProblems[name] == nil ? .active : .missing
    }

    /// Store this Mac's folders on the server, encrypted, when they changed or the vault key
    /// was rotated since. One upload at a time, so an older list never lands last.
    func publishFolders() async {
        guard !publishing else { return }
        publishing = true
        defer { publishing = false }
        while let session {
            let wanted = Published(epoch: session.keyring.currentEpoch,
                                   folders: config.folders.map { DeviceMeta.Folder(name: $0.name, path: $0.path) })
            guard published != wanted else { return }
            do {
                try await session.publishFolders(wanted.folders)
                published = wanted
            } catch is ConnectionError {
                return  // tried again after the next sync
            } catch is CancellationError {
                return
            } catch {
                warn("Couldn't store this Mac's folder list on the server (\(error)).")
                return
            }
        }
    }

    /// Read the vault's folders and every device's mappings again.
    public func refreshFolders() async {
        guard let session, let engine else { return }
        let me = await session.deviceId()
        let remote = (try? await engine.remoteFolders()) ?? [:]
        guard let devices = try? await session.deviceFolders() else { return }
        otherDevices = devices.filter { $0.device.id != me }.map { OtherDevice(id: $0.device.id, name: $0.device.name, lastSeenAt: $0.device.lastSeenAt) }
        var elsewhere: [String: [String: String]] = [:]
        for d in devices where d.device.id != me {
            for f in d.folders ?? [] { elsewhere[f.name, default: [:]][d.device.id] = f.path }
        }
        var names = Set(remote.keys).union(config.folders.map(\.name)).union(elsewhere.keys)
        names = names.filter(PathFilter.isFolderName)
        vaultFolders = names.sorted { $0.localizedStandardCompare($1) == .orderedAscending }.map { name in
            VaultFolder(name: name, files: remote[name]?.files ?? 0, size: remote[name]?.size ?? 0, mapping: config.folder(name),
                        elsewhere: elsewhere[name] ?? [:])
        }
    }

    private func check(name: String, path: String, mapping existing: Bool) throws {
        let taken = existing ? config.folders.map(\.name) : vaultFolders.map(\.name) + config.folders.map(\.name)
        try ConfigStore.checkFolder(name: name, path: path, taken: taken, vaults: allVaults())
    }

    /// Add a local folder to the vault as a new top-level folder with its name.
    public func addFolder(path: String) throws {
        let url = URL(filePath: path).standardizedFileURL
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue else {
            throw ControllerError("Choose an existing folder.")
        }
        let name = url.lastPathComponent.precomposedStringWithCanonicalMapping
        try check(name: name, path: url.path, mapping: false)
        changeFolders { $0.append(FolderMapping(name: name, path: url.path)) }
    }

    /// Where mapping `name` into `parent` puts it.
    public nonisolated static func mappedPath(_ name: String, in parent: String) -> String {
        URL(filePath: parent).standardizedFileURL.appending(path: name).path
    }

    /// Whether a folder exists and has files the user should decide about.
    public nonisolated static func hasFiles(_ path: String) -> Bool {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []
        return names.contains { $0 != ".DS_Store" && $0 != "Icon\r" }
    }

    /// Sync the vault folder `name` with `<parent>/<name>` on this Mac, creating it if needed.
    /// If it already has files they are merged with the vault's: ask the user first
    /// (`hasFiles`).
    public func mapFolder(_ name: String, parent: String) throws {
        let path = Self.mappedPath(name, in: parent)
        try check(name: name, path: path, mapping: true)
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        changeFolders { $0.append(FolderMapping(name: name, path: path)) }
    }

    /// Stop syncing `name` on this Mac. Its files stay in the vault and on other devices; here
    /// they stay in place, or with `keepFiles` false the local folder goes to the Trash.
    public func unmapFolder(_ name: String, keepFiles: Bool) async throws {
        guard let f = config.folder(name) else { return }
        // Nothing of it may be pushed later, deletions included: stop the engine first.
        if let engine { await engine.close() }
        if f.showsFolderIcon && FileManager.default.fileExists(atPath: f.path) { FolderIcon.remove(from: f.url) }
        try (session?.store ?? SQLiteStore(url: configs.stateURL(config.id))).forget(folder: name)
        if !keepFiles && FileManager.default.fileExists(atPath: f.path) { try FileManager.default.trashItem(at: f.url, resultingItemURL: nil) }
        changeFolders { $0.removeAll { $0.name.utf8.elementsEqual(name.utf8) } }
    }

    /// Delete the vault folder `name` and its files for every device. Only for a folder no
    /// device syncs.
    @discardableResult
    public func deleteFromVault(_ name: String) async throws -> Int {
        await rebuild?.value
        let engine = try connectedEngine()
        await refreshFolders()
        guard let folder = vaultFolders.first(where: { $0.name.utf8.elementsEqual(name.utf8) }), folder.isUnmapped else {
            throw ControllerError("A device still syncs \(name). It can be deleted from the vault once no device does.")
        }
        let n = try await engine.deleteFolder(name)
        await refreshFolders()
        return n
    }

    public func setFolderPaused(_ name: String, _ paused: Bool) {
        changeFolders { folders in
            if let i = folders.firstIndex(where: { $0.name.utf8.elementsEqual(name.utf8) }) { folders[i].paused = paused }
        }
    }

    public func updateExclude(_ name: String, _ text: String) {
        changeFolders { folders in
            if let i = folders.firstIndex(where: { $0.name.utf8.elementsEqual(name.utf8) }) { folders[i].exclude = text }
        }
    }

    /// Show or hide the synced-folder icon on one folder in Finder.
    public func setShowsFolderIcon(_ name: String, _ on: Bool) {
        guard let i = config.folders.firstIndex(where: { $0.name.utf8.elementsEqual(name.utf8) }) else { return }
        var folders = config.folders
        folders[i].showsFolderIcon = on
        setFoldersWithoutRestart(folders)
        updateFolderIcons()
    }
}
