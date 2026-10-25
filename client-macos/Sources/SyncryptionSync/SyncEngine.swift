import Foundation
import SyncryptionAPI
import SyncryptionCrypto
import SyncryptionStore

/// The sync engine (docs/architecture.md 4.2): pull the change feed, scan local files, push
/// the outbox, merge when both sides changed, and re-encrypt files after a key rotation. A
/// port of client-obsidian-plugin/src/sync/engine.ts, for a plain folder (no Obsidian config folder, no
/// remote-only content).

/// How often one sync pushes again after merges queued new changes.
private let maxPushRounds = 5
/// Statuses that refuse one file's upload, not the whole sync.
private let refused: Set<Int> = [400, 413, 422]

public struct SyncReport: Sendable, Equatable {
    public var pulled = 0
    public var pushed = 0
    public var merged = 0
    public var conflicts: [String] = []
    /// Remote revisions that failed their integrity checks and were skipped.
    public var rejected = 0
    /// Files committed again under the current epoch after a rotation.
    public var reencrypted = 0
    /// Packages whose changes wait, by path.
    public var held: [String: HoldReason] = [:]
    public init() {}
}

/// Why the changes of a package (a folder macOS shows as one file) wait. A package is synced
/// as one unit, so its app never sees it half updated.
public enum HoldReason: Sendable, Equatable {
    /// Something in it changed less than the quiet period ago.
    case settling(until: Date)
    /// The process `pid` has a file in it open.
    case inUse(pid: Int32)
    /// Another device is uploading it.
    case uploading(device: String)
}

/// How far a sync is.
public enum SyncProgress: Sendable {
    /// `done` revisions of the change feed read, the last one `rev`, and `path` while that
    /// revision's file is being received.
    case pull(done: Int, rev: Int, path: String?)
    case scan(done: Int, total: Int)
    /// `path`: the queued file being pushed.
    case push(done: Int, total: Int, path: String)
    /// The file being received or uploaded: `done` of its `total` bytes, one chunk at a time.
    case file(path: String, done: Int, total: Int)
}

/// One revision of a file, from its encrypted metadata.
public struct HistoryEntry: Sendable, Equatable, Identifiable {
    public var id: Int { rev }
    public let rev: Int
    /// When the server stored it. Not authenticated, only for display.
    public let createdAt: String
    public let deleted: Bool
    public let size: Int
    public let mtime: Int
    /// The id of the device that wrote it.
    public let device: String
}

public struct HistoryPage: Sendable {
    /// Newest first.
    public let entries: [HistoryEntry]
    /// Pass as `before` to get the next, older page. Nil on the last page.
    public let next: Int?
    /// Revisions that failed their integrity checks and were left out.
    public let rejected: Int
}

/// The keyring the engine follows: the change feed carries the server's keyring version,
/// and a newer one is fetched and checked before any change is applied (crypto.md 8.4).
public protocol KeyringSource: Sendable {
    func version() async -> Int
    func refresh() async throws
}

public struct SyncStopped: Error, CustomStringConvertible {
    public let description = "Sync stopped."
}

public struct EngineOptions: Sendable {
    public var api: ApiClient
    public var vaultId: String
    public var cipher: VaultCipher
    public var fs: any VaultFs
    public var store: any SyncStore
    /// This device's id, recorded in every revision's metadata.
    public var deviceId: String
    /// Used in conflict-copy names.
    public var deviceName: String
    public var filter: PathFilter
    public var keyring: (any KeyringSource)?
    public var now: @Sendable () -> Date = { Date() }
    /// Problems that skip one file but don't stop the sync. Never gets plaintext.
    public var onWarning: @Sendable (String) -> Void = { _ in }
    public var onProgress: @Sendable (SyncProgress) -> Void = { _ in }
    /// Waits before each retry of a chunk download that failed to reach the server.
    public var blobRetries: [Duration] = [.seconds(1), .seconds(4)]
    /// How long nothing in a package must change before it is uploaded.
    public var quietPeriod: Duration = .seconds(30)
    /// The lease, in seconds, of the lock held on a package while it is uploaded.
    public var lockTtl = 120

    public init(api: ApiClient, vaultId: String, cipher: VaultCipher, fs: any VaultFs, store: any SyncStore, deviceId: String,
                deviceName: String, filter: PathFilter, keyring: (any KeyringSource)? = nil)
    {
        self.api = api
        self.vaultId = vaultId
        self.cipher = cipher
        self.fs = fs
        self.store = store
        self.deviceId = deviceId
        self.deviceName = deviceName
        self.filter = filter
        self.keyring = keyring
    }
}

private struct LocalFile {
    var exists: Bool
    var stat: FileStat?
    /// Set when the file exists and was read.
    var data: Bytes?
    var sha256: String
}

/// A remote change for a package a process has open here: it is written once it is closed.
private struct PackageInUse: Error {}
/// A package file's commit found a newer head: another device changed the package too.
private struct PackageChanged: Error {}

public actor SyncEngine {
    private let o: EngineOptions
    private var running: Task<SyncReport, any Error>?
    private var again = false
    private var forced = false
    private var report = SyncReport()
    private var closed = false
    private var pullDone = 0
    /// Whether each package has local changes, and which process has it open (if one
    /// does), found once per pull.
    private var packageDirty: [PathKey: Bool] = [:]
    private var packageHolder: [PathKey: Int32?] = [:]
    /// The holder id of this engine's locks (protocol.md 11).
    private let clientId = Primitives.random(16).b64u

    public init(_ options: EngineOptions) { o = options }

    /// Stop for good: a running sync is cancelled with its requests in flight, and this
    /// returns once it has stopped. Nothing is written or committed after that.
    public func close() async {
        closed = true
        guard let running else { return }
        running.cancel()
        _ = try? await running.value
    }

    private func checkOpen() throws {
        if closed { throw SyncStopped() }
        try Task.checkCancellation()
    }

    /// Pull, scan, push. Calls made while a sync is running are folded into one more run
    /// after it, so changes made during a sync are never missed.
    /// With `force` (the user asked for it), packages don't wait for their quiet period, but
    /// still wait while a process has them open.
    @discardableResult
    public func sync(force: Bool = false) async throws -> SyncReport {
        try checkOpen()
        if force { forced = true }
        if let running {
            again = true
            return try await running.value
        }
        let task = Task { () throws -> SyncReport in
            defer {
                self.running = nil
                self.report = SyncReport()
                self.forced = false
            }
            repeat {
                self.again = false
                try await self.pull()
                try await self.adopt()
                try await self.scan()
                try await self.push()
                try await self.reencrypt()
            } while self.again
            return self.report
        }
        running = task
        return try await task.value
    }

    /// How many files are in sync: those with a synced state that isn't a deletion.
    public func fileCount() throws -> Int { try o.store.countFiles() }

    /// The plaintext size of the files in sync, in bytes.
    public func totalSize() throws -> Int { try o.store.totalSize() }

    /// Synced paths that exist (not deletions), sorted: the files with a history to browse.
    public func syncedPaths() throws -> [String] {
        try o.store.files().filter { !$0.value.deleted && o.filter.includes($0.key.path) }.map(\.key.path).sorted()
    }

    /// Note a local change from a file event. The next sync pushes it. Returns true for a
    /// change inside a package, which waits for the package's quiet period anyway.
    @discardableResult
    public func noteChange(_ path: String) throws -> Bool {
        guard o.filter.includes(path) else { return false }
        try o.store.enqueue(path)
        return o.fs.packageRoot(path) != nil
    }

    /// The package `path` is in, if any (see `VaultFs.packageRoot`).
    public nonisolated func packageRoot(_ path: String) -> String? { o.fs.packageRoot(path) }

    /// The local changes waiting to be pushed, oldest first.
    public func pending() throws -> [OutboxEntry] { try o.store.outbox() }

    /// Synced paths whose last revision is a deletion, sorted: the files that can be restored.
    public func deletedPaths() throws -> [String] {
        try o.store.files().filter { $0.value.deleted && o.filter.includes($0.key.path) }.map(\.key.path).sorted()
    }

    /// One page of the revisions of `path`, newest first.
    public func history(_ path: String, before: Int? = nil) async throws -> HistoryPage {
        let fileId = try o.cipher.fileId(path)
        let page = try await o.api.revisions(o.vaultId, fileId, before: before)
        var entries: [HistoryEntry] = []
        var rejected = 0
        for r in page.revisions {
            guard let meta = try? o.cipher.openMeta(fileId: fileId, meta: r.meta) else {
                rejected += 1
                continue
            }
            entries.append(HistoryEntry(rev: r.rev, createdAt: r.createdAt, deleted: meta.deleted, size: meta.size, mtime: meta.mtime,
                                        device: meta.device))
        }
        return HistoryPage(entries: entries, next: page.more ? page.revisions.last?.rev : nil, rejected: rejected)
    }

    public struct NotKept: Error, CustomStringConvertible {
        public let description = "This version is no longer kept on the server."
    }

    /// The content of revision `rev` of `path`, or nil for a deletion.
    public func readRevision(_ path: String, rev: Int) async throws -> Bytes? {
        do { return try await content(try o.cipher.fileId(path), rev: rev) } catch let e as ApiError where e.status == 404 {
            throw NotKept()
        }
    }

    public struct RestoreError: Error, CustomStringConvertible {
        public let description: String
    }

    /// Commit the content of revision `rev` as the new head of `path`. A sync runs first, so
    /// local edits are pushed and stay in the history.
    public func restore(_ path: String, rev: Int) async throws {
        guard o.filter.includes(path) else { throw RestoreError(description: "This file isn't synced.") }
        try await sync()
        guard let data = try await readRevision(path, rev: rev) else {
            throw RestoreError(description: "This revision is a deletion and can't be restored.")
        }
        try o.fs.write(path, data, mtime: now(), ctime: nil)
        try o.store.enqueue(path)
        try await sync()
    }

    // MARK: Pull

    /// Apply every remote change since the cursor.
    func pull() async throws {
        var cursor = try o.store.meta(MetaKey.cursor, as: Int.self) ?? 0
        let earlier = try o.store.meta(MetaKey.failed, as: [Revision].self) ?? []
        var failed: [Revision] = []
        pullDone = 0
        packageDirty = [:]
        packageHolder = [:]
        while true {
            let page = try await o.api.changes(o.vaultId, since: cursor)
            if let k = o.keyring, page.keyringVersion > (await k.version()) { try await k.refresh() }
            for r in page.changes {
                try checkOpen()
                try await applyOrKeep(r, &failed)
                pullDone += 1
                o.onProgress(.pull(done: pullDone, rev: r.rev, path: nil))
            }
            // Saved before the cursor moves past them, so they aren't lost if the sync stops here.
            try o.store.setMeta(MetaKey.failed, earlier + failed)
            cursor = page.cursor
            try o.store.setMeta(MetaKey.cursor, cursor)
            if !page.more { break }
        }
        // After the feed: a newer revision of the same file makes an older failure moot.
        for r in earlier { try await applyOrKeep(r, &failed, first: false) }
        try o.store.setMeta(MetaKey.failed, failed)
        try await resolvePackageConflicts()
    }

    /// Apply the remote files of folders synced here that the feed skipped while they weren't
    /// (a folder just mapped or resumed): the remote index has their latest revisions.
    func adopt() async throws {
        guard let current = o.filter.folderNames else { return }
        let before = Set((try o.store.meta(MetaKey.syncedFolders, as: [String].self) ?? []).map(PathKey.init))
        let added = current.filter { !before.contains(PathKey($0)) }.map { Array(($0 + "/").utf8) }
        if added.isEmpty {
            try o.store.setMeta(MetaKey.syncedFolders, current)
            return
        }
        let synced = try o.store.files()
        var failed: [Revision] = []
        for (path, r) in try o.store.remoteFiles().sorted(by: { $0.value.rev < $1.value.rev })
            where o.filter.includes(path.path) && added.contains(where: { path.path.utf8.starts(with: $0) })
        {
            if let s = synced[path] { if r.rev <= s.rev { continue } } else if r.deleted { continue }
            guard let revision = try? JSONDecoder().decode(Revision.self, from: r.revision) else { continue }
            try await applyOrKeep(revision, &failed)
        }
        if !failed.isEmpty {
            try o.store.setMeta(MetaKey.failed, (try o.store.meta(MetaKey.failed, as: [Revision].self) ?? []) + failed)
        }
        try o.store.setMeta(MetaKey.syncedFolders, current)
        try await resolvePackageConflicts()
    }

    /// Remember `revision` as the latest of `path` in the remote index.
    private func noteRemote(_ path: String, _ revision: Revision, _ meta: FileMeta) throws {
        if let known = try o.store.remoteFile(path), known.rev >= revision.rev { return }
        try o.store.putRemote(path, RemoteFile(rev: revision.rev, deleted: meta.deleted, size: meta.size,
                                               revision: try JSONEncoder().encode(revision)))
    }

    /// The top-level folders of the vault that have files, with how many and their size.
    public func remoteFolders() throws -> [String: (files: Int, size: Int)] {
        var out: [String: (files: Int, size: Int)] = [:]
        for (path, r) in try o.store.remoteFiles() where !r.deleted {
            guard let slash = path.path.firstIndex(of: "/") else { continue }
            let name = String(path.path[..<slash])
            out[name, default: (0, 0)].files += 1
            out[name, default: (0, 0)].size += r.size
        }
        return out
    }

    public struct FolderSynced: Error, CustomStringConvertible {
        public let description = "This folder is synced on this Mac. Unmap it first."
    }

    /// Delete every file of the top-level folder `name` in the vault, for every device. Only
    /// for a folder this Mac doesn't sync. Returns how many files were deleted.
    @discardableResult
    public func deleteFolder(_ name: String) async throws -> Int {
        let prefix = Array((name + "/").utf8)
        var deleted = 0
        for (path, r) in try o.store.remoteFiles() where !r.deleted && path.path.utf8.starts(with: prefix) {
            if o.filter.includes(path.path) { throw FolderSynced() }
            try checkOpen()
            var parent = r.rev
            for _ in 0..<3 {
                let t = now()
                let sealed = try o.cipher.seal(path: path.path, data: nil, mtime: t, ctime: t, device: o.deviceId)
                let fileId = try o.cipher.fileId(path.path)
                do {
                    let revision = try await o.api.commit(o.vaultId, fileId, CommitRequest(blobs: [], deleted: true, meta: sealed.meta,
                                                                                           parentRev: parent))
                    try noteRemote(path.path, revision, try o.cipher.openMeta(fileId: fileId, meta: revision.meta))
                    deleted += 1
                    break
                } catch let e as ApiError where e.code == "stale_parent" {
                    // Written again since: delete the newer head, unless it is a deletion already.
                    guard let head = e.details["head"], head != .null, let h = try? decodeRevision(head),
                          let meta = try? o.cipher.openMeta(fileId: fileId, meta: h.meta) else { break }
                    try noteRemote(path.path, h, meta)
                    if meta.deleted { break }
                    parent = h.rev
                }
            }
        }
        return deleted
    }

    /// Stop syncing the top-level folder `name` here: forget its synced state and queued
    /// changes, so nothing is pushed for it. Its files stay in the vault.
    public func forgetFolder(_ name: String) throws { try o.store.forget(folder: name) }

    /// Apply a remote revision. If writing it here fails (a name the disk refuses, or one that
    /// clashes with another file's), keep it to try again on the next pull, and warn the first
    /// time. A revision the server has pruned since (a 404) is replaced by the file's head.
    private func applyOrKeep(_ revision: Revision, _ failed: inout [Revision], first: Bool = true) async throws {
        var current = revision
        do {
            do { try await applyRemote(revision) } catch let e as ApiError where e.status == 404 {
                let head = try await o.api.head(o.vaultId, revision.fileId)
                if head.rev == revision.rev { throw e }
                current = head
                try await applyRemote(head)
            }
        } catch let e where e is ApiError || e is ConnectionError || e is SyncStopped || e is KeyringError || e is CancellationError {
            throw e
        } catch is PackageInUse {
            failed.append(current)
        } catch {
            failed.append(current)
            if first {
                o.onWarning("Couldn't write a remote change here (revision \(current.rev)): \(error). It is tried again on every sync.")
            }
        }
    }

    // MARK: Scan

    /// Queue every local difference from the last synced state (startup and fallback).
    func scan() async throws {
        let synced = try o.store.files()
        var present = Set<PathKey>()
        let files = try o.fs.list(skip: o.filter.skipsFolder).filter { o.filter.includes($0.path) }
        for (i, file) in files.enumerated() {
            try checkOpen()
            o.onProgress(.scan(done: i, total: files.count))
            present.insert(PathKey(file.path))
            let s = synced[PathKey(file.path)]
            if let s, !s.deleted, s.size == file.stat.size, s.mtime == file.stat.mtime { continue }
            let local = try local(file.path, withData: false)
            if let s, !s.deleted, local.sha256 == s.sha256 {
                // Touched but not changed: remember the new mtime so it isn't hashed again.
                var updated = s
                updated.mtime = file.stat.mtime
                try o.store.putFile(file.path, updated)
            } else {
                try o.store.enqueue(file.path)
            }
        }
        for (path, s) in synced where !s.deleted && !present.contains(path) && o.filter.includes(path.path) {
            try o.store.enqueue(path.path)
        }
    }

    // MARK: Push

    /// Commit every queued path. A merge after a `409` queues the result for the next round.
    /// The files of a package are committed together, once it is quiet and not in use.
    func push() async throws {
        for _ in 0..<maxPushRounds {
            let entries = try o.store.outbox().filter { e in
                !report.held.keys.contains { inside(e.path, $0) }
            }
            if entries.isEmpty { return }
            var plain: [OutboxEntry] = []
            var packages: [String: [OutboxEntry]] = [:]
            for e in entries {
                if let p = o.fs.packageRoot(e.path) { packages[p, default: []].append(e) } else { plain.append(e) }
            }
            var done = 0
            for entry in plain {
                try checkOpen()
                o.onProgress(.push(done: done, total: entries.count, path: entry.path))
                done += 1
                try await pushEntry(entry)
            }
            let holders = packages.isEmpty ? [:] : o.fs.holders(Array(packages.keys))
            for (package, list) in packages.sorted(by: { $0.key < $1.key }) {
                if let reason = holdReason(package, holders) {
                    report.held[package] = reason
                    continue
                }
                try await pushPackage(package, list, done: &done, total: entries.count)
            }
        }
    }

    /// Push one queued path and dequeue it. Returns what it committed, if anything.
    @discardableResult
    private func pushEntry(_ entry: OutboxEntry, inPackage: Bool = false) async throws -> Committed? {
        let committed: Committed?
        do { committed = try await pushPath(entry.path, inPackage: inPackage) } catch let e as ApiError where refused.contains(e.status) {
            // A request the server refuses for this file only: keep it queued, go on.
            o.onWarning("Couldn't upload a file (\(e.code)). It stays queued.")
            return nil
        }
        try o.store.dequeue(entry)
        return committed
    }

    // MARK: Packages

    private func inside(_ path: String, _ dir: String) -> Bool { path.utf8.starts(with: (dir + "/").utf8) }

    private var quietMs: Int {
        let c = o.quietPeriod.components
        return Int(c.seconds) * 1000 + Int(c.attoseconds / 1_000_000_000_000_000)
    }

    /// Why `package` must wait now, or nil if it can be uploaded.
    private func holdReason(_ package: String, _ holders: [String: Int32]) -> HoldReason? {
        if let pid = holders[package] { return .inUse(pid: pid) }
        if !forced, let last = o.fs.lastChange(in: package), last + quietMs > now() {
            return .settling(until: Date(timeIntervalSince1970: Double(last + quietMs) / 1000))
        }
        return nil
    }

    /// Commit the queued files of `package` under a lock on it, so two devices never
    /// interleave their uploads of one package.
    private func pushPackage(_ package: String, _ entries: [OutboxEntry], done: inout Int, total: Int) async throws {
        let lockId = try o.cipher.fileId(package)
        do { try await o.api.acquireLock(o.vaultId, lockId, clientId: clientId, ttl: o.lockTtl) } catch let e as ApiError
            where e.status == 423
        {
            var device = "another device"
            if case .object(let lock)? = e.details["lock"], case .string(let name)? = lock["deviceName"] { device = name }
            report.held[package] = .uploading(device: device)
            return
        }
        do {
            try await pushLocked(package, lockId, done: &done, total: total)
        } catch {
            try? await o.api.releaseLock(o.vaultId, lockId, clientId: clientId)
            throw error
        }
        try? await o.api.releaseLock(o.vaultId, lockId, clientId: clientId)
    }

    private func pushLocked(_ package: String, _ lockId: String, done: inout Int, total: Int) async throws {
        // What was committed just before the lock: changed there too, the pull resolves it.
        try await pull()
        if try conflicts().contains(PathKey(package)) { return }
        let entries = try o.store.outbox().filter { inside($0.path, package) }
        var committed: [Committed] = []
        var renewed = ContinuousClock.now
        for entry in entries {
            try checkOpen()
            o.onProgress(.push(done: done, total: total, path: entry.path))
            done += 1
            if ContinuousClock.now - renewed > .seconds(o.lockTtl / 2) {
                try await o.api.acquireLock(o.vaultId, lockId, clientId: clientId, ttl: o.lockTtl)
                renewed = .now
            }
            do {
                if let c = try await pushEntry(entry, inPackage: true) { committed.append(c) }
            } catch is PackageChanged {
                // Another device committed into the package without its lock. Take back what
                // this round committed, so the vault holds that device's package unmixed, and
                // let the pull move this one to a conflict copy.
                try setConflicts(try conflicts().map(\.path) + [package])
                for c in committed.reversed() { try await revert(c) }
                try await pull()
                return
            }
        }
    }

    /// A commit of `path` from `parent` (nil: a new file) to `rev`.
    private struct Committed {
        let path: String
        let fileId: String
        let parent: Int?
        let rev: Int
    }

    /// Commit the content `c` replaced again on top of it: a deletion for a new file. Nothing
    /// if the file has a newer head again, or its parent is no longer kept.
    private func revert(_ c: Committed) async throws {
        let data: Bytes?
        if let parent = c.parent {
            do { data = try await content(c.fileId, rev: parent) } catch let e as ApiError where e.status == 404 { return }
        } else {
            data = nil
        }
        let t = now()
        let sealed = try o.cipher.seal(path: c.path, data: data, mtime: t, ctime: t, device: o.deviceId)
        let missing = Set(try await o.api.missingBlobs(o.vaultId, sealed.chunks.map(\.id)))
        for chunk in sealed.chunks where missing.contains(chunk.id) {
            try checkOpen()
            try await o.api.putBlob(o.vaultId, chunk.id, Data(chunk.object))
        }
        do {
            _ = try await o.api.commit(o.vaultId, c.fileId, CommitRequest(blobs: sealed.chunks.map(\.id), deleted: data == nil,
                                                                          meta: sealed.meta, parentRev: c.rev))
        } catch let e as ApiError where e.code == "stale_parent" {}
    }

    private func conflicts() throws -> [PathKey] {
        (try o.store.meta(MetaKey.packageConflicts, as: [String].self) ?? []).map(PathKey.init)
    }

    private func setConflicts(_ list: [String]) throws {
        var seen = Set<PathKey>()
        try o.store.setMeta(MetaKey.packageConflicts, list.filter { seen.insert(PathKey($0)).inserted })
    }

    /// The files in the folder `package` here.
    private func files(in package: String) throws -> [ListedFile] {
        try o.fs.list(skip: { dir in
            !(dir.utf8.elementsEqual(package.utf8) || inside(dir, package) || inside(package, dir))
        }).filter { inside($0.path, package) && o.filter.includes($0.path) }
    }

    private func holder(_ package: String) -> Int32? {
        if let known = packageHolder[PathKey(package)] { return known }
        let pid = o.fs.holders([package])[package]
        packageHolder[PathKey(package)] = pid
        return pid
    }

    /// Whether `package` has changes here that aren't uploaded, from comparing it with its
    /// synced state. Not from the outbox: file events queue what the pull itself wrote.
    private func isDirty(_ package: String) throws -> Bool {
        if let known = packageDirty[PathKey(package)] { return known }
        let dirty = try findDirty(package)
        packageDirty[PathKey(package)] = dirty
        return dirty
    }

    private func findDirty(_ package: String) throws -> Bool {
        let synced = try o.store.files().filter { inside($0.key.path, package) && !$0.value.deleted }
        let present = try files(in: package)
        if present.count != synced.count { return true }
        for f in present {
            guard let s = synced[PathKey(f.path)] else { return true }
            if s.size == f.stat.size && s.mtime == f.stat.mtime { continue }
            if try o.fs.hash(f.path) != s.sha256 { return true }
        }
        return false
    }

    /// Move each package changed on both sides to a conflict copy, then make it the vault's
    /// version again: the remote side keeps the name, as for a single file.
    private func resolvePackageConflicts() async throws {
        let pending = try conflicts()
        guard !pending.isEmpty else { return }
        let holders = o.fs.holders(pending.map(\.path))
        for package in pending.map(\.path) {
            if let pid = holders[package] {
                report.held[package] = .inUse(pid: pid)
                continue
            }
            try await resolve(package)
            try setConflicts(try conflicts().map(\.path).filter { !$0.utf8.elementsEqual(package.utf8) })
        }
    }

    private func resolve(_ package: String) async throws {
        let local = try files(in: package)
        if !local.isEmpty {
            let taken = try o.fs.list(skip: { _ in false }).map(\.path)
            let copy = Merge.conflictPath(package, device: o.deviceName, date: o.now()) { c in taken.contains { inside($0, c) } }
            for f in local {
                try checkOpen()
                let target = copy + f.path.dropFirst(package.count)
                try o.fs.write(target, try o.fs.read(f.path), mtime: f.stat.mtime, ctime: f.stat.ctime)
                try o.store.enqueue(target)
            }
            report.conflicts.append(copy)
        }
        for entry in try o.store.outbox() where inside(entry.path, package) { try o.store.dequeue(entry) }
        // Now the package is the vault's version, file by file, from the remote index.
        let remote = try o.store.remoteFiles().filter { inside($0.key.path, package) }
        let synced = try o.store.files().filter { inside($0.key.path, package) }
        var paths = Set(remote.keys).union(synced.keys)
        for f in local { paths.insert(PathKey(f.path)) }
        for key in paths {
            try checkOpen()
            let path = key.path
            let here = try self.local(path, withData: false)
            guard let r = remote[key], let revision = try? JSONDecoder().decode(Revision.self, from: r.revision),
                  let meta = try await openRemoteMeta(revision)
            else {
                // Never in the vault: only in the conflict copy now.
                if here.exists { try o.fs.remove(path) }
                if synced[key] != nil { try o.store.removeFile(path) }
                continue
            }
            if meta.deleted {
                if here.exists { try o.fs.remove(path) }
                try record(path, revision, meta, stat: nil)
            } else if here.exists && here.sha256 == meta.sha256 {
                try record(path, revision, meta, stat: here.stat)
            } else {
                do { try await writeRemoteChunks(path, revision, meta) } catch is Objects.Failure {
                    report.rejected += 1
                    o.onWarning("Skipped a remote change whose content failed its integrity check (revision \(revision.rev)).")
                }
            }
        }
        packageDirty[PathKey(package)] = false
    }

    /// Background re-encryption (crypto.md 8.4): commit every live file whose synced head is
    /// from an older epoch again, unchanged, under the current one. A newer sync request
    /// stops it, and the next round goes on.
    private func reencrypt() async throws {
        let current = o.cipher.currentEpoch
        for (path, file) in try o.store.files() {
            if again { return }
            try checkOpen()
            if file.deleted || file.epoch >= current || !o.filter.includes(path.path) { continue }
            do { try await pushPath(path.path, again: true) } catch let e as ApiError where refused.contains(e.status) {
                o.onWarning("Couldn't re-encrypt a file (\(e.code)).")
            }
        }
    }

    /// With `again`, commit an unchanged file anyway (re-encryption). With `inPackage`, a newer
    /// head throws `PackageChanged` instead of merging this file alone.
    @discardableResult
    private func pushPath(_ path: String, again: Bool = false, inPackage: Bool = false) async throws -> Committed? {
        guard o.filter.includes(path) else { return nil }
        let synced = try o.store.file(path)
        if !again, let s = synced, !s.deleted, s.mtime != 0 {
            // Same size and time as synced (a file the pull just wrote): unchanged.
            if let stat = try o.fs.stat(path), stat.size == s.size, stat.mtime == s.mtime { return nil }
            // Touched, maybe not changed: hash in chunks first, so a big file isn't read whole.
            let peek = try local(path, withData: false)
            if peek.exists, peek.sha256 == s.sha256, let stat = peek.stat {
                var updated = s
                updated.mtime = stat.mtime
                try o.store.putFile(path, updated)
                return nil
            }
        }
        let local = try local(path)
        if !local.exists && (synced == nil || synced!.deleted) { return nil }
        let unchanged = local.exists && synced != nil && !synced!.deleted && local.sha256 == synced!.sha256
        if again ? !unchanged : unchanged { return nil }

        let t = now()
        let sealed = try o.cipher.seal(path: path, data: local.exists ? local.data! : nil, mtime: local.stat?.mtime ?? t,
                                       ctime: local.stat?.ctime ?? t, device: o.deviceId)
        let missing = Set(try await o.api.missingBlobs(o.vaultId, sealed.chunks.map(\.id)))
        let total = sealed.chunks.reduce(0) { $0 + $1.size }
        var sent = 0
        if !sealed.chunks.isEmpty { o.onProgress(.file(path: path, done: 0, total: total)) }
        for c in sealed.chunks {
            if missing.contains(c.id) {
                try checkOpen()
                try await o.api.putBlob(o.vaultId, c.id, Data(c.object))
            }
            sent += c.size
            o.onProgress(.file(path: path, done: sent, total: total))
        }
        let fileId = try o.cipher.fileId(path)
        try checkOpen()
        let revision: Revision
        do {
            revision = try await o.api.commit(o.vaultId, fileId, CommitRequest(blobs: sealed.chunks.map(\.id), deleted: !local.exists,
                                                                               meta: sealed.meta, parentRev: synced?.rev))
        } catch let e as ApiError where e.code == "stale_parent" {
            if inPackage { throw PackageChanged() }
            if let head = e.details["head"], head != .null, let r = try? decodeRevision(head) {
                try await applyRemote(r)
            } else {
                // The file is gone on the server (it shouldn't be): commit it as new.
                try o.store.removeFile(path)
                try o.store.enqueue(path)
            }
            return nil
        }
        try o.store.putFile(path, SyncedFile(fileId: fileId, rev: revision.rev, deleted: !local.exists,
                                             sha256: local.exists ? sealed.sha256 : "", size: local.data?.count ?? 0,
                                             mtime: local.stat?.mtime ?? 0, epoch: try o.cipher.epoch(meta: sealed.meta)))
        try o.store.putRemote(path, RemoteFile(rev: revision.rev, deleted: !local.exists, size: local.data?.count ?? 0,
                                               revision: try JSONEncoder().encode(revision)))
        if again { report.reencrypted += 1 } else { report.pushed += 1 }
        return Committed(path: path, fileId: fileId, parent: synced?.rev, rev: revision.rev)
    }

    // MARK: Apply a remote revision

    /// Apply one remote revision: write it, merge it with local changes, or skip it.
    private func applyRemote(_ revision: Revision) async throws {
        guard let meta = try await openRemoteMeta(revision) else {
            report.rejected += 1
            o.onWarning("Skipped a remote change that failed its integrity check (revision \(revision.rev)).")
            return
        }
        let path = meta.path
        try noteRemote(path, revision, meta)
        guard o.filter.includes(path) else { return }
        let synced = try o.store.file(path)
        if let synced, revision.rev <= synced.rev { return }
        if let package = o.fs.packageRoot(path) {
            // A package changes as one unit: never under an app that has it open, and never
            // merged file by file. Changed on both sides, it is resolved after the feed.
            if try conflicts().contains(PathKey(package)) { return }
            if let pid = holder(package) {
                report.held[package] = .inUse(pid: pid)
                throw PackageInUse()
            }
            if try isDirty(package) {
                try setConflicts(try conflicts().map(\.path) + [package])
                return
            }
        }
        try checkOpen()
        o.onProgress(.pull(done: pullDone, rev: revision.rev, path: path))
        // Always hashed: a stat that looks unchanged mustn't let a remote write replace an edit.
        let local = try local(path, withData: false)
        let unchanged: Bool = if let synced { synced.deleted ? !local.exists : local.exists && local.sha256 == synced.sha256 }
            else { !local.exists }
        report.pulled += 1

        if meta.deleted {
            if unchanged || !local.exists {
                if local.exists { try o.fs.remove(path) }
                try record(path, revision, meta, stat: nil)
            } else {
                // Edited here, deleted there: keep the edit and commit it on top of the deletion.
                try record(path, revision, meta, stat: nil)
                try o.store.enqueue(path)
            }
            return
        }

        if local.exists && local.sha256 == meta.sha256 {
            try record(path, revision, meta, stat: local.stat)
            return
        }
        func rejected(_ e: any Error) -> Bool {
            guard e is Objects.Failure else { return false }
            report.rejected += 1
            o.onWarning("Skipped a remote change whose content failed its integrity check (revision \(revision.rev)).")
            return true
        }
        // Deleted here but edited there: the edit wins.
        if unchanged || !local.exists {
            do { try await writeRemoteChunks(path, revision, meta) } catch where rejected(error) {}
            return
        }
        let remote: Bytes
        do { remote = try await download(revision, meta) } catch where rejected(error) { return }

        // Both sides changed.
        let localData = try local.data ?? o.fs.read(path)
        let base: Bytes? = if let synced, !synced.deleted { try await self.base(revision.fileId, rev: synced.rev) } else { nil }
        if let merged = Merge.mergeText(path: path, base: base, local: localData, remote: remote) {
            if Primitives.sha256(merged).hex == meta.sha256 {
                try writeRemote(path, revision, meta, remote)
            } else {
                // The merge goes on top of the remote revision. No mtime is recorded, so the
                // next scan hashes the file instead of trusting its stat.
                try o.fs.write(path, merged, mtime: now(), ctime: nil)
                try record(path, revision, meta, stat: nil)
                try o.store.enqueue(path)
            }
            report.merged += 1
            return
        }
        let taken = Set(try o.fs.list(skip: { _ in false }).map { PathKey($0.path) })
        let copy = Merge.conflictPath(path, device: o.deviceName, date: o.now()) { taken.contains(PathKey($0)) }
        try o.fs.write(copy, localData, mtime: now(), ctime: nil)
        try o.store.enqueue(copy)
        try writeRemote(path, revision, meta, remote)
        report.conflicts.append(copy)
    }

    /// A revision's metadata, or nil if it fails its checks. Under an epoch this keyring
    /// doesn't have, the keyring is refreshed once first.
    private func openRemoteMeta(_ revision: Revision) async throws -> FileMeta? {
        do { return try o.cipher.openMeta(fileId: revision.fileId, meta: revision.meta) } catch is KeyringError {
            guard let k = o.keyring else { return nil }
            try await k.refresh()
            return try? o.cipher.openMeta(fileId: revision.fileId, meta: revision.meta)
        } catch { return nil }
    }

    private func writeRemote(_ path: String, _ revision: Revision, _ meta: FileMeta, _ data: Bytes) throws {
        try checkOpen()
        try o.fs.write(path, data, mtime: meta.mtime, ctime: meta.ctime)
        try record(path, revision, meta, stat: try o.fs.stat(path))
    }

    /// Download and write a revision chunk by chunk. Throws before writing if a check fails.
    private func writeRemoteChunks(_ path: String, _ revision: Revision, _ meta: FileMeta) async throws {
        try checkOpen()
        let writer = try o.fs.beginWrite(path)
        do {
            try await chunks(revision, meta) { try writer.append($0) }
            try checkOpen()
            try writer.commit(mtime: meta.mtime, ctime: meta.ctime)
        } catch {
            writer.abort()
            throw error
        }
        try record(path, revision, meta, stat: try o.fs.stat(path))
    }

    /// Remember `revision` as the synced state of `path`.
    private func record(_ path: String, _ revision: Revision, _ meta: FileMeta, stat: FileStat?) throws {
        try o.store.putFile(path, SyncedFile(fileId: revision.fileId, rev: revision.rev, deleted: meta.deleted,
                                             sha256: meta.deleted ? "" : meta.sha256, size: meta.size, mtime: stat?.mtime ?? 0,
                                             epoch: try o.cipher.epoch(meta: revision.meta)))
    }

    private func download(_ revision: Revision, _ meta: FileMeta) async throws -> Bytes {
        var all = Bytes()
        all.reserveCapacity(meta.size)
        try await chunks(revision, meta) { all += $0 }
        return all
    }

    /// A revision's plaintext, one chunk at a time. Each chunk is checked as it comes, and the
    /// file's hash after the last one: this throws instead of finishing.
    private func chunks(_ revision: Revision, _ meta: FileMeta, _ append: (Bytes) throws -> Void) async throws {
        var opener = try o.cipher.contentOpener(fileId: revision.fileId, meta: meta)
        var received = 0
        if !meta.chunks.isEmpty { o.onProgress(.file(path: meta.path, done: 0, total: meta.size)) }
        for (i, chunk) in meta.chunks.enumerated() {
            try checkOpen()
            try append(try opener.open(i, try await blob(chunk.id)))
            received += chunk.size
            o.onProgress(.file(path: meta.path, done: received, total: meta.size))
        }
        try opener.finish()
    }

    /// One blob, tried again after a short wait when the server can't be reached.
    private func blob(_ id: String) async throws -> Bytes {
        var attempt = 0
        while true {
            do { return Bytes(try await o.api.getBlob(o.vaultId, id)) } catch let e as ConnectionError {
                guard attempt < o.blobRetries.count else { throw e }
                try await Task.sleep(for: o.blobRetries[attempt])
                attempt += 1
                try checkOpen()
            }
        }
    }

    /// The content of a revision, or nil for a deletion.
    private func content(_ fileId: String, rev: Int) async throws -> Bytes? {
        let revision = try await o.api.revision(o.vaultId, fileId, rev: rev)
        let meta = try o.cipher.openMeta(fileId: fileId, meta: revision.meta)
        return meta.deleted ? nil : try await download(revision, meta)
    }

    /// The content of an earlier revision, as the merge base. Nil if it can't be read.
    private func base(_ fileId: String, rev: Int) async throws -> Bytes? {
        do { return try await content(fileId, rev: rev) } catch let e as ApiError where e.status == 404 { return nil }
    }

    /// The local state of `path`, and its content unless `withData` is false (then the file
    /// is hashed in chunks).
    private func local(_ path: String, withData: Bool = true) throws -> LocalFile {
        guard let stat = try o.fs.stat(path) else { return LocalFile(exists: false, stat: nil, data: nil, sha256: "") }
        if !withData { return LocalFile(exists: true, stat: stat, data: nil, sha256: try o.fs.hash(path)) }
        let data = try o.fs.read(path)
        return LocalFile(exists: true, stat: stat, data: data, sha256: Primitives.sha256(data).hex)
    }

    private func now() -> Int { Int(o.now().timeIntervalSince1970 * 1000) }
}

func decodeRevision(_ v: JSONValue) throws -> Revision {
    try JSONDecoder().decode(Revision.self, from: try JSONEncoder().encode(v))
}
