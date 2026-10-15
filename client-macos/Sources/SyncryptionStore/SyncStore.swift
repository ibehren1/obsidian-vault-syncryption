import Foundation

/// Local sync state (docs/architecture.md 4.1), behind a protocol so tests can use memory.

/// The last synced state of one path.
public struct SyncedFile: Codable, Equatable, Sendable {
    public var fileId: String
    /// The revision this path was last synced at: the `parentRev` of the next commit.
    public var rev: Int
    public var deleted: Bool
    /// Hex SHA-256 of the plaintext ("" for a deletion).
    public var sha256: String
    public var size: Int
    /// Local `mtime` (ms) after the last sync, to skip hashing unchanged files. 0: always hash.
    public var mtime: Int
    /// The key epoch of that revision.
    public var epoch: Int

    public init(fileId: String, rev: Int, deleted: Bool, sha256: String, size: Int, mtime: Int, epoch: Int) {
        self.fileId = fileId
        self.rev = rev
        self.deleted = deleted
        self.sha256 = sha256
        self.size = size
        self.mtime = mtime
        self.epoch = epoch
    }
}

/// A path with local changes to push. What to push is decided when it is pushed.
public struct OutboxEntry: Equatable, Sendable {
    public var path: String
    /// Changes on every enqueue, so a push only removes the entry it pushed.
    public var id: String
    public var queuedAt: Double
}

public protocol SyncStore: Sendable {
    func meta<T: Decodable>(_ key: String, as type: T.Type) throws -> T?
    func setMeta<T: Encodable>(_ key: String, _ value: T?) throws
    func file(_ path: String) throws -> SyncedFile?
    func putFile(_ path: String, _ file: SyncedFile) throws
    func removeFile(_ path: String) throws
    /// Every synced path, by exact bytes (see `PathKey`).
    func files() throws -> [PathKey: SyncedFile]
    /// Add `path` to the outbox, or refresh its entry.
    func enqueue(_ path: String) throws
    /// Oldest first.
    func outbox() throws -> [OutboxEntry]
    /// Remove `entry`, unless the path was queued again since it was read.
    func dequeue(_ entry: OutboxEntry) throws
    /// Forget everything, e.g. when the vault was recreated on the server.
    func clear() throws
}

/// Store meta keys.
public enum MetaKey {
    public static let cursor = "cursor"
    /// Remote revisions that couldn't be written here, tried again on every pull.
    public static let failed = "failed"
    public static let keyringPin = "keyringPin"
    public static let vaultId = "vaultId"
    /// The device whose key this device replaced, until it is removed (hand-over).
    public static let replacedDevice = "replacedDevice"
    /// The devices this device started removing, until the keyring is rotated.
    public static let revokingDevices = "revokingDevices"
    /// Devices the server reports removed that the user chose to keep in the keyring.
    public static let keptDevices = "keptDevices"
}

extension SyncStore {
    /// The paths in sync: the synced files, without deletions.
    public func countFiles() throws -> Int { try files().values.filter { !$0.deleted }.count }

    /// The plaintext bytes in sync: the sizes of the synced files, without deletions.
    public func totalSize() throws -> Int { try files().values.filter { !$0.deleted }.reduce(0) { $0 + $1.size } }
}

/// Paths are compared by their exact characters, not Swift's canonical equivalence: on disk
/// an NFC and an NFD name are different files to sync.
public struct PathKey: Hashable, Sendable {
    public let path: String
    public init(_ path: String) { self.path = path }
    public static func == (a: PathKey, b: PathKey) -> Bool { a.path.utf8.elementsEqual(b.path.utf8) }
    public func hash(into h: inout Hasher) { h.combine(Array(path.utf8)) }
}

public final class MemoryStore: SyncStore, @unchecked Sendable {
    private let lock = NSLock()
    private var metaValues: [String: Data] = [:]
    private var synced: [PathKey: SyncedFile] = [:]
    private var queue: [PathKey: OutboxEntry] = [:]

    public init() {}

    public func meta<T: Decodable>(_ key: String, as type: T.Type) throws -> T? {
        guard let d = lock.withLock({ metaValues[key] }) else { return nil }
        return try JSONDecoder().decode(T.self, from: d)
    }

    public func setMeta<T: Encodable>(_ key: String, _ value: T?) throws {
        let d = try value.map { try JSONEncoder().encode($0) }
        lock.withLock { metaValues[key] = d }
    }

    public func file(_ path: String) throws -> SyncedFile? { lock.withLock { synced[PathKey(path)] } }
    public func putFile(_ path: String, _ file: SyncedFile) throws { lock.withLock { synced[PathKey(path)] = file } }
    public func removeFile(_ path: String) throws { _ = lock.withLock { synced.removeValue(forKey: PathKey(path)) } }

    public func files() throws -> [PathKey: SyncedFile] { lock.withLock { synced } }

    public func enqueue(_ path: String) throws {
        lock.withLock {
            let previous = queue[PathKey(path)]
            queue[PathKey(path)] = OutboxEntry(path: path, id: UUID().uuidString,
                                               queuedAt: previous?.queuedAt ?? Date().timeIntervalSince1970 * 1000)
        }
    }

    public func outbox() throws -> [OutboxEntry] { lock.withLock { queue.values.sorted { $0.queuedAt < $1.queuedAt } } }

    public func dequeue(_ entry: OutboxEntry) throws {
        lock.withLock { if queue[PathKey(entry.path)]?.id == entry.id { queue[PathKey(entry.path)] = nil } }
    }

    public func clear() throws {
        lock.withLock {
            metaValues = [:]
            synced = [:]
            queue = [:]
        }
    }
}
