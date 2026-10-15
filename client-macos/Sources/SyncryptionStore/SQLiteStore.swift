import Foundation
import SQLite3

/// The sync state of one folder in SQLite (`state.db`), with the plugin's three tables: meta
/// (JSON values), files (the synced state per path) and outbox. Paths are stored as UTF-8
/// blobs, so an NFC and an NFD name stay two rows.
public final class SQLiteStore: SyncStore, @unchecked Sendable {
    private var db: OpaquePointer?
    private let lock = NSLock()

    public struct Failure: Error, CustomStringConvertible {
        public let description: String
    }

    public init(url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK else {
            throw Failure(description: "can't open the sync state")
        }
        try exec("PRAGMA journal_mode = WAL")
        try exec("PRAGMA synchronous = NORMAL")
        try exec("""
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS files (path BLOB PRIMARY KEY, value BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS outbox (path BLOB PRIMARY KEY, id TEXT NOT NULL, queued_at REAL NOT NULL);
            """)
    }

    deinit { sqlite3_close_v2(db) }

    private func exec(_ sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw failure() }
    }

    private func failure() -> Failure { Failure(description: String(cString: sqlite3_errmsg(db))) }

    private enum Value {
        case text(String)
        case blob(Data)
        case real(Double)
    }

    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    /// Run `sql` with `args`, calling `row` for each result row.
    private func run(_ sql: String, _ args: [Value] = [], row: ((OpaquePointer) -> Void)? = nil) throws {
        try lock.withLock {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { throw failure() }
            defer { sqlite3_finalize(stmt) }
            for (i, a) in args.enumerated() {
                let idx = Int32(i + 1)
                switch a {
                case .text(let s): sqlite3_bind_text(stmt, idx, s, -1, Self.transient)
                case .blob(let d): _ = d.withUnsafeBytes { sqlite3_bind_blob(stmt, idx, $0.baseAddress, Int32(d.count), Self.transient) }
                case .real(let r): sqlite3_bind_double(stmt, idx, r)
                }
            }
            while true {
                let rc = sqlite3_step(stmt)
                if rc == SQLITE_DONE { break }
                guard rc == SQLITE_ROW else { throw failure() }
                row?(stmt!)
            }
        }
    }

    private static func blob(_ stmt: OpaquePointer, _ col: Int32) -> Data {
        guard let p = sqlite3_column_blob(stmt, col) else { return Data() }
        return Data(bytes: p, count: Int(sqlite3_column_bytes(stmt, col)))
    }

    private static func text(_ stmt: OpaquePointer, _ col: Int32) -> String {
        sqlite3_column_text(stmt, col).map { String(cString: $0) } ?? ""
    }

    private static func pathData(_ path: String) -> Value { .blob(Data(path.utf8)) }
    private static func path(_ d: Data) -> String { String(decoding: d, as: UTF8.self) }

    public func meta<T: Decodable>(_ key: String, as type: T.Type) throws -> T? {
        var data: Data?
        try run("SELECT value FROM meta WHERE key = ?", [.text(key)]) { data = Self.blob($0, 0) }
        return try data.map { try JSONDecoder().decode(T.self, from: $0) }
    }

    public func setMeta<T: Encodable>(_ key: String, _ value: T?) throws {
        if let value {
            try run("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", [.text(key), .blob(try JSONEncoder().encode(value))])
        } else {
            try run("DELETE FROM meta WHERE key = ?", [.text(key)])
        }
    }

    public func file(_ path: String) throws -> SyncedFile? {
        var data: Data?
        try run("SELECT value FROM files WHERE path = ?", [Self.pathData(path)]) { data = Self.blob($0, 0) }
        return try data.map { try JSONDecoder().decode(SyncedFile.self, from: $0) }
    }

    public func putFile(_ path: String, _ file: SyncedFile) throws {
        try run("INSERT OR REPLACE INTO files (path, value) VALUES (?, ?)", [Self.pathData(path), .blob(try JSONEncoder().encode(file))])
    }

    public func removeFile(_ path: String) throws {
        try run("DELETE FROM files WHERE path = ?", [Self.pathData(path)])
    }

    public func files() throws -> [PathKey: SyncedFile] {
        var rows: [(Data, Data)] = []
        try run("SELECT path, value FROM files") { rows.append((Self.blob($0, 0), Self.blob($0, 1))) }
        var out: [PathKey: SyncedFile] = [:]
        for (p, v) in rows { out[PathKey(Self.path(p))] = try JSONDecoder().decode(SyncedFile.self, from: v) }
        return out
    }

    public func enqueue(_ path: String) throws {
        try run("""
            INSERT INTO outbox (path, id, queued_at) VALUES (?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET id = excluded.id
            """, [Self.pathData(path), .text(UUID().uuidString), .real(Date().timeIntervalSince1970 * 1000)])
    }

    public func outbox() throws -> [OutboxEntry] {
        var out: [OutboxEntry] = []
        try run("SELECT path, id, queued_at FROM outbox ORDER BY queued_at, rowid") {
            out.append(OutboxEntry(path: Self.path(Self.blob($0, 0)), id: Self.text($0, 1), queuedAt: sqlite3_column_double($0, 2)))
        }
        return out
    }

    public func dequeue(_ entry: OutboxEntry) throws {
        try run("DELETE FROM outbox WHERE path = ? AND id = ?", [Self.pathData(entry.path), .text(entry.id)])
    }

    public func clear() throws {
        try exec("DELETE FROM meta; DELETE FROM files; DELETE FROM outbox;")
    }
}
