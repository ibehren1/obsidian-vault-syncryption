import Foundation
import SyncryptionCrypto
import SyncryptionStore

/// The files the engine syncs, behind a protocol so tests can use memory.

public struct FileStat: Equatable, Sendable {
    /// Milliseconds since the epoch.
    public var mtime: Int
    public var ctime: Int
    public var size: Int
}

public struct ListedFile: Sendable {
    /// Relative to the listed folder, `/`-separated, as named on disk.
    public var path: String
    public var stat: FileStat
}

public protocol VaultFs: Sendable {
    /// Every file in the folder (no folders), except under folders `skip` returns true for.
    func list(skip: (String) -> Bool) throws -> [ListedFile]
    func stat(_ path: String) throws -> FileStat?
    func read(_ path: String) throws -> Bytes
    /// The hex SHA-256 of a file, without holding it whole.
    func hash(_ path: String) throws -> String
    /// Create or replace, creating parent folders as needed. Throws if another file's name
    /// differs from `path` only in case or Unicode form (one file on APFS).
    func write(_ path: String, _ data: Bytes, mtime: Int, ctime: Int?) throws
    /// Start writing a file that arrives in chunks. Nothing is visible until `commit`.
    func beginWrite(_ path: String) throws -> any ChunkWriter
    /// Delete a file because it was deleted on another device.
    func remove(_ path: String) throws
    /// The outermost folder holding `path` that macOS shows as one file (a package, like an
    /// app's document bundle), or nil. Only folders that exist here count.
    func packageRoot(_ path: String) -> String?
    /// The newest mtime (ms) of anything in the folder `package`, folders included: a folder's
    /// mtime changes when a file in it is added, removed or renamed.
    func lastChange(in package: String) -> Int?
    /// For each folder in `packages` that a process other than this one has a file open in,
    /// that process's id.
    func holders(_ packages: [String]) -> [String: Int32]
}

public protocol ChunkWriter: AnyObject {
    func append(_ chunk: Bytes) throws
    /// Put the file in place with these times.
    func commit(mtime: Int, ctime: Int?) throws
    /// Throw the partial file away.
    func abort()
}

public struct NameClash: Error, CustomStringConvertible {
    public let description = "Another file's name differs only in case or Unicode form, and this Mac's disk sees them as one file."
}

/// A folder on disk. Writes go to a temp file in the same folder and are renamed into place.
///
/// Paths are kept as strings and created with POSIX calls: Foundation's `URL` decomposes file
/// names (NFD), so a file synced as NFC would land on disk under another name, and the next
/// scan would see a different path. APFS finds a file under either form, so reading,
/// hashing and deleting can use any.
public struct PlainFolderFs: VaultFs {
    public let root: URL
    private let rootPath: String
    private var fm: FileManager { FileManager.default }
    private let packages = PackageCache()

    public init(root: URL) {
        self.root = root.standardizedFileURL
        rootPath = self.root.path
    }

    /// Whether each folder is a package, remembered once the folder exists.
    final class PackageCache: @unchecked Sendable {
        private let lock = NSLock()
        private var known: [PathKey: Bool] = [:]
        func get(_ dir: String) -> Bool? { lock.withLock { known[PathKey(dir)] } }
        func set(_ dir: String, _ value: Bool) { lock.withLock { known[PathKey(dir)] = value } }
    }

    private func full(_ path: String) -> String { rootPath + "/" + path }

    private static func ms(_ d: Date?) -> Int { Int(((d ?? Date(timeIntervalSince1970: 0)).timeIntervalSince1970 * 1000).rounded(.down)) }

    private static func split(_ path: String) -> (dir: String, name: String) {
        guard let slash = path.lastIndex(of: "/") else { return ("", path) }
        return (String(path[..<slash]), String(path[path.index(after: slash)...]))
    }

    public func list(skip: (String) -> Bool) throws -> [ListedFile] {
        guard let e = fm.enumerator(atPath: rootPath) else { return [] }
        var out: [ListedFile] = []
        while let rel = e.nextObject() as? String {
            guard let attrs = e.fileAttributes, let type = attrs[.type] as? FileAttributeType else { continue }
            if type == .typeDirectory {
                if skip(rel) { e.skipDescendants() }
                continue
            }
            guard type == .typeRegular else { continue }  // symlinks and the like aren't synced
            out.append(ListedFile(path: rel, stat: FileStat(mtime: Self.ms(attrs[.modificationDate] as? Date),
                                                             ctime: Self.ms(attrs[.creationDate] as? Date),
                                                             size: (attrs[.size] as? NSNumber)?.intValue ?? 0)))
        }
        return out
    }

    public func stat(_ path: String) throws -> FileStat? {
        guard let attrs = try? fm.attributesOfItem(atPath: full(path)), attrs[.type] as? FileAttributeType == .typeRegular,
              exactName(path) else { return nil }
        return FileStat(mtime: Self.ms(attrs[.modificationDate] as? Date), ctime: Self.ms(attrs[.creationDate] as? Date),
                        size: (attrs[.size] as? NSNumber)?.intValue ?? 0)
    }

    public func read(_ path: String) throws -> Bytes {
        guard let d = fm.contents(atPath: full(path)) else { throw CocoaError(.fileReadNoSuchFile) }
        return Bytes(d)
    }

    public func hash(_ path: String) throws -> String {
        guard let h = FileHandle(forReadingAtPath: full(path)) else { throw CocoaError(.fileReadNoSuchFile) }
        defer { try? h.close() }
        var s = SHA256Stream()
        while let chunk = try h.read(upToCount: 1 << 20), !chunk.isEmpty {
            try Task.checkCancellation()
            s.update(Bytes(chunk))
        }
        return s.finalize().hex
    }

    /// Whether the file at `path` has exactly that name: APFS finds `A.md` for `a.md`, and an
    /// NFD name for an NFC one.
    private func exactName(_ path: String) -> Bool {
        let (dir, name) = Self.split(path)
        let names = (try? fm.contentsOfDirectory(atPath: dir.isEmpty ? rootPath : full(dir))) ?? []
        return names.contains { $0.utf8.elementsEqual(name.utf8) }
    }

    /// Create the folders of `path` under their exact names. Throws `NameClash` if a component
    /// exists under a name that differs only in case or Unicode form.
    private func prepareFolders(_ path: String) throws {
        var dir = rootPath
        let parts = path.split(separator: "/").map(String.init)
        for (i, part) in parts.enumerated() {
            let names = (try? fm.contentsOfDirectory(atPath: dir)) ?? []
            // Swift's `==` is canonical equivalence, so this also finds NFC against NFD.
            let folded = part.lowercased()
            if let other = names.first(where: { $0.lowercased() == folded }), !other.utf8.elementsEqual(part.utf8) {
                throw NameClash()
            }
            dir += "/" + part
            if i < parts.count - 1 && !names.contains(where: { $0.utf8.elementsEqual(part.utf8) }) {
                guard mkdir(dir, 0o755) == 0 || errno == EEXIST else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
            }
        }
    }

    private func tempPath(for path: String) -> String {
        let (dir, _) = Self.split(path)
        return (dir.isEmpty ? rootPath : full(dir)) + "/" + PathFilter.tempPrefix + UUID().uuidString
    }

    fileprivate func finish(temp: String, path: String, mtime: Int, ctime: Int?) throws {
        var attrs: [FileAttributeKey: Any] = [.modificationDate: Date(timeIntervalSince1970: Double(mtime) / 1000)]
        if let ctime { attrs[.creationDate] = Date(timeIntervalSince1970: Double(ctime) / 1000) }
        try fm.setAttributes(attrs, ofItemAtPath: temp)
        // rename(2) with the path's own bytes: the name lands on disk as sent.
        guard rename(temp, full(path)) == 0 else {
            let code = errno
            try? fm.removeItem(atPath: temp)
            throw POSIXError(.init(rawValue: code) ?? .EIO)
        }
    }

    public func write(_ path: String, _ data: Bytes, mtime: Int, ctime: Int?) throws {
        try prepareFolders(path)
        let temp = tempPath(for: path)
        guard fm.createFile(atPath: temp, contents: Data(data)) else { throw CocoaError(.fileWriteUnknown) }
        try finish(temp: temp, path: path, mtime: mtime, ctime: ctime)
    }

    public func beginWrite(_ path: String) throws -> any ChunkWriter {
        try prepareFolders(path)
        let temp = tempPath(for: path)
        guard fm.createFile(atPath: temp, contents: nil), let h = FileHandle(forWritingAtPath: temp) else {
            throw CocoaError(.fileWriteUnknown)
        }
        return FolderChunkWriter(fs: self, handle: h, temp: temp, path: path)
    }

    final class FolderChunkWriter: ChunkWriter {
        let fs: PlainFolderFs
        let handle: FileHandle
        let temp: String, path: String

        init(fs: PlainFolderFs, handle: FileHandle, temp: String, path: String) {
            self.fs = fs
            self.handle = handle
            self.temp = temp
            self.path = path
        }

        func append(_ chunk: Bytes) throws { try handle.write(contentsOf: Data(chunk)) }

        func commit(mtime: Int, ctime: Int?) throws {
            try handle.close()
            try fs.finish(temp: temp, path: path, mtime: mtime, ctime: ctime)
        }

        func abort() {
            try? handle.close()
            try? FileManager.default.removeItem(atPath: temp)
        }
    }

    public func packageRoot(_ path: String) -> String? {
        let parts = path.split(separator: "/").dropLast()
        var dir = ""
        for part in parts {
            dir += (dir.isEmpty ? "" : "/") + part
            if let known = packages.get(dir) {
                if known { return dir }
                continue
            }
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: full(dir), isDirectory: &isDir), isDir.boolValue else { return nil }
            let package = (try? URL(fileURLWithPath: full(dir), isDirectory: true).resourceValues(forKeys: [.isPackageKey]))?
                .isPackage ?? false
            packages.set(dir, package)
            if package { return dir }
        }
        return nil
    }

    public func lastChange(in package: String) -> Int? {
        guard let top = try? fm.attributesOfItem(atPath: full(package)) else { return nil }
        var newest = Self.ms(top[.modificationDate] as? Date)
        if let e = fm.enumerator(atPath: full(package)) {
            while e.nextObject() != nil {
                if let d = e.fileAttributes?[.modificationDate] as? Date { newest = max(newest, Self.ms(d)) }
            }
        }
        return newest
    }

    public func holders(_ packages: [String]) -> [String: Int32] {
        let byFull = Dictionary(packages.map { (full($0), $0) }, uniquingKeysWith: { a, _ in a })
        var out: [String: Int32] = [:]
        for (f, pid) in OpenFiles.holders(under: Array(byFull.keys)) { if let p = byFull[f] { out[p] = pid } }
        return out
    }

    public func remove(_ path: String) throws {
        guard exactName(path) else { return }
        try fm.removeItem(atPath: full(path))
        // Folders aren't synced: remove the ones the deletion left empty.
        var dir = Self.split(path).dir
        while !dir.isEmpty {
            let names = (try? fm.contentsOfDirectory(atPath: full(dir))) ?? ["?"]
            guard names.allSatisfy({ $0 == ".DS_Store" }) else { break }
            try? fm.removeItem(atPath: full(dir))
            dir = Self.split(dir).dir
        }
    }
}

public struct NotMapped: Error, CustomStringConvertible {
    public let description = "This path isn't in a folder synced on this Mac."
}

/// A vault on the Mac: each top-level vault folder in `folders` is a folder on disk, which
/// may be anywhere. Vault paths are `<folder>/<path in it>`; the root has no files.
public struct MappedFs: VaultFs {
    public let folders: [String: any VaultFs]

    public init(folders: [String: any VaultFs]) { self.folders = folders }

    /// Each folder on disk.
    public init(roots: [String: URL]) { folders = roots.mapValues { PlainFolderFs(root: $0) } }

    private func resolve(_ path: String) throws -> (fs: any VaultFs, rest: String) {
        guard let slash = path.firstIndex(of: "/") else { throw NotMapped() }
        let name = String(path[..<slash])
        // By exact bytes, like every path here.
        guard let fs = folders.first(where: { $0.key.utf8.elementsEqual(name.utf8) })?.value else { throw NotMapped() }
        return (fs, String(path[path.index(after: slash)...]))
    }

    public func list(skip: (String) -> Bool) throws -> [ListedFile] {
        var out: [ListedFile] = []
        for (name, fs) in folders.sorted(by: { $0.key < $1.key }) where !skip(name) {
            for f in try fs.list(skip: { skip(name + "/" + $0) }) {
                out.append(ListedFile(path: name + "/" + f.path, stat: f.stat))
            }
        }
        return out
    }

    public func stat(_ path: String) throws -> FileStat? {
        guard let (fs, rest) = try? resolve(path) else { return nil }
        return try fs.stat(rest)
    }

    public func read(_ path: String) throws -> Bytes { let r = try resolve(path); return try r.fs.read(r.rest) }
    public func hash(_ path: String) throws -> String { let r = try resolve(path); return try r.fs.hash(r.rest) }

    public func write(_ path: String, _ data: Bytes, mtime: Int, ctime: Int?) throws {
        let r = try resolve(path)
        try r.fs.write(r.rest, data, mtime: mtime, ctime: ctime)
    }

    public func beginWrite(_ path: String) throws -> any ChunkWriter { let r = try resolve(path); return try r.fs.beginWrite(r.rest) }
    public func remove(_ path: String) throws { let r = try resolve(path); try r.fs.remove(r.rest) }

    public func packageRoot(_ path: String) -> String? {
        guard let r = try? resolve(path), let p = r.fs.packageRoot(r.rest) else { return nil }
        return String(path[..<path.firstIndex(of: "/")!]) + "/" + p
    }

    public func lastChange(in package: String) -> Int? {
        guard let r = try? resolve(package) else { return nil }
        return r.fs.lastChange(in: r.rest)
    }

    public func holders(_ packages: [String]) -> [String: Int32] {
        var byFolder: [String: [String]] = [:]
        for p in packages { if let slash = p.firstIndex(of: "/") { byFolder[String(p[..<slash]), default: []].append(p) } }
        var out: [String: Int32] = [:]
        for (name, list) in byFolder {
            guard let fs = folders.first(where: { $0.key.utf8.elementsEqual(name.utf8) })?.value else { continue }
            let prefix = name.count + 1
            for (rest, pid) in fs.holders(list.map { String($0.dropFirst(prefix)) }) { out[name + "/" + rest] = pid }
        }
        return out
    }
}

/// Files in memory, for tests.
public final class MemoryFs: VaultFs, @unchecked Sendable {
    public struct File {
        public var data: Bytes
        public var stat: FileStat
    }

    private let lock = NSLock()
    private var files: [PathKey: File] = [:]
    private var clock = 1_790_000_000_000
    /// When a file was last removed from each folder, like a folder's mtime on disk.
    private var removed: [PathKey: Int] = [:]
    private var packageDirs: Set<PathKey> = []
    private var openFiles: [PathKey: Int32] = [:]

    public init() {}

    /// The time of the last edit, in ms: what `set` stamps as mtime.
    public var now: Int { lock.withLock { clock } }

    /// Makes the folder `dir` a package, as an app's registered document type would.
    public func makePackage(_ dir: String) { _ = lock.withLock { packageDirs.insert(PathKey(dir)) } }

    /// Simulates another process holding `path` open (nil: closing it).
    public func setOpen(_ path: String, by pid: Int32?) { lock.withLock { openFiles[PathKey(path)] = pid } }

    /// Simulates an edit by the user.
    public func set(_ path: String, _ content: String) { set(path, Bytes(utf8: content)) }

    public func set(_ path: String, _ data: Bytes) {
        lock.withLock {
            clock += 1000
            let ctime = files[PathKey(path)]?.stat.ctime ?? clock
            files[PathKey(path)] = File(data: data, stat: FileStat(mtime: clock, ctime: ctime, size: data.count))
        }
    }

    public func text(_ path: String) -> String? {
        lock.withLock { files[PathKey(path)].map { String(decoding: $0.data, as: UTF8.self) } }
    }

    public func delete(_ path: String) {
        lock.withLock {
            guard files.removeValue(forKey: PathKey(path)) != nil else { return }
            clock += 1000
            if let slash = path.lastIndex(of: "/") { removed[PathKey(String(path[..<slash]))] = clock }
        }
    }

    public var paths: [String] { lock.withLock { files.keys.map(\.path).sorted() } }

    public func list(skip: (String) -> Bool) throws -> [ListedFile] {
        lock.withLock { files.map { ListedFile(path: $0.key.path, stat: $0.value.stat) } }
    }

    public func stat(_ path: String) throws -> FileStat? { lock.withLock { files[PathKey(path)]?.stat } }

    public func read(_ path: String) throws -> Bytes {
        guard let f = lock.withLock({ files[PathKey(path)] }) else { throw CocoaError(.fileNoSuchFile) }
        return f.data
    }

    public func hash(_ path: String) throws -> String { Primitives.sha256(try read(path)).hex }

    public func write(_ path: String, _ data: Bytes, mtime: Int, ctime: Int?) throws {
        lock.withLock {
            let c = ctime ?? files[PathKey(path)]?.stat.ctime ?? mtime
            // Like a real clock, later edits get later times than anything written before.
            clock = max(clock, mtime)
            files[PathKey(path)] = File(data: data, stat: FileStat(mtime: mtime, ctime: c, size: data.count))
        }
    }

    public func beginWrite(_ path: String) throws -> any ChunkWriter { MemoryChunkWriter(fs: self, path: path) }

    final class MemoryChunkWriter: ChunkWriter {
        let fs: MemoryFs
        let path: String
        var data = Bytes()
        init(fs: MemoryFs, path: String) {
            self.fs = fs
            self.path = path
        }

        func append(_ chunk: Bytes) throws { data += chunk }
        func commit(mtime: Int, ctime: Int?) throws { try fs.write(path, data, mtime: mtime, ctime: ctime) }
        func abort() {}
    }

    public func remove(_ path: String) throws { delete(path) }

    private static func inside(_ path: String, _ dir: String) -> Bool { path.utf8.starts(with: (dir + "/").utf8) }

    public func packageRoot(_ path: String) -> String? {
        lock.withLock {
            let parts = path.split(separator: "/").dropLast()
            var dir = ""
            for part in parts {
                dir += (dir.isEmpty ? "" : "/") + part
                if packageDirs.contains(PathKey(dir)) && files.keys.contains(where: { Self.inside($0.path, dir) }) { return dir }
            }
            return nil
        }
    }

    public func lastChange(in package: String) -> Int? {
        lock.withLock {
            let times = files.filter { Self.inside($0.key.path, package) }.map(\.value.stat.mtime)
                + removed.filter { $0.key.path.utf8.elementsEqual(package.utf8) || Self.inside($0.key.path, package) }.map(\.value)
            return times.max()
        }
    }

    public func holders(_ packages: [String]) -> [String: Int32] {
        lock.withLock {
            var out: [String: Int32] = [:]
            for p in packages { if let o = openFiles.first(where: { Self.inside($0.key.path, p) }) { out[p] = o.value } }
            return out
        }
    }
}
