import Foundation

/// Encrypted metadata and chunk objects (docs/crypto.md 8).
public enum Objects {
    public static let formatVersion: UInt8 = 1
    public static let headerSize = 5
    public static let nonceSize = 24
    public static let overhead = headerSize + nonceSize + 16
    public static let chunkSize = 4 * 1024 * 1024
    public static let maxMetaSize = 64 * 1024

    public struct Failure: Error, Equatable, CustomStringConvertible {
        public let description: String
        public init(_ d: String) { description = d }
    }

    public static func metaDomain(_ fileId: Bytes) -> Bytes { Bytes(utf8: "syncryption/v1/meta") + fileId }

    public static func chunkDomain(_ fileId: Bytes, _ index: Int) -> Bytes {
        concat(Bytes(utf8: "syncryption/v1/chunk"), fileId, u32be(UInt32(index)))
    }

    public static func deviceDomain(_ deviceId: String) -> Bytes { Bytes(utf8: "syncryption/v1/device") + Bytes(utf8: deviceId) }

    private static func header(_ epoch: Int) -> Bytes {
        precondition(epoch >= 1 && epoch <= Int(UInt32.max), "invalid epoch")
        return [formatVersion] + u32be(UInt32(epoch))
    }

    /// `header || nonce || AEAD(fileKey, nonce, plaintext, header || domain)`.
    public static func seal(fileKey: Bytes, epoch: Int, domain: Bytes, _ plaintext: Bytes,
                            nonce: Bytes = Primitives.random(24)) -> Bytes
    {
        precondition(nonce.count == nonceSize)
        let h = header(epoch)
        return h + nonce + Primitives.xchachaSeal(key: fileKey, nonce: nonce, plaintext, ad: h + domain)
    }

    /// The epoch in an object's header, so the reader can pick the right VDK.
    public static func epoch(of object: Bytes) throws(Failure) -> Int {
        guard object.count >= overhead, object[0] == formatVersion else { throw Failure("unsupported or truncated object") }
        return Int(readU32be(object, at: 1))
    }

    public static func open(fileKey: Bytes, domain: Bytes, _ object: Bytes) throws(Failure) -> Bytes {
        _ = try epoch(of: object)
        let h = Array(object[0..<headerSize])
        let nonce = Array(object[headerSize..<(headerSize + nonceSize)])
        guard let plain = Primitives.xchachaOpen(key: fileKey, nonce: nonce, Array(object[(headerSize + nonceSize)...]),
                                                 ad: h + domain)
        else { throw Failure("object failed to decrypt") }
        return plain
    }

    /// A device's metadata object (crypto.md 8.5), under `deviceKey(VDK[epoch], deviceId)`.
    public static func sealDeviceMeta(vdk: Bytes, epoch: Int, deviceId: String, _ meta: DeviceMeta,
                                      nonce: Bytes = Primitives.random(24)) throws(Failure) -> Bytes
    {
        let json: Data
        do { json = try jsonEncoder.encode(meta) } catch { throw Failure("device metadata can't be encoded") }
        let object = seal(fileKey: KDF.deviceKey(vdk: vdk, deviceId: deviceId), epoch: epoch, domain: deviceDomain(deviceId),
                          Bytes(json), nonce: nonce)
        guard object.count <= maxMetaSize else { throw Failure("device metadata too large") }
        return object
    }

    /// Decrypt a device's metadata; `vdk` is the VDK of the object's epoch (`epoch(of:)`).
    public static func openDeviceMeta(vdk: Bytes, deviceId: String, _ object: Bytes) throws(Failure) -> DeviceMeta {
        guard object.count <= maxMetaSize else { throw Failure("device metadata too large") }
        let plain = try open(fileKey: KDF.deviceKey(vdk: vdk, deviceId: deviceId), domain: deviceDomain(deviceId), object)
        guard let meta = try? JSONDecoder().decode(DeviceMeta.self, from: Data(plain)), meta.v == 1 else {
            throw Failure("device metadata has the wrong shape")
        }
        return meta
    }

    /// Blob id: `hex(SHA-256(object))`.
    public static func blobId(_ object: Bytes) -> String { Primitives.sha256(object).hex }

    public static func sealMeta(fileKey: Bytes, epoch: Int, fileId: Bytes, _ meta: FileMeta,
                                nonce: Bytes = Primitives.random(24)) throws(Failure) -> Bytes
    {
        let json: Data
        do { json = try jsonEncoder.encode(meta) } catch { throw Failure("metadata can't be encoded") }
        let object = seal(fileKey: fileKey, epoch: epoch, domain: metaDomain(fileId), Bytes(json), nonce: nonce)
        guard object.count <= maxMetaSize else { throw Failure("metadata too large") }
        return object
    }

    /// Decrypt and check metadata (crypto.md 8.3): its path must hash to `fileId`, and the
    /// chunk list must match `size`.
    public static func openMeta(fileKey: Bytes, indexKey: Bytes, fileId: Bytes, _ object: Bytes) throws(Failure) -> FileMeta {
        guard object.count <= maxMetaSize else { throw Failure("metadata too large") }
        let plain = try open(fileKey: fileKey, domain: metaDomain(fileId), object)
        let meta: FileMeta
        do { meta = try JSONDecoder().decode(FileMeta.self, from: Data(plain)) } catch {
            throw Failure("metadata has the wrong shape")
        }
        guard meta.isWellFormed else { throw Failure("metadata has the wrong shape") }
        guard let pathId = try? KDF.fileId(indexKey: indexKey, path: meta.path) else { throw Failure("metadata path is invalid") }
        guard constantTimeEqual(pathId, fileId) else { throw Failure("metadata path does not match fileId") }
        guard meta.chunks.reduce(0, { $0 + $1.size }) == meta.size else { throw Failure("chunk sizes do not add up to size") }
        guard !meta.deleted || meta.chunks.isEmpty else { throw Failure("deleted file has chunks") }
        let last = meta.chunks.count - 1
        for (i, c) in meta.chunks.enumerated() where c.size > chunkSize || (i < last && c.size != chunkSize) {
            throw Failure("chunks must be 4 MiB, except the last")
        }
        return meta
    }

    public struct SealedChunk: Sendable {
        public let id: String
        public let size: Int
        public let object: Bytes
    }

    /// Split into 4 MiB chunks and seal each one. An empty file has no chunks.
    public static func sealChunks(fileKey: Bytes, epoch: Int, fileId: Bytes, _ data: Bytes) -> [SealedChunk] {
        stride(from: 0, to: data.count, by: chunkSize).enumerated().map { i, off in
            let plain = Array(data[off..<min(off + chunkSize, data.count)])
            let object = seal(fileKey: fileKey, epoch: epoch, domain: chunkDomain(fileId, i), plain)
            return SealedChunk(id: blobId(object), size: plain.count, object: object)
        }
    }

    /// Decrypt chunks in metadata order and check the whole file against `meta.sha256`.
    public static func openChunks(fileKey: Bytes, fileId: Bytes, meta: FileMeta, _ objects: [Bytes]) throws(Failure) -> Bytes {
        guard objects.count == meta.chunks.count else { throw Failure("wrong number of chunks") }
        var opener = ChunkOpener(fileKey: fileKey, fileId: fileId, meta: meta)
        var data = Bytes()
        for (i, o) in objects.enumerated() { data += try opener.open(i, o) }
        try opener.finish()
        return data
    }

    static let jsonEncoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.withoutEscapingSlashes]
        return e
    }()
}

/// Decrypts a file's chunks one at a time, in metadata order, so a large file is never whole
/// in memory. Until `finish` passes, the chunks must not be used as the file's content.
public struct ChunkOpener {
    private var next = 0
    private var hasher = SHA256Stream()
    private let fileKey: Bytes
    private let fileId: Bytes
    private let meta: FileMeta

    public init(fileKey: Bytes, fileId: Bytes, meta: FileMeta) {
        self.fileKey = fileKey
        self.fileId = fileId
        self.meta = meta
    }

    /// Decrypt `object`, the blob for `meta.chunks[index]`. Chunks must come in order.
    public mutating func open(_ index: Int, _ object: Bytes) throws(Objects.Failure) -> Bytes {
        guard index == next, index < meta.chunks.count else { throw Objects.Failure("chunk out of order") }
        let ref = meta.chunks[index]
        guard Objects.blobId(object) == ref.id else { throw Objects.Failure("chunk does not match its id") }
        let plain = try Objects.open(fileKey: fileKey, domain: Objects.chunkDomain(fileId, index), object)
        guard plain.count == ref.size else { throw Objects.Failure("chunk has the wrong size") }
        hasher.update(plain)
        next += 1
        return plain
    }

    public mutating func finish() throws(Objects.Failure) {
        guard next == meta.chunks.count else { throw Objects.Failure("wrong number of chunks") }
        guard hasher.finalize().hex == meta.sha256 else { throw Objects.Failure("file hash does not match") }
    }
}

public struct ChunkRef: Codable, Equatable, Sendable {
    public var id: String
    public var size: Int
    public init(id: String, size: Int) {
        self.id = id
        self.size = size
    }
}

/// File metadata (crypto.md 8.3). Times are milliseconds since the epoch.
public struct FileMeta: Codable, Equatable, Sendable {
    public var v: Int = 1
    public var path: String
    public var deleted: Bool
    public var size: Int
    public var mtime: Int
    public var ctime: Int
    public var sha256: String
    public var chunks: [ChunkRef]
    public var device: String

    public init(path: String, deleted: Bool, size: Int, mtime: Int, ctime: Int, sha256: String, chunks: [ChunkRef], device: String) {
        self.path = path
        self.deleted = deleted
        self.size = size
        self.mtime = mtime
        self.ctime = ctime
        self.sha256 = sha256
        self.chunks = chunks
        self.device = device
    }

    var isWellFormed: Bool {
        let maxSafe = (1 << 53) - 1
        let isCount = { (x: Int) in x >= 0 && x <= maxSafe }
        return v == 1 && isCount(size) && isCount(mtime) && isCount(ctime) && isHex64(sha256)
            && chunks.allSatisfy { isHex64($0.id) && $0.size > 0 && isCount($0.size) }
    }
}

func isHex64(_ s: String) -> Bool {
    s.utf8.count == 64 && s.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
}

/// The plaintext of a device's metadata object (crypto.md 8.5).
public struct DeviceMeta: Codable, Equatable, Sendable {
    /// A top-level vault folder this device syncs, and the local folder it syncs with.
    public struct Folder: Codable, Equatable, Sendable {
        public var name: String
        public var path: String
        public init(name: String, path: String) {
            self.name = name
            self.path = path
        }
    }

    public var v = 1
    public var folders: [Folder]

    public init(folders: [Folder]) { self.folders = folders }

    private enum CodingKeys: String, CodingKey { case v, folders }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decode(Int.self, forKey: .v)
        folders = try c.decodeIfPresent([Folder].self, forKey: .folders) ?? []
    }
}
