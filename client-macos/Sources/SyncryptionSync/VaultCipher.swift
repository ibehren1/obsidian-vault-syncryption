import Foundation
import SyncryptionCrypto

/// File encryption for one vault, on top of the keyring (docs/crypto.md 5 and 8).
public struct VaultCipher: Sendable {
    public static let emptySha256 = Primitives.sha256([]).hex

    public struct Sealed: Sendable {
        /// b64u, for the commit body.
        public let meta: String
        public let chunks: [Objects.SealedChunk]
        public let sha256: String
    }

    private let keyring: @Sendable () -> Keyring

    public init(keyring: @escaping @Sendable () -> Keyring) { self.keyring = keyring }

    public var currentEpoch: Int { keyring().currentEpoch }

    /// The epoch a revision's metadata (b64u) was encrypted under.
    public func epoch(meta: String) throws -> Int { try Objects.epoch(of: Bytes(b64u: meta) ?? []) }

    public func fileId(_ path: String) throws -> String { KDF.fileIdString(try KDF.fileId(indexKey: keyring().indexKeyBytes, path: path)) }

    private func fileKey(_ fileId: Bytes, epoch: Int) throws -> Bytes { KDF.fileKey(vdk: try keyring().epochKey(epoch), fileId: fileId) }

    /// Decrypt and check a revision's metadata. Throws `Objects.Failure` if it was tampered
    /// with, `KeyringError` if its epoch isn't in this keyring.
    public func openMeta(fileId: String, meta: String) throws -> FileMeta {
        guard let id = Bytes(b64u: fileId), let object = Bytes(b64u: meta) else { throw Objects.Failure("not base64url") }
        return try Objects.openMeta(fileKey: try fileKey(id, epoch: try Objects.epoch(of: object)), indexKey: keyring().indexKeyBytes,
                                    fileId: id, object)
    }

    /// Decrypts a revision's chunks one at a time. The epoch comes from the first chunk, and
    /// every later one must have the same.
    public struct ContentOpener {
        let cipher: VaultCipher
        let fileId: Bytes
        let meta: FileMeta
        var opener: ChunkOpener?
        var epoch = 0

        public mutating func open(_ index: Int, _ object: Bytes) throws -> Bytes {
            let e = try Objects.epoch(of: object)
            if opener == nil {
                epoch = e
                opener = ChunkOpener(fileKey: try cipher.fileKey(fileId, epoch: e), fileId: fileId, meta: meta)
            } else if e != epoch {
                throw Objects.Failure("chunks from different epochs")
            }
            return try opener!.open(index, object)
        }

        /// No chunks: only an empty file, checked against its hash.
        public mutating func finish() throws {
            if opener == nil { opener = ChunkOpener(fileKey: Bytes(repeating: 0, count: 32), fileId: fileId, meta: meta) }
            try opener!.finish()
        }
    }

    public func contentOpener(fileId: String, meta: FileMeta) throws -> ContentOpener {
        guard let id = Bytes(b64u: fileId) else { throw Objects.Failure("not base64url") }
        return ContentOpener(cipher: self, fileId: id, meta: meta)
    }

    /// A device's metadata object (crypto.md 8.5), under the current epoch.
    public func sealDeviceMeta(deviceId: String, _ meta: DeviceMeta) throws -> Bytes {
        let k = keyring()
        return try Objects.sealDeviceMeta(vdk: try k.epochKey(k.currentEpoch), epoch: k.currentEpoch, deviceId: deviceId, meta)
    }

    /// Decrypt a device's metadata object (b64u, as in the device list).
    public func openDeviceMeta(deviceId: String, _ meta: String) throws -> DeviceMeta {
        guard let object = Bytes(b64u: meta) else { throw Objects.Failure("not base64url") }
        return try Objects.openDeviceMeta(vdk: try keyring().epochKey(try Objects.epoch(of: object)), deviceId: deviceId, object)
    }

    /// Encrypt a file, or a deletion when `data` is nil, under the current epoch.
    public func seal(path: String, data: Bytes?, mtime: Int, ctime: Int, device: String) throws -> Sealed {
        let k = keyring()
        let id = try KDF.fileId(indexKey: k.indexKeyBytes, path: path)
        let epoch = k.currentEpoch
        let key = try fileKey(id, epoch: epoch)
        let chunks = data.map { Objects.sealChunks(fileKey: key, epoch: epoch, fileId: id, $0) } ?? []
        let digest = data.map { Primitives.sha256($0).hex } ?? Self.emptySha256
        let meta = FileMeta(path: path, deleted: data == nil, size: data?.count ?? 0, mtime: mtime, ctime: ctime, sha256: digest,
                            chunks: chunks.map { ChunkRef(id: $0.id, size: $0.size) }, device: device)
        return Sealed(meta: try Objects.sealMeta(fileKey: key, epoch: epoch, fileId: id, meta).b64u, chunks: chunks, sha256: digest)
    }
}
