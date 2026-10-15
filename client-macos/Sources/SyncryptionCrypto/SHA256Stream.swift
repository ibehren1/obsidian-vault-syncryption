import CryptoKit

/// Incremental SHA-256, for hashing files chunk by chunk.
public struct SHA256Stream {
    private var h = SHA256()
    public init() {}
    public mutating func update(_ b: Bytes) { h.update(data: b) }
    public func finalize() -> Bytes { Bytes(h.finalize()) }
}
