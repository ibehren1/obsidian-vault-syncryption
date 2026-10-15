import Foundation

/// Vault key derivations (docs/crypto.md 5).
public enum KDF {
    public struct InvalidPath: Error {}

    /// `normPath` (crypto.md 5.2): relative, `/`-separated, no empty, `.` or `..` segments, no
    /// `\` or control characters, no segment ending in `:`, Unicode NFC, case preserved.
    public static func normPath(_ path: String) throws(InvalidPath) -> String {
        let nfc = path.precomposedStringWithCanonicalMapping
        guard !nfc.isEmpty else { throw InvalidPath() }
        for s in nfc.unicodeScalars where s == "\\" || s.value < 0x20 || s.value == 0x7f { throw InvalidPath() }
        for seg in nfc.split(separator: "/", omittingEmptySubsequences: false) {
            if seg.isEmpty || seg == "." || seg == ".." || seg.hasSuffix(":") { throw InvalidPath() }
        }
        return nfc
    }

    public static func isVaultPath(_ path: String) -> Bool { (try? normPath(path)) != nil }

    /// `indexKey = HKDF(VDK[1], "", "syncryption/v1/index")`.
    public static func indexKey(vdk1: Bytes) -> Bytes {
        Primitives.hkdf(ikm: vdk1, salt: [], info: Bytes(utf8: "syncryption/v1/index"))
    }

    /// `fileId = HMAC(indexKey, utf8(normPath))`, 32 bytes.
    public static func fileId(indexKey: Bytes, path: String) throws(InvalidPath) -> Bytes {
        Primitives.hmacSHA256(key: indexKey, Bytes(utf8: try normPath(path)))
    }

    /// The 43-character form of a fileId used in the API.
    public static func fileIdString(_ fileId: Bytes) -> String { fileId.b64u }

    /// `fileKey[e] = HKDF(VDK[e], "", "syncryption/v1/file" || fileId)`.
    public static func fileKey(vdk: Bytes, fileId: Bytes) -> Bytes {
        Primitives.hkdf(ikm: vdk, salt: [], info: Bytes(utf8: "syncryption/v1/file") + fileId)
    }
}
