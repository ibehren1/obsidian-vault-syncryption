import Foundation

/// OpenSSH Ed25519 keys (docs/crypto.md 3.1 and 3.2). Parses and writes unencrypted
/// `openssh-key-v1` private keys; the client only generates its keys, so passphrase-protected
/// keys are refused. Only Ed25519 keys are accepted.

public enum SshKeyError: Error, Equatable {
    case notOpenSSH
    case unsupportedKeyType
    case unsupportedCipher
    case passphraseRequired
    case corrupt

    /// The plugin's code for the same error (client-obsidian-plugin/src/crypto/openssh.ts), used by the vectors.
    public var code: String {
        switch self {
        case .notOpenSSH: "not-openssh"
        case .unsupportedKeyType: "unsupported-key-type"
        case .unsupportedCipher: "unsupported-cipher"
        case .passphraseRequired: "passphrase-required"
        case .corrupt: "corrupt"
        }
    }
}

public struct OpenSshKey: Sendable {
    /// The 32-byte Ed25519 seed: the only secret the client keeps.
    public var seed: Bytes
    public var publicKey: Bytes
    public var comment: String
}

private let magic = Bytes(utf8: "openssh-key-v1\0")
private let keyType = "ssh-ed25519"
private let pemBegin = "-----BEGIN OPENSSH PRIVATE KEY-----"
private let pemEnd = "-----END OPENSSH PRIVATE KEY-----"

public enum OpenSSH {
    /// RFC 8709 public key wire format: string("ssh-ed25519") || string(pk32).
    public static func publicKeyWire(_ pk: Bytes) -> Bytes { concat(sshString(Bytes(utf8: keyType)), sshString(pk)) }

    /// `ssh-ed25519 <base64> [comment]`, as in `authorized_keys`.
    public static func publicKeyText(_ pk: Bytes, comment: String = "") -> String {
        let text = "\(keyType) \(publicKeyWire(pk).base64)"
        return comment.isEmpty ? text : "\(text) \(comment)"
    }

    /// Parse `ssh-ed25519 <base64> [comment]` into the 32-byte public key.
    public static func parsePublicKeyText(_ text: String) throws(SshKeyError) -> Bytes {
        let parts = text.split(whereSeparator: { $0.isWhitespace })
        guard parts.first == Substring(keyType) else { throw .unsupportedKeyType }
        guard parts.count >= 2, let wire = Bytes(base64: String(parts[1])) else { throw .corrupt }
        var r = SshReader(wire, error: SshKeyError.corrupt)
        do {
            guard String(latin1: try r.string()) == keyType else { throw SshKeyError.corrupt }
            let pk = try r.string()
            guard pk.count == 32, r.remaining == 0 else { throw SshKeyError.corrupt }
            return pk
        } catch { throw .corrupt }
    }

    /// `SHA256:<base64>` without padding, as printed by `ssh-keygen -l`.
    public static func fingerprint(_ pk: Bytes) -> String {
        "SHA256:" + Primitives.sha256(publicKeyWire(pk)).base64NoPad
    }

    /// A new device key: `seed32 = RAND(32)` (crypto.md 3.3).
    public static func generate(comment: String = "") -> OpenSshKey {
        let seed = Primitives.random(32)
        return OpenSshKey(seed: seed, publicKey: Primitives.ed25519PublicKey(seed: seed), comment: comment)
    }

    /// Parse an unencrypted OpenSSH Ed25519 private key. Every check in crypto.md 3.2 is a
    /// hard error.
    public static func parsePrivateKey(_ pem: String) throws(SshKeyError) -> OpenSshKey {
        guard let start = pem.range(of: pemBegin), let end = pem.range(of: pemEnd, range: start.upperBound..<pem.endIndex)
        else { throw .notOpenSSH }
        let body = pem[start.upperBound..<end.lowerBound].filter { !$0.isWhitespace }
        guard let blob = Bytes(base64: String(body)) else { throw .corrupt }
        guard blob.count >= magic.count, Array(blob.prefix(magic.count)) == magic else { throw .notOpenSSH }
        do {
            var r = SshReader(Array(blob.dropFirst(magic.count)), error: SshKeyError.corrupt)
            let cipher = String(latin1: try r.string())
            let kdf = String(latin1: try r.string())
            let kdfOptions = try r.string()
            guard try r.u32() == 1 else { throw SshKeyError.corrupt }
            var outer = SshReader(try r.string(), error: SshKeyError.corrupt)
            let section = try r.string()
            guard String(latin1: try outer.string()) == keyType else { throw SshKeyError.unsupportedKeyType }
            let outerPk = try outer.string()
            guard outerPk.count == 32, outer.remaining == 0 else { throw SshKeyError.corrupt }
            switch cipher {
            case "none": break
            case "aes256-ctr": throw SshKeyError.passphraseRequired
            default: throw SshKeyError.unsupportedCipher
            }
            guard r.remaining == 0, kdf == "none", kdfOptions.isEmpty else { throw SshKeyError.corrupt }
            return try parseSection(section, outerPk: outerPk)
        } catch let e as SshKeyError { throw e } catch { throw .corrupt }
    }

    private static func parseSection(_ section: Bytes, outerPk: Bytes) throws -> OpenSshKey {
        let blockSize = 8
        guard section.count % blockSize == 0 else { throw SshKeyError.corrupt }
        var r = SshReader(section, error: SshKeyError.corrupt)
        guard try r.u32() == (try r.u32()) else { throw SshKeyError.corrupt }
        guard String(latin1: try r.string()) == keyType else { throw SshKeyError.corrupt }
        let pk = try r.string()
        var sk = try r.string()
        let commentBytes = try r.string()
        let padding = try r.rest()
        defer { wipe(&sk) }
        guard pk.count == 32, sk.count == 64, padding.count < blockSize else { throw SshKeyError.corrupt }
        for (i, b) in padding.enumerated() where b != UInt8(i + 1) { throw SshKeyError.corrupt }
        let seed = Array(sk.prefix(32))
        guard Array(sk.suffix(32)) == pk, pk == outerPk, Primitives.ed25519PublicKey(seed: seed) == pk else {
            throw SshKeyError.corrupt
        }
        guard let comment = String(bytes: commentBytes, encoding: .utf8) else { throw SshKeyError.corrupt }
        return OpenSshKey(seed: seed, publicKey: pk, comment: comment)
    }

    /// Write an unencrypted Ed25519 key in `openssh-key-v1` format, byte for byte as
    /// `ssh-keygen` does. `checkint` is random unless given (test vectors only).
    public static func writePrivateKey(seed: Bytes, comment: String = "", checkint: UInt32? = nil) -> String {
        precondition(seed.count == 32)
        let pk = Primitives.ed25519PublicKey(seed: seed)
        let check = checkint ?? UInt32.random(in: .min ... .max)
        var body = concat(u32be(check), u32be(check), sshString(Bytes(utf8: keyType)), sshString(pk),
                          sshString(concat(seed, pk)), sshString(Bytes(utf8: comment)))
        let pad = (8 - body.count % 8) % 8
        body += (0..<pad).map { UInt8($0 + 1) }
        var blob = concat(magic, sshString(Bytes(utf8: "none")), sshString(Bytes(utf8: "none")), sshString([]),
                          u32be(1), sshString(publicKeyWire(pk)), sshString(body))
        var lines: [String] = [pemBegin]
        lines.append(contentsOf: wrapLines(blob.base64, width: 70))
        lines.append(contentsOf: [pemEnd, ""])
        let text = lines.joined(separator: "\n")
        wipe(&body)
        wipe(&blob)
        return text
    }

    private static let crockford = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    /// Pairing code (crypto.md 6.5): the first 50 bits of SHA-256(pubWire) in Crockford
    /// base32, grouped `XXXXX-XXXXX`.
    public static func pairingCode(_ pk: Bytes) -> String {
        let d = Primitives.sha256(publicKeyWire(pk))
        var bits: UInt64 = 0
        for i in 0..<7 { bits = bits << 8 | UInt64(d[i]) }
        bits >>= 6
        var code = ""
        for i in stride(from: 9, through: 0, by: -1) { code.append(crockford[Int(bits >> UInt64(5 * i) & 31)]) }
        return "\(code.prefix(5))-\(code.suffix(5))"
    }
}
