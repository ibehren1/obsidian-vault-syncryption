import Foundation

/// age v1 (age-encryption.org/v1) with the `ssh-ed25519` stanza (docs/crypto.md 4) and the
/// native X25519 stanza (the recovery key, crypto.md 9). Interoperable with Go `age` and
/// `rage`; checked against their files in testvectors/age-ssh-ed25519.json.
public enum Age {
    public enum Failure: Error, Equatable {
        /// The header or payload is malformed, or the MAC or a chunk didn't verify.
        case malformed
        /// A stanza of a type we handle is malformed.
        case invalidStanza
        /// No stanza could be opened with the given identities.
        case noIdentityMatched
    }

    public struct Stanza: Equatable, Sendable {
        public var args: [String]
        public var body: Bytes
        public init(args: [String], body: Bytes) {
            self.args = args
            self.body = body
        }
    }

    public enum Recipient: Sendable {
        /// A 32-byte Ed25519 public key.
        case sshEd25519(Bytes)
        /// A 32-byte X25519 public key.
        case x25519(Bytes)

        /// Parse `age1...`.
        public static func x25519(text: String) -> Recipient? {
            guard let (hrp, data) = Bech32.decode(text), hrp == "age", data.count == 32 else { return nil }
            return .x25519(data)
        }
    }

    public enum Identity: Sendable {
        /// A 32-byte Ed25519 seed.
        case sshEd25519(seed: Bytes)
        /// A 32-byte X25519 secret.
        case x25519(secret: Bytes)

        /// Parse `AGE-SECRET-KEY-1...` (either case).
        public static func x25519(text: String) -> Identity? {
            guard let (hrp, data) = Bech32.decode(text.trimmingCharacters(in: .whitespacesAndNewlines)),
                  hrp == "age-secret-key-", data.count == 32 else { return nil }
            return .x25519(secret: data)
        }
    }

    /// `AGE-SECRET-KEY-1...` for a 32-byte X25519 secret.
    public static func identityText(secret: Bytes) -> String {
        Bech32.encode(hrp: "age-secret-key-", secret).uppercased()
    }

    /// `age1...` for a 32-byte X25519 public key.
    public static func recipientText(publicKey: Bytes) -> String { Bech32.encode(hrp: "age", publicKey) }

    // MARK: Stanzas

    static let sshLabel = Bytes(utf8: "age-encryption.org/v1/ssh-ed25519")
    static let x25519Label = Bytes(utf8: "age-encryption.org/v1/X25519")
    static let zeroNonce = Bytes(repeating: 0, count: 12)
    static let fileKeySize = 16

    static func sshTag(_ wire: Bytes) -> String { Array(Primitives.sha256(wire).prefix(4)).base64NoPad }

    static func sshTweak(_ wire: Bytes) -> Bytes { Primitives.hkdf(ikm: [], salt: wire, info: sshLabel) }

    /// The deterministic core of the `ssh-ed25519` wrap, with the ephemeral secret passed in.
    /// Only tests call this directly; `encrypt` uses a fresh random ephemeral every time.
    static func wrapSshEd25519(publicKey: Bytes, fileKey: Bytes, ephemeral: Bytes) throws(Failure) -> Stanza {
        guard let pkX = Primitives.ed25519PublicToX25519(publicKey) else { throw .invalidStanza }
        let wire = OpenSSH.publicKeyWire(publicKey)
        let ePk = Primitives.x25519Base(ephemeral)
        guard let inner = Primitives.x25519(ephemeral, pkX), let shared = Primitives.x25519(sshTweak(wire), inner) else {
            throw .invalidStanza
        }
        let wrapKey = Primitives.hkdf(ikm: shared, salt: ePk + pkX, info: sshLabel)
        return Stanza(args: ["ssh-ed25519", sshTag(wire), ePk.base64NoPad],
                      body: Primitives.chachaSeal(key: wrapKey, nonce: zeroNonce, fileKey))
    }

    static func wrapX25519(publicKey: Bytes, fileKey: Bytes, ephemeral: Bytes) throws(Failure) -> Stanza {
        let ePk = Primitives.x25519Base(ephemeral)
        guard let shared = Primitives.x25519(ephemeral, publicKey) else { throw .invalidStanza }
        let wrapKey = Primitives.hkdf(ikm: shared, salt: ePk + publicKey, info: x25519Label)
        return Stanza(args: ["X25519", ePk.base64NoPad], body: Primitives.chachaSeal(key: wrapKey, nonce: zeroNonce, fileKey))
    }

    /// The file key, nil if the stanza isn't for this identity. Throws on a malformed stanza
    /// of the identity's type, as Go age does.
    static func unwrap(_ s: Stanza, with identity: Identity) throws(Failure) -> Bytes? {
        switch identity {
        case .sshEd25519(let seed):
            guard s.args.first == "ssh-ed25519" else { return nil }
            guard s.args.count == 3, let ePk = Bytes(base64NoPad: s.args[2]), ePk.count == 32 else { throw .invalidStanza }
            let pk = Primitives.ed25519PublicKey(seed: seed)
            let wire = OpenSSH.publicKeyWire(pk)
            guard s.args[1] == sshTag(wire) else { return nil }
            guard s.body.count == fileKeySize + 16 else { throw .invalidStanza }
            guard let pkX = Primitives.ed25519PublicToX25519(pk),
                  let inner = Primitives.x25519(Primitives.ed25519SeedToX25519(seed), ePk),
                  let shared = Primitives.x25519(sshTweak(wire), inner)
            else { throw .invalidStanza }
            let wrapKey = Primitives.hkdf(ikm: shared, salt: ePk + pkX, info: sshLabel)
            return Primitives.chachaOpen(key: wrapKey, nonce: zeroNonce, s.body)
        case .x25519(let secret):
            guard s.args.first == "X25519" else { return nil }
            guard s.args.count == 2, let ePk = Bytes(base64NoPad: s.args[1]), ePk.count == 32,
                  s.body.count == fileKeySize + 16
            else { throw .invalidStanza }
            guard let shared = Primitives.x25519(secret, ePk) else { throw .invalidStanza }
            let pk = Primitives.x25519Base(secret)
            let wrapKey = Primitives.hkdf(ikm: shared, salt: ePk + pk, info: x25519Label)
            return Primitives.chachaOpen(key: wrapKey, nonce: zeroNonce, s.body)
        }
    }

    // MARK: Files

    private static let intro = Bytes(utf8: "age-encryption.org/v1\n")
    private static let chunkSize = 64 * 1024

    /// Encrypt `plaintext` to every recipient.
    public static func encrypt(_ plaintext: Bytes, to recipients: [Recipient]) throws(Failure) -> Bytes {
        precondition(!recipients.isEmpty)
        var fileKey = Primitives.random(fileKeySize)
        defer { wipe(&fileKey) }
        var header = intro
        for r in recipients {
            var e = Primitives.random(32)
            defer { wipe(&e) }
            let s = switch r {
            case .sshEd25519(let pk): try wrapSshEd25519(publicKey: pk, fileKey: fileKey, ephemeral: e)
            case .x25519(let pk): try wrapX25519(publicKey: pk, fileKey: fileKey, ephemeral: e)
            }
            header += Bytes(utf8: "-> " + s.args.joined(separator: " ") + "\n")
            let lines = wrapLines(s.body.base64NoPad, width: 64)
            for l in lines { header += Bytes(utf8: l + "\n") }
            if s.body.base64NoPad.count % 64 == 0 { header += Bytes(utf8: "\n") }
        }
        header += Bytes(utf8: "---")
        let mac = Primitives.hmacSHA256(key: Primitives.hkdf(ikm: fileKey, salt: [], info: Bytes(utf8: "header")), header)
        header += Bytes(utf8: " " + mac.base64NoPad + "\n")

        let nonce = Primitives.random(16)
        var payloadKey = Primitives.hkdf(ikm: fileKey, salt: nonce, info: Bytes(utf8: "payload"))
        defer { wipe(&payloadKey) }
        var out = header + nonce
        var counter: UInt64 = 0
        var offset = 0
        repeat {
            let end = min(offset + chunkSize, plaintext.count)
            let last = end == plaintext.count
            out += Primitives.chachaSeal(key: payloadKey, nonce: streamNonce(counter, last: last),
                                         Array(plaintext[offset..<end]))
            counter += 1
            offset = end
        } while offset < plaintext.count
        return out
    }

    /// The STREAM nonce: an 11-byte big-endian counter, then 1 for the last chunk.
    private static func streamNonce(_ counter: UInt64, last: Bool) -> Bytes {
        var nonce = Bytes(repeating: 0, count: 12)
        for i in 0..<8 {
            let shift = UInt64(56 - 8 * i)
            nonce[3 + i] = UInt8(truncatingIfNeeded: counter >> shift)
        }
        if last { nonce[11] = 1 }
        return nonce
    }

    /// Decrypt with the first identity that opens a stanza.
    public static func decrypt(_ file: Bytes, with identities: [Identity]) throws(Failure) -> Bytes {
        let (stanzas, macInput, mac, payloadStart) = try parseHeader(file)
        var fileKey: Bytes?
        search: for id in identities {
            for s in stanzas {
                if let k = try unwrap(s, with: id) {
                    fileKey = k
                    break search
                }
            }
        }
        guard var key = fileKey else { throw .noIdentityMatched }
        defer { wipe(&key) }
        let expected = Primitives.hmacSHA256(key: Primitives.hkdf(ikm: key, salt: [], info: Bytes(utf8: "header")), macInput)
        guard constantTimeEqual(expected, mac) else { throw .malformed }

        guard file.count - payloadStart >= 16 else { throw .malformed }
        let nonce = Array(file[payloadStart..<(payloadStart + 16)])
        var payloadKey = Primitives.hkdf(ikm: key, salt: nonce, info: Bytes(utf8: "payload"))
        defer { wipe(&payloadKey) }
        var out = Bytes()
        var offset = payloadStart + 16
        var counter: UInt64 = 0
        guard offset < file.count else { throw .malformed }
        while offset < file.count {
            let end = min(offset + chunkSize + 16, file.count)
            let last = end == file.count
            guard let plain = Primitives.chachaOpen(key: payloadKey, nonce: streamNonce(counter, last: last),
                                                    Array(file[offset..<end]))
            else { throw .malformed }
            if plain.isEmpty && last && counter > 0 { throw .malformed }
            out += plain
            counter += 1
            offset = end
        }
        return out
    }

    /// Splits the header into stanzas, the bytes the MAC covers, the MAC and where the
    /// payload starts.
    static func parseHeader(_ file: Bytes) throws(Failure) -> ([Stanza], Bytes, Bytes, Int) {
        var pos = 0
        func line() throws(Failure) -> String {
            guard let nl = file[pos...].firstIndex(of: 0x0a) else { throw .malformed }
            let bytes = file[pos..<nl]
            guard bytes.allSatisfy({ $0 >= 0x20 && $0 < 0x7f }) else { throw .malformed }
            pos = nl + 1
            return String(decoding: bytes, as: UTF8.self)
        }
        guard try line() == "age-encryption.org/v1" else { throw .malformed }
        var stanzas: [Stanza] = []
        while true {
            let start = pos
            let l = try line()
            if l.hasPrefix("--- ") {
                guard let mac = Bytes(base64NoPad: String(l.dropFirst(4))), mac.count == 32 else { throw .malformed }
                return (stanzas, Array(file[0..<(start + 3)]), mac, pos)
            }
            guard l.hasPrefix("-> ") else { throw .malformed }
            let args = l.dropFirst(3).split(separator: " ", omittingEmptySubsequences: false).map(String.init)
            guard !args.isEmpty, args.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7f } }) else {
                throw .malformed
            }
            var body = ""
            while true {
                let b = try line()
                guard b.count <= 64 else { throw .malformed }
                body += b
                if b.count < 64 { break }
            }
            guard let decoded = Bytes(base64NoPad: body) else { throw .malformed }
            stanzas.append(Stanza(args: args, body: decoded))
        }
    }
}
