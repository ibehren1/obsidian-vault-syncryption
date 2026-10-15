import Foundation

/// OpenSSH signatures (`PROTOCOL.sshsig`, docs/crypto.md 7), Ed25519 and SHA-512 only.
/// Output is byte-identical to `ssh-keygen -Y sign`, since Ed25519 is deterministic.
public enum SshSig {
    public static let namespaceAuth = "syncryption-auth@v1"
    public static let namespaceKeyring = "syncryption-keyring@v1"

    public enum Failure: Error, Equatable {
        case invalid
        case unsupportedKeyType
        case wrongNamespace
    }

    private static let magic = Bytes(utf8: "SSHSIG")
    private static let hash = "sha512"
    private static let keyType = "ssh-ed25519"
    private static let begin = "-----BEGIN SSH SIGNATURE-----"
    private static let end = "-----END SSH SIGNATURE-----"

    private static func signedData(_ namespace: String, _ message: Bytes) -> Bytes {
        concat(magic, sshString(Bytes(utf8: namespace)), sshString([]), sshString(Bytes(utf8: hash)),
               sshString(Primitives.sha512(message)))
    }

    public static func sign(seed: Bytes, namespace: String, message: Bytes) -> String {
        precondition(!namespace.isEmpty)
        let pk = Primitives.ed25519PublicKey(seed: seed)
        let sig = Primitives.ed25519Sign(seed: seed, signedData(namespace, message))
        let signature = concat(sshString(Bytes(utf8: keyType)), sshString(sig))
        let blob = concat(magic, u32be(1), sshString(OpenSSH.publicKeyWire(pk)), sshString(Bytes(utf8: namespace)),
                          sshString([]), sshString(Bytes(utf8: hash)), sshString(signature))
        var lines: [String] = [begin]
        lines.append(contentsOf: wrapLines(blob.base64, width: 70))
        lines.append(contentsOf: [end, ""])
        return lines.joined(separator: "\n")
    }

    /// Verify an armored sshsig over `message` in `namespace`. Returns the signer's 32-byte
    /// Ed25519 public key; the caller decides whether that key is trusted.
    public static func verify(_ armored: String, namespace: String, message: Bytes) throws(Failure) -> Bytes {
        let text = armored.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.hasPrefix(begin), text.hasSuffix(end), text.count >= begin.count + end.count else { throw .invalid }
        let body = text.dropFirst(begin.count).dropLast(end.count).filter { !$0.isWhitespace }
        guard let blob = Bytes(base64: String(body)) else { throw .invalid }
        do {
            var r = SshReader(blob, error: Failure.invalid)
            guard try r.bytes(magic.count) == magic, try r.u32() == 1 else { throw Failure.invalid }
            let pubWire = try r.string()
            let ns = try r.string()
            let reserved = try r.string()
            let h = try r.string()
            let sigBlob = try r.string()
            guard r.remaining == 0 else { throw Failure.invalid }
            var pub = SshReader(pubWire, error: Failure.invalid)
            guard String(latin1: try pub.string()) == keyType else { throw Failure.unsupportedKeyType }
            let pk = try pub.string()
            guard pk.count == 32, pub.remaining == 0 else { throw Failure.invalid }
            guard String(latin1: ns) == namespace else { throw Failure.wrongNamespace }
            guard reserved.isEmpty, String(latin1: h) == hash else { throw Failure.invalid }
            var s = SshReader(sigBlob, error: Failure.invalid)
            guard String(latin1: try s.string()) == keyType else { throw Failure.invalid }
            let sig = try s.string()
            guard sig.count == 64, s.remaining == 0 else { throw Failure.invalid }
            guard Primitives.ed25519Verify(publicKey: pk, signature: sig, signedData(namespace, message)) else {
                throw Failure.invalid
            }
            return pk
        } catch let e as Failure { throw e } catch { throw .invalid }
    }
}
