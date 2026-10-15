import Foundation

/// The vault keyring (docs/crypto.md 6, 8.4 and 9): plaintext, age encryption, signing and the
/// trust checks. A port of client-obsidian-plugin/src/crypto/keyring.ts.

public let maxKeyringSize = 1024 * 1024

public struct KeyringDevice: Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    /// `ssh-ed25519 AAAA...`
    public var publicKey: String
    public var added: String
    /// Nil for a full device, `"remote-only"` otherwise (docs/remote-only.md 4).
    public var policy: String?

    public init(id: String, name: String, publicKey: String, added: String = "", policy: String? = nil) {
        self.id = id
        self.name = name
        self.publicKey = publicKey
        self.added = added
        self.policy = policy
    }
}

public struct KeyringEpoch: Codable, Equatable, Sendable {
    public var epoch: Int
    /// b64u, 32 bytes.
    public var vdk: String
}

public struct Keyring: Codable, Equatable, Sendable {
    public var v: Int
    public var vaultId: String
    public var version: Int
    public var name: String
    public var indexKey: String
    public var currentEpoch: Int
    public var keys: [KeyringEpoch]
    public var devices: [KeyringDevice]
    /// Optional native age X25519 recipient (`age1...`), crypto.md 9.
    public var recovery: String?
    /// The Ed25519 key derived from the recovery key (`ssh-ed25519 AAAA...`), set with `recovery`.
    public var recoverySigner: String?
    /// The device that set the recovery key, set with `recovery`.
    public var recoverySetBy: String?
    public var updatedBy: String
    public var updatedAt: String

    public static let remoteOnly = "remote-only"

    /// Key material for an epoch.
    public func epochKey(_ epoch: Int? = nil) throws(KeyringError) -> Bytes {
        let e = epoch ?? currentEpoch
        guard let k = keys.first(where: { $0.epoch == e }), let b = Bytes(b64u: k.vdk) else {
            throw KeyringError(.malformed, "keyring has no epoch \(e)")
        }
        return b
    }

    public var indexKeyBytes: Bytes { Bytes(b64u: indexKey) ?? [] }
}

/// A keyring as stored on the server (protocol.md 7.3), with the age file as bytes.
public struct KeyringBlob: Equatable, Sendable {
    public var version: Int
    public var keyring: Bytes
    public var signature: String
    public init(version: Int, keyring: Bytes, signature: String) {
        self.version = version
        self.keyring = keyring
        self.signature = signature
    }
}

/// What the client pins locally after accepting a keyring.
public struct KeyringPin: Codable, Equatable, Sendable {
    public var version: Int
    public var sha256: String
    public init(version: Int, sha256: String) {
        self.version = version
        self.sha256 = sha256
    }
}

public struct TrustedKeyring: Equatable, Sendable {
    public var keyring: Keyring
    public var pin: KeyringPin
}

public struct KeyringContext: Sendable {
    /// This device's Ed25519 seed.
    public var seed: Bytes
    public var vaultId: String
    public var name: String
    public init(seed: Bytes, vaultId: String, name: String) {
        self.seed = seed
        self.vaultId = vaultId
        self.name = name
    }
}

public struct KeyringError: Error, Equatable, CustomStringConvertible {
    public enum Code: String, Sendable {
        case malformed
        case badSignature = "bad-signature"
        case untrustedSigner = "untrusted-signer"
        case notARecipient = "not-a-recipient"
        case wrongVault = "wrong-vault"
        case versionMismatch = "version-mismatch"
        case rollback
        case chainGap = "chain-gap"
        case inconsistent
    }

    public let code: Code
    public let description: String
    public init(_ code: Code, _ description: String) {
        self.code = code
        self.description = description
    }
}

public struct RecoveryKey: Sendable {
    /// `AGE-SECRET-KEY-1...`, shown once and never stored.
    public var identity: String
    /// `age1...`
    public var recipient: String
    /// `ssh-ed25519 AAAA...` of the derived signing key.
    public var signer: String
}

public enum Keyrings {
    static func nowIso() -> String { ISO8601DateFormatter().string(from: Date()) }

    /// The genesis keyring (version 1, epoch 1) for a new vault.
    public static func create(vaultId: String, name: String, device: KeyringDevice, recovery: RecoveryKey? = nil,
                              now: String? = nil) -> Keyring
    {
        let now = now ?? nowIso()
        var vdk = Primitives.random(32)
        defer { wipe(&vdk) }
        var d = device
        d.added = now
        var k = Keyring(v: 1, vaultId: vaultId, version: 1, name: name, indexKey: KDF.indexKey(vdk1: vdk).b64u, currentEpoch: 1,
                        keys: [KeyringEpoch(epoch: 1, vdk: vdk.b64u)], devices: [d], updatedBy: device.id, updatedAt: now)
        if let recovery {
            k.recovery = recovery.recipient
            k.recoverySigner = recovery.signer
            k.recoverySetBy = device.id
        }
        return k
    }

    private static func next(_ prev: Keyring, _ updatedBy: String, _ now: String?) -> Keyring {
        var k = prev
        k.version += 1
        k.updatedBy = updatedBy
        k.updatedAt = now ?? nowIso()
        return k
    }

    public struct UsageError: Error, CustomStringConvertible {
        public let description: String
    }

    /// Pairing (crypto.md 6.5): the next version, with `device` added as a recipient.
    public static func addDevice(_ prev: Keyring, _ device: KeyringDevice, updatedBy: String, now: String? = nil) throws -> Keyring {
        var k = next(prev, updatedBy, now)
        guard !k.devices.contains(where: { $0.id == device.id || $0.publicKey == device.publicKey }) else {
            throw UsageError(description: "device is already in the keyring")
        }
        var d = device
        d.added = k.updatedAt
        k.devices.append(d)
        return k
    }

    /// The next version, with a device's policy set (nil: a full device).
    public static func setPolicy(_ prev: Keyring, deviceId: String, policy: String?, updatedBy: String,
                                 now: String? = nil) throws -> Keyring
    {
        var k = next(prev, updatedBy, now)
        guard let i = k.devices.firstIndex(where: { $0.id == deviceId }) else {
            throw UsageError(description: "device is not in the keyring")
        }
        k.devices[i].policy = policy
        return k
    }

    /// Revocation (crypto.md 8.4): the next version without the devices, with a new epoch, and
    /// without the recovery key if a removed device set it.
    public static func removeDevicesAndRotate(_ prev: Keyring, _ ids: Set<String>, updatedBy: String,
                                              now: String? = nil) throws -> Keyring
    {
        var k = next(prev, updatedBy, now)
        let devices = k.devices.filter { !ids.contains($0.id) }
        guard devices.count == k.devices.count - ids.count else { throw UsageError(description: "device is not in the keyring") }
        guard !devices.isEmpty else { throw UsageError(description: "can't remove the last device") }
        k.devices = devices
        if let by = k.recoverySetBy, ids.contains(by) { clearRecovery(&k) }
        rotate(&k)
        return k
    }

    private static func rotate(_ k: inout Keyring) {
        k.currentEpoch = (k.keys.map(\.epoch).max() ?? 0) + 1
        k.keys.append(KeyringEpoch(epoch: k.currentEpoch, vdk: Primitives.random(32).b64u))
    }

    private static func clearRecovery(_ k: inout Keyring) {
        k.recovery = nil
        k.recoverySigner = nil
        k.recoverySetBy = nil
    }

    /// Set (in `updatedBy`'s name) or clear the recovery key, as a new version (crypto.md 9).
    /// Replacing or removing a key also starts a new epoch, since the old key can still open
    /// the older keyring versions.
    public static func setRecovery(_ prev: Keyring, _ recovery: RecoveryKey?, updatedBy: String, now: String? = nil) -> Keyring {
        var k = next(prev, updatedBy, now)
        if prev.recovery != nil { rotate(&k) }
        clearRecovery(&k)
        if let recovery {
            k.recovery = recovery.recipient
            k.recoverySigner = recovery.signer
            k.recoverySetBy = updatedBy
        }
        return k
    }

    // MARK: Recovery key

    /// The Ed25519 seed that signs recovery uploads, derived from a recovery identity (crypto.md 9).
    public static func recoverySigningSeed(_ identity: String) throws -> Bytes {
        guard case .x25519(let secret)? = Age.Identity.x25519(text: identity) else {
            throw UsageError(description: "not a recovery key")
        }
        return Primitives.hkdf(ikm: secret, salt: [], info: Bytes(utf8: "syncryption/v1/recovery-signing"))
    }

    /// The signer text of a recovery identity.
    public static func recoverySigner(_ identity: String) throws -> String {
        var seed = try recoverySigningSeed(identity)
        defer { wipe(&seed) }
        return OpenSSH.publicKeyText(Primitives.ed25519PublicKey(seed: seed))
    }

    /// A new recovery key. The identity is shown once and never stored.
    public static func generateRecoveryKey() -> RecoveryKey {
        var secret = Primitives.random(32)
        defer { wipe(&secret) }
        let identity = Age.identityText(secret: secret)
        return RecoveryKey(identity: identity, recipient: Age.recipientText(publicKey: Primitives.x25519Base(secret)),
                           signer: (try? recoverySigner(identity)) ?? "")
    }

    // MARK: Seal and open

    /// Encrypt to every device (and the recovery key), then sign with `seed`: a device in the
    /// keyring, or the recovery signer.
    public static func seal(_ keyring: Keyring, seed: Bytes) throws -> KeyringBlob {
        try validate(keyring)
        let signer = OpenSSH.publicKeyText(Primitives.ed25519PublicKey(seed: seed))
        guard keyring.devices.contains(where: { $0.publicKey == signer }) || keyring.recoverySigner == signer else {
            throw UsageError(description: "the signing device must be in the keyring")
        }
        var recipients: [Age.Recipient] = try keyring.devices.map { .sshEd25519(try OpenSSH.parsePublicKeyText($0.publicKey)) }
        if let r = keyring.recovery {
            guard let rec = Age.Recipient.x25519(text: r) else { throw UsageError(description: "invalid recovery recipient") }
            recipients.append(rec)
        }
        let age = try Age.encrypt(Bytes(try Objects.jsonEncoder.encode(keyring)), to: recipients)
        guard age.count <= maxKeyringSize else { throw UsageError(description: "keyring too large") }
        return KeyringBlob(version: keyring.version, keyring: age,
                           signature: SshSig.sign(seed: seed, namespace: SshSig.namespaceKeyring, message: age))
    }

    /// Verify, decrypt and check a keyring (crypto.md 6.3, 6.4).
    ///
    /// - With `trusted`, the keyring must be the same version and bytes, or exactly the next
    ///   version signed by a device in `trusted.keyring.devices` or its recovery signer. Further
    ///   ahead is `chain-gap`: use `openChain`.
    /// - Without `trusted` (first use), the signer must be in the keyring's own `devices` or be
    ///   its own recovery signer.
    public static func open(_ blob: KeyringBlob, _ ctx: KeyringContext, trusted: TrustedKeyring? = nil) throws(KeyringError) -> TrustedKeyring {
        try open(blob, vaultId: ctx.vaultId, name: ctx.name, identity: .sshEd25519(seed: ctx.seed), trusted: trusted)
    }

    /// Open the current keyring with a recovery identity instead of a device key (crypto.md 9),
    /// on first use. The keyring's `recoverySigner` must be the one this identity derives.
    public static func openWithRecovery(_ blob: KeyringBlob, vaultId: String, name: String, identity: String) throws -> TrustedKeyring {
        let signer = try recoverySigner(identity)
        guard let id = Age.Identity.x25519(text: identity) else { throw UsageError(description: "not a recovery key") }
        let opened = try open(blob, vaultId: vaultId, name: name, identity: id, trusted: nil)
        guard opened.keyring.recoverySigner == signer else {
            throw KeyringError(.inconsistent, "keyring names another recovery signer")
        }
        return opened
    }

    /// Walk from `trusted` through each later version in order, checking every link.
    public static func openChain(_ blobs: [KeyringBlob], _ ctx: KeyringContext, trusted: TrustedKeyring) throws(KeyringError) -> TrustedKeyring {
        var current = trusted
        for blob in blobs.sorted(by: { $0.version < $1.version }) where blob.version > current.pin.version {
            current = try open(blob, ctx, trusted: current)
        }
        return current
    }

    private static func open(_ blob: KeyringBlob, vaultId: String, name: String, identity: Age.Identity,
                             trusted: TrustedKeyring?) throws(KeyringError) -> TrustedKeyring
    {
        guard blob.keyring.count <= maxKeyringSize else { throw KeyringError(.malformed, "keyring too large") }
        let signerKey: Bytes
        do { signerKey = try SshSig.verify(blob.signature, namespace: SshSig.namespaceKeyring, message: blob.keyring) } catch {
            throw KeyringError(.badSignature, "keyring signature is invalid")
        }
        let pin = KeyringPin(version: blob.version, sha256: Primitives.sha256(blob.keyring).hex)
        if let trusted {
            if blob.version < trusted.pin.version { throw KeyringError(.rollback, "server keyring is older than the pinned one") }
            if blob.version == trusted.pin.version && pin.sha256 != trusted.pin.sha256 {
                throw KeyringError(.rollback, "server keyring differs from the pinned one")
            }
            if blob.version > trusted.pin.version + 1 {
                throw KeyringError(.chainGap, "keyring versions must be checked one by one")
            }
        }

        let keyring = try decrypt(blob.keyring, identity)
        guard keyring.vaultId == vaultId, keyring.name == name else { throw KeyringError(.wrongVault, "keyring belongs to another vault") }
        guard keyring.version == blob.version else {
            throw KeyringError(.versionMismatch, "keyring version differs from the server's")
        }

        let authority = if let trusted, blob.version > trusted.pin.version { trusted.keyring } else { keyring }
        let signer = authority.devices.first { (try? OpenSSH.parsePublicKeyText($0.publicKey)) == signerKey }
        let byRecovery = signer == nil
            && authority.recoverySigner.flatMap { try? OpenSSH.parsePublicKeyText($0) } == signerKey
        guard signer != nil || byRecovery else { throw KeyringError(.untrustedSigner, "keyring was signed by an unknown device") }
        // A remote-only device can't manage the vault, so it never signs a keyring.
        if signer?.policy != nil { throw KeyringError(.untrustedSigner, "keyring was signed by a remote-only device") }
        if let trusted { try checkConsistent(trusted.keyring, keyring, signer: signer) }
        return TrustedKeyring(keyring: keyring, pin: pin)
    }

    private static func decrypt(_ age: Bytes, _ identity: Age.Identity) throws(KeyringError) -> Keyring {
        let plain: Bytes
        do { plain = try Age.decrypt(age, with: [identity]) } catch {
            if error == .noIdentityMatched { throw KeyringError(.notARecipient, "this device is not in the keyring") }
            throw KeyringError(.malformed, "keyring failed to decrypt")
        }
        let k: Keyring
        do { k = try JSONDecoder().decode(Keyring.self, from: Data(plain)) } catch {
            throw KeyringError(.malformed, "keyring is not valid JSON or has the wrong shape")
        }
        try validate(k)
        return k
    }

    private static func malformed(_ why: String) -> KeyringError { KeyringError(.malformed, "keyring is malformed: \(why)") }

    private static func isKey32(_ s: String) -> Bool { Bytes(b64u: s)?.count == 32 }

    static func validate(_ k: Keyring) throws(KeyringError) {
        let maxSafe = (1 << 53) - 1
        let posInt = { (x: Int) in x >= 1 && x <= maxSafe }
        guard k.v == 1 else { throw malformed("unsupported format version") }
        guard posInt(k.version), posInt(k.currentEpoch) else { throw malformed("version or currentEpoch") }
        guard isKey32(k.indexKey) else { throw malformed("indexKey") }
        let recovery = [k.recovery, k.recoverySigner, k.recoverySetBy]
        if recovery.contains(where: { $0 != nil }) {
            guard recovery.allSatisfy({ $0 != nil }) else { throw malformed("recovery fields must be set together") }
            guard k.recovery!.hasPrefix("age1") else { throw malformed("recovery") }
            guard (try? OpenSSH.parsePublicKeyText(k.recoverySigner!)) != nil else { throw malformed("recoverySigner") }
        }
        guard !k.keys.isEmpty else { throw malformed("keys") }
        var epochs = Set<Int>()
        for e in k.keys {
            guard posInt(e.epoch), isKey32(e.vdk) else { throw malformed("key epoch") }
            guard epochs.insert(e.epoch).inserted else { throw malformed("duplicate epoch") }
        }
        guard epochs.contains(k.currentEpoch) else { throw malformed("currentEpoch is not in keys") }
        guard let first = k.keys.first(where: { $0.epoch == 1 }), let vdk1 = Bytes(b64u: first.vdk),
              constantTimeEqual(KDF.indexKey(vdk1: vdk1), k.indexKeyBytes)
        else { throw malformed("indexKey does not match epoch 1") }
        guard !k.devices.isEmpty else { throw malformed("devices") }
        var ids = Set<String>()
        for d in k.devices {
            guard (try? OpenSSH.parsePublicKeyText(d.publicKey)) != nil else { throw malformed("device public key") }
            guard d.policy == nil || d.policy == Keyring.remoteOnly else { throw malformed("device policy") }
            guard ids.insert(d.id).inserted else { throw malformed("duplicate device") }
        }
    }

    /// A newer keyring may add epochs and devices, but never change what was trusted. Only a
    /// device (`signer`, from `prev`) may change the recovery key, in its own name, or set,
    /// change or remove a device's policy.
    private static func checkConsistent(_ prev: Keyring, _ k: Keyring, signer: KeyringDevice?) throws(KeyringError) {
        func fail(_ why: String) -> KeyringError { KeyringError(.inconsistent, "keyring changed \(why)") }
        guard k.indexKey == prev.indexKey else { throw fail("its indexKey") }
        for e in prev.keys where k.keys.first(where: { $0.epoch == e.epoch })?.vdk != e.vdk { throw fail("epoch \(e.epoch)") }
        guard k.currentEpoch >= prev.currentEpoch else { throw fail("to an older epoch") }
        let changed = k.recovery != prev.recovery || k.recoverySigner != prev.recoverySigner || k.recoverySetBy != prev.recoverySetBy
        if changed {
            guard let signer else { throw fail("its recovery key, signed by the recovery key") }
            if k.recovery != nil && k.recoverySetBy != signer.id { throw fail("its recovery key in another device's name") }
        }
        if signer == nil {
            let before = Dictionary(prev.devices.map { ($0.id, $0.policy) }, uniquingKeysWith: { a, _ in a })
            for d in k.devices {
                let changedPolicy = if let old = before[d.id] { old != d.policy } else { d.policy != nil }
                if changedPolicy { throw fail("a device policy, signed by the recovery key") }
            }
        }
    }
}
