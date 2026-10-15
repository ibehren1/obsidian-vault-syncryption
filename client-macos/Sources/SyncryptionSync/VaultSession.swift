import Foundation
import SyncryptionAPI
import SyncryptionCrypto
import SyncryptionStore

/// Connecting to a vault (docs/protocol.md 5 and 7, crypto.md 6): log in or join, open or
/// create the vault, wait for pairing or recover with the recovery key, and fetch and verify
/// the keyring. Also approving other keys, removing keys, replacing this device's key and
/// setting the recovery key. A port of client-obsidian-plugin/src/sync/session.ts.

public struct SetupCancelled: Error, CustomStringConvertible {
    public let description = "Setup was cancelled."
}

/// The macOS client syncs full devices only (PLAN, macOS Client): a key approved as
/// remote-only, or made remote-only later, doesn't sync.
public struct RemoteOnlyRefused: Error, CustomStringConvertible {
    public let description = "This key is remote-only. The macOS client supports full devices only: remove this key from another device of the vault, or make it a full device there."
}

public protocol ConnectCallbacks: Sendable {
    /// The server needs the shared secret to create the vault. Nil if the user cancels.
    func askSharedSecret() async -> String?
    /// This device must be approved from an active device. Called once with the code to show,
    /// then the session polls until it is approved or the task is cancelled. `canRecover` is
    /// true when the vault exists: `VaultSession.recover` then adds this device with the
    /// vault's recovery key instead.
    func showPairing(code: String, canRecover: Bool) async
}

private func blob(_ k: SyncryptionAPI.Keyring) throws -> KeyringBlob {
    guard let bytes = Bytes(b64u: k.keyring) else { throw KeyringError.malformedBlob }
    return KeyringBlob(version: k.version, keyring: bytes, signature: k.signature)
}

extension KeyringError {
    static let malformedBlob = KeyringError(.malformed, "keyring is not base64url")
}

func upload(_ b: KeyringBlob, _ keyring: SyncryptionCrypto.Keyring, signer: String) -> KeyringUpload {
    KeyringUpload(keyring: b.keyring.b64u, recoverySigner: keyring.recoverySigner, signature: b.signature, signer: signer, version: b.version)
}

/// This device's keyring entry, found by its public key. Its id must be the one the server
/// returned at login: a server that returns another device's id would otherwise make this
/// device follow that device's policy.
func selfEntry(_ k: SyncryptionCrypto.Keyring, publicKey: String, deviceId: String?) throws -> KeyringDevice {
    guard let entry = k.devices.first(where: { $0.publicKey == publicKey }) else {
        throw DeviceMismatchError(description: "This device's key isn't in the vault's keyring.")
    }
    guard entry.id == deviceId else { throw DeviceMismatchError(description: "The server returned another device's id for this key.") }
    return entry
}

private func fetchTrusted(_ api: ApiClient, _ vault: Vault, _ seed: Bytes, _ trusted: TrustedKeyring?) async throws -> TrustedKeyring {
    let ctx = KeyringContext(seed: seed, vaultId: vault.id, name: vault.name)
    let latest = try blob(try await api.keyring(vault.id))
    let opened: TrustedKeyring
    if let trusted {
        if latest.version <= trusted.pin.version + 1 {
            opened = try Keyrings.open(latest, ctx, trusted: trusted)
        } else {
            var blobs = [latest]
            for v in (trusted.pin.version + 1)..<latest.version { blobs.append(try blob(try await api.keyring(vault.id, version: v))) }
            opened = try Keyrings.openChain(blobs, ctx, trusted: trusted)
        }
    } else {
        opened = try Keyrings.open(latest, ctx)
    }
    _ = try selfEntry(opened.keyring, publicKey: OpenSSH.publicKeyText(Primitives.ed25519PublicKey(seed: seed)),
                      deviceId: await api.deviceId)
    return opened
}

/// A connected vault: the keyring is verified and pinned.
public actor VaultSession: KeyringSource {
    public nonisolated let api: ApiClient
    public nonisolated let vault: Vault
    public nonisolated let store: any SyncStore
    private var trusted: TrustedKeyring
    private let seed: Bytes
    private nonisolated let publicKey: String
    /// The keyring, readable without awaiting (the cipher reads it for every file).
    private nonisolated let current: KeyringBox

    final class KeyringBox: @unchecked Sendable {
        private let lock = NSLock()
        private var value: SyncryptionCrypto.Keyring
        init(_ v: SyncryptionCrypto.Keyring) { value = v }
        var keyring: SyncryptionCrypto.Keyring {
            get { lock.withLock { value } }
            set { lock.withLock { value = newValue } }
        }
    }

    init(api: ApiClient, vault: Vault, store: any SyncStore, trusted: TrustedKeyring, seed: Bytes) {
        self.api = api
        self.vault = vault
        self.store = store
        self.trusted = trusted
        self.seed = seed
        publicKey = OpenSSH.publicKeyText(Primitives.ed25519PublicKey(seed: seed))
        current = KeyringBox(trusted.keyring)
    }

    public nonisolated var keyring: SyncryptionCrypto.Keyring { current.keyring }

    public nonisolated var cipher: VaultCipher {
        let box = current
        return VaultCipher { box.keyring }
    }

    public func deviceId() async -> String { await api.deviceId ?? "" }

    public func version() async -> Int { trusted.pin.version }

    /// Fetch the latest keyring and check it against the pinned one (crypto.md 6.4).
    public func refresh() async throws { try await refreshKeyring() }

    public func refreshKeyring() async throws {
        trusted = try await fetchTrusted(api, vault, seed, trusted)
        current.keyring = trusted.keyring
        try store.setMeta(MetaKey.keyringPin, trusted.pin)
    }

    /// This device's policy in the keyring, from the entry with this device's public key. The
    /// server's copy isn't trusted, nor is the device id it returned.
    public func isRemoteOnly() async throws -> Bool {
        try selfEntry(keyring, publicKey: publicKey, deviceId: await api.deviceId).policy == SyncryptionCrypto.Keyring.remoteOnly
    }

    /// Every key of this vault on the server, revoked ones included.
    public func devices() async throws -> [Device] { try await api.devices(vault.id) }

    /// Keys waiting for approval, with the pairing code computed here, not by the server.
    /// Keys waiting for approval. The pairing code and fingerprint are computed here from the
    /// public key that approving adds: the server's `fingerprint` could name another key.
    public func pendingDevices() async throws -> [(device: Device, code: String, fingerprint: String)] {
        try await devices().filter { $0.status == "pending" }.map { d in
            let key = try OpenSSH.parsePublicKeyText(d.publicKey)
            return (d, OpenSSH.pairingCode(key), OpenSSH.fingerprint(key))
        }
    }

    /// Pairing, active side (crypto.md 6.5): add the key to the keyring, upload it signed,
    /// then approve it. The user must have compared the pairing codes.
    public func approve(id: String, name: String, publicKey text: String, remoteOnly: Bool = false) async throws {
        let key = OpenSSH.publicKeyText(try OpenSSH.parsePublicKeyText(text))
        let policy = remoteOnly ? SyncryptionCrypto.Keyring.remoteOnly : nil
        let me = await deviceId()
        try await update { k in
            if let existing = k.devices.first(where: { $0.publicKey == key }) {
                // Approved before, but the approval didn't reach the server: follow this choice.
                return existing.policy == policy ? nil : try Keyrings.setPolicy(k, deviceId: existing.id, policy: policy, updatedBy: me)
            }
            return try Keyrings.addDevice(k, KeyringDevice(id: id, name: name, publicKey: key, policy: policy), updatedBy: me)
        }
        _ = try await api.approveDevice(vault.id, id, remoteOnly: remoteOnly)
    }

    public struct Refused: Error, CustomStringConvertible {
        public let description: String
    }

    /// Make another active device remote-only, or a full device again: the keyring first,
    /// which is what the device follows, then the server.
    public func setPolicy(deviceId target: String, remoteOnly: Bool) async throws {
        let me = await deviceId()
        guard target != me else { throw Refused(description: "This device can't change its own policy.") }
        let policy = remoteOnly ? SyncryptionCrypto.Keyring.remoteOnly : nil
        try await update { k in
            guard let entry = k.devices.first(where: { $0.id == target }) else { throw Refused(description: "That device isn't in the keyring.") }
            return entry.policy == policy ? nil : try Keyrings.setPolicy(k, deviceId: target, policy: policy, updatedBy: me)
        }
        _ = try await api.setDevicePolicy(vault.id, target, remoteOnly: remoteOnly)
    }

    /// Lock or unlock another remote-only device. Only the server knows.
    public func setLocked(deviceId target: String, locked: Bool) async throws {
        _ = try await api.setDeviceLocked(vault.id, target, locked: locked)
    }

    /// Revocation (crypto.md 8.4): revoke the key on the server first, then remove it from the
    /// keyring with a new epoch. Other devices re-encrypt their files in the background.
    public func removeDevice(_ target: String) async throws {
        try await removeDevices([target])
    }

    /// `removeDevice` for several keys, with one rotation.
    public func removeDevices(_ ids: [String]) async throws {
        guard !ids.contains(await deviceId()) else { throw Refused(description: "This device can't remove its own key.") }
        // Noted first, so an interrupted removal is finished at the next start without asking.
        try updateList(MetaKey.revokingDevices) { l in l + ids.filter { !l.contains($0) } }
        for id in ids {
            do { try await api.removeDevice(vault.id, id) } catch let e as ApiError where e.status == 404 {
                // Already gone from the server: the keyring still has to follow.
            }
        }
        try await rotateOut(ids)
        try updateList(MetaKey.revokingDevices) { $0.filter { !ids.contains($0) } }
        try updateList(MetaKey.keptDevices) { $0.filter { !ids.contains($0) } }
    }

    public struct StaleDevices: Equatable, Sendable {
        /// The names of the devices whose removal this device finished.
        public let removed: [String]
        /// Devices the server reports removed that this device didn't remove: the user decides.
        public let unconfirmed: [KeyringDevice]
    }

    /// Keyring devices whose key is revoked or gone on the server. Those this device started
    /// removing are removed from the keyring (a rotation that didn't finish); the others are
    /// returned, apart from those the user chose to keep: only the user decides that another
    /// device's removal is real, since the server's word alone could expel a legitimate device.
    public func removeStaleDevices() async throws -> StaleDevices {
        let status = Dictionary(try await devices().map { ($0.id, $0.status) }, uniquingKeysWith: { a, _ in a })
        try await refreshKeyring()
        let me = await deviceId()
        let stale = keyring.devices.filter { $0.id != me && (status[$0.id] ?? "revoked") == "revoked" }
        let revoking = try list(MetaKey.revokingDevices), kept = try list(MetaKey.keptDevices)
        let own = stale.filter { revoking.contains($0.id) }
        if !own.isEmpty { try await removeDevices(own.map(\.id)) }
        return StaleDevices(removed: own.map(\.name),
                            unconfirmed: stale.filter { !revoking.contains($0.id) && !kept.contains($0.id) })
    }

    /// The user keeps these devices in the keyring although the server reports them removed.
    public func keepDevices(_ ids: [String]) throws {
        try updateList(MetaKey.keptDevices) { l in l + ids.filter { !l.contains($0) } }
    }

    private func list(_ key: String) throws -> [String] { try store.meta(key, as: [String].self) ?? [] }

    private func updateList(_ key: String, _ change: ([String]) -> [String]) throws {
        try store.setMeta(key, change(try list(key)))
    }

    /// After a key change (`handOver`): remove the replaced key, if this is the new one.
    public func finishReplace() async throws -> Bool {
        guard let old = try store.meta(MetaKey.replacedDevice, as: String.self) else { return false }
        let removed = old != (await deviceId())
        if removed { try await removeDevice(old) }
        try store.setMeta(MetaKey.replacedDevice, String?.none)
        return removed
    }

    private func rotateOut(_ ids: [String]) async throws {
        let me = await deviceId()
        try await update { k in
            let gone = Set(ids.filter { id in k.devices.contains { $0.id == id } })
            return gone.isEmpty ? nil : try Keyrings.removeDevicesAndRotate(k, gone, updatedBy: me)
        }
    }

    /// Set this device's recovery key, or remove the recovery key (crypto.md 9).
    public func setRecovery(_ recovery: RecoveryKey?) async throws {
        let me = await deviceId()
        try await update { k in Keyrings.setRecovery(k, recovery, updatedBy: me) }
    }

    /// Upload the next keyring version built from the latest one by `change` (nil: nothing
    /// to do), then refresh. Starts again if another device uploaded a version first.
    private func update(_ change: (SyncryptionCrypto.Keyring) throws -> SyncryptionCrypto.Keyring?) async throws {
        let me = await deviceId()
        var attempt = 0
        while true {
            try await refreshKeyring()
            guard let next = try change(keyring) else { return }
            do {
                _ = try await api.putKeyring(vault.id, upload(try Keyrings.seal(next, seed: seed), next, signer: me))
                break
            } catch let e as ApiError where e.code == "keyring_version" && attempt < 3 {
                attempt += 1
            }
        }
        try await refreshKeyring()
    }

    /// Replace this device's key, active side. `api` is a client for the new key, which isn't
    /// saved yet. The new key logs in (pending), this key adds and approves it, and the store
    /// records this key as replaced. The caller then saves the new key, and the new key's
    /// session removes the old one (`finishReplace`) and rotates the vault key.
    public func handOver(to newApi: ApiClient, deviceName: String) async throws {
        guard newApi.origin == api.origin, newApi.username == api.username, newApi.vaultName == api.vaultName else {
            throw Refused(description: "The new key must be for the same vault.")
        }
        let joined = try await newApi.login()
        if let v = joined.vaultId, v != vault.id { throw Refused(description: "The new key joined another vault.") }
        try await approve(id: joined.deviceId, name: deviceName, publicKey: OpenSSH.publicKeyText(newApi.publicKey))
        try store.setMeta(MetaKey.replacedDevice, await deviceId())
    }
}

/// Log in, asking for the shared secret if the server needs it to let this key create the vault.
public func login(_ api: ApiClient, _ callbacks: any ConnectCallbacks) async throws {
    do { try await api.login() } catch let e as ApiError where e.code == "join_required" {
        guard let secret = await callbacks.askSharedSecret() else { throw SetupCancelled() }
        try await api.login(sharedSecret: secret)
    }
}

/// Recovery (crypto.md 9): open the current keyring with the recovery identity, add this
/// device, and upload the next version signed by the recovery key. The server then activates
/// this device's membership; a `connect` waiting for pairing goes on at its next poll.
public func recoverVault(_ api: ApiClient, vault: Vault, seed: Bytes, deviceName: String, identity: String) async throws {
    var signing = try Keyrings.recoverySigningSeed(identity)
    defer { wipe(&signing) }
    let publicKey = OpenSSH.publicKeyText(Primitives.ed25519PublicKey(seed: seed))
    let me = await api.deviceId ?? ""
    var attempt = 0
    while true {
        let current = try blob(try await api.recoveryKeyring(vault.id))
        let opened = try Keyrings.openWithRecovery(current, vaultId: vault.id, name: vault.name, identity: identity)
        if opened.keyring.devices.contains(where: { $0.publicKey == publicKey }) {
            throw VaultSession.Refused(description: "This device is already in the keyring. Approve it from another device.")
        }
        let next = try Keyrings.addDevice(opened.keyring, KeyringDevice(id: me, name: deviceName, publicKey: publicKey), updatedBy: me)
        do {
            _ = try await api.recover(vault.id, upload(try Keyrings.seal(next, seed: signing), next, signer: me))
            return
        } catch let e as ApiError where e.code == "keyring_version" && attempt < 3 {
            attempt += 1
        }
    }
}

/// Connect to the configured vault, creating it if it doesn't exist yet. Logs in first unless
/// `api` already has. `openStore` opens the local state for a vault id. Throws
/// `RemoteOnlyRefused` if the keyring makes this key remote-only.
public func connect(api: ApiClient, seed: Bytes, deviceName: String, callbacks: any ConnectCallbacks,
                    openStore: @Sendable (String) throws -> any SyncStore, pollInterval: Duration = .seconds(5),
                    onPending: (@Sendable (Vault) -> Void)? = nil) async throws -> VaultSession
{
    // The server stores names like this, and the keyring must name the vault the same way.
    let vaultName = api.vaultName
    if await api.deviceId == nil { try await login(api, callbacks) }
    let myKey = OpenSSH.publicKeyText(Primitives.ed25519PublicKey(seed: seed))
    var shownPairing = false
    func pair(_ pending: Vault?) async throws {
        if !shownPairing {
            if let pending { onPending?(pending) }
            await callbacks.showPairing(code: OpenSSH.pairingCode(Primitives.ed25519PublicKey(seed: seed)), canRecover: pending != nil)
        }
        shownPairing = true
        do { try await Task.sleep(for: pollInterval) } catch { throw SetupCancelled() }
    }

    var vault: Vault
    while true {
        let opened: OpenResponse
        do { opened = try await api.openVault(vaultName) } catch let e as ApiError where e.code == "not_found" {
            do {
                // Only the key that joined with the shared secret gets here (protocol.md 5).
                vault = try await create(api, name: vaultName, publicKey: myKey, deviceName: deviceName, seed: seed)
            } catch let e as ApiError where e.code == "exists" {
                continue  // created meanwhile
            }
            break
        }
        if opened.membership == "active" {
            vault = opened.vault
            break
        }
        try await pair(opened.vault)
    }

    let store = try openStore(vault.id)
    if try store.meta(MetaKey.vaultId, as: String.self) != vault.id {
        try store.clear()
        try store.setMeta(MetaKey.vaultId, vault.id)
    }
    let pin = try store.meta(MetaKey.keyringPin, as: KeyringPin.self)
    var trusted: TrustedKeyring
    while true {
        do {
            let pinned: TrustedKeyring? = if let pin { try await pinnedKeyring(api, vault, seed, pin) } else { nil }
            trusted = try await fetchTrusted(api, vault, seed, pinned)
            break
        } catch let e as KeyringError where e.code == .notARecipient {
            // Membership is approved after the keyring is uploaded, but don't rely on it.
            try await pair(vault)
        }
    }
    try store.setMeta(MetaKey.keyringPin, trusted.pin)
    let session = VaultSession(api: api, vault: vault, store: store, trusted: trusted, seed: seed)
    if try await session.isRemoteOnly() { throw RemoteOnlyRefused() }
    return session
}

/// Re-open the pinned keyring version so newer versions can be checked against it.
private func pinnedKeyring(_ api: ApiClient, _ vault: Vault, _ seed: Bytes, _ pin: KeyringPin) async throws -> TrustedKeyring {
    let opened = try Keyrings.open(try blob(try await api.keyring(vault.id, version: pin.version)),
                                   KeyringContext(seed: seed, vaultId: vault.id, name: vault.name))
    guard opened.pin.sha256 == pin.sha256 else { throw KeyringError(.rollback, "server keyring differs from the pinned one") }
    return opened
}

private func create(_ api: ApiClient, name: String, publicKey: String, deviceName: String, seed: Bytes) async throws -> Vault {
    let vaultId = UUID().uuidString.lowercased()
    let me = await api.deviceId ?? ""
    let keyring = Keyrings.create(vaultId: vaultId, name: name, device: KeyringDevice(id: me, name: deviceName, publicKey: publicKey))
    return try await api.createVault(id: vaultId, name: name, keyring: upload(try Keyrings.seal(keyring, seed: seed), keyring, signer: me))
}
