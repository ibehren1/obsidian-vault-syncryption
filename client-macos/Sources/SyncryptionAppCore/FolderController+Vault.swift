import Foundation
import SyncryptionAPI
import SyncryptionCrypto
import SyncryptionStore
import SyncryptionSync

/// Vault management from a connected folder (docs/protocol.md 6 and 7, crypto.md 6, 8.4 and 9):
/// the keys of the vault, the recovery key, file history, and replacing this Mac's key.
extension FolderController {
    public struct NotConnected: Error, CustomStringConvertible {
        public let description = "This folder isn't connected to its vault. Wait until it is, or choose Try Again."
    }

    func connected() throws -> VaultSession {
        guard let session else { throw NotConnected() }
        return session
    }

    func connectedEngine() throws -> SyncEngine {
        guard let engine else { throw NotConnected() }
        return engine
    }

    // MARK: This folder's key

    public struct KeyInfo: Equatable, Sendable {
        public let fingerprint: String
        public let pairingCode: String
    }

    /// From the public key in the config; the private key stays in the Keychain.
    public var keyInfo: KeyInfo? {
        guard let pk = try? OpenSSH.parsePublicKeyText(config.publicKey) else { return nil }
        return KeyInfo(fingerprint: OpenSSH.fingerprint(pk), pairingCode: OpenSSH.pairingCode(pk))
    }

    // MARK: Keys of the vault

    public struct VaultKey: Identifiable, Equatable, Sendable {
        public let id: String
        public let name: String
        public let status: String
        public let fingerprint: String
        public let pairingCode: String
        public let publicKey: String
        /// The policy in the signed keyring, which is what the device follows.
        public let remoteOnly: Bool
        public let locked: Bool
        public let lastSeenAt: String?
        public let createdAt: String
        public let isThisMac: Bool
        /// In the keyring: can open the vault.
        public let inKeyring: Bool
        /// When it was added to the keyring.
        public let added: String?

        /// The server's view of the key, for its dot.
        public var serverKind: FolderController.Kind {
            switch status {
            case "active": locked ? .warn : .ok
            case "pending": .warn
            default: .off
            }
        }

        public var serverLabel: String {
            if status == "active" { return locked ? "Locked" : "Active" }
            return status.capitalized
        }
    }

    /// Every key of the vault, revoked ones last.
    public func vaultKeys() async throws -> [VaultKey] {
        let session = try connected()
        let me = await session.deviceId()
        let keyring = session.keyring
        let order = ["active": 0, "pending": 1, "revoked": 2]
        return try await session.devices().map { d in
            let entry = keyring.devices.first { $0.id == d.id }
            // Computed here from the key, not taken from the server, which could name another key.
            let pk = try? OpenSSH.parsePublicKeyText(d.publicKey)
            return VaultKey(id: d.id, name: d.name, status: d.status, fingerprint: pk.map(OpenSSH.fingerprint) ?? "Unreadable key",
                            pairingCode: pk.map(OpenSSH.pairingCode) ?? "—",
                            publicKey: d.publicKey, remoteOnly: entry?.policy == Keyring.remoteOnly, locked: d.locked ?? false,
                            lastSeenAt: d.lastSeenAt, createdAt: d.createdAt, isThisMac: d.id == me, inKeyring: entry != nil,
                            added: entry?.added)
        }.sorted { (order[$0.status] ?? 3, $0.name) < (order[$1.status] ?? 3, $1.name) }
    }

    /// Approve a waiting key after the user compared its pairing code (crypto.md 6.5).
    public func approve(_ device: PendingDevice, remoteOnly: Bool) async throws {
        try await connected().approve(id: device.id, name: device.name, publicKey: device.publicKey, remoteOnly: remoteOnly)
        await refreshPending()
    }

    /// Revoke a key and rotate the vault key; every device re-encrypts in the background.
    public func removeKey(_ id: String) async throws {
        try await connected().removeDevice(id)
        await refreshPending()
        syncNow()
    }

    public func setRemoteOnly(_ id: String, _ remoteOnly: Bool) async throws {
        try await connected().setPolicy(deviceId: id, remoteOnly: remoteOnly)
    }

    public func setLocked(_ id: String, _ locked: Bool) async throws {
        try await connected().setLocked(deviceId: id, locked: locked)
    }

    /// Remove keys the server reports removed, after the user confirmed it (`unconfirmedRemovals`).
    public func confirmRemoval(_ ids: [String]) async throws {
        try await connected().removeDevices(ids)
        unconfirmedRemovals.removeAll { ids.contains($0.id) }
        syncNow()
    }

    /// Keep keys the server reports removed: they aren't offered for removal again.
    public func keepKeys(_ ids: [String]) async throws {
        try await connected().keepDevices(ids)
        unconfirmedRemovals.removeAll { ids.contains($0.id) }
    }

    /// Finish this Mac's own removals that didn't rotate the key, and collect the keys the
    /// server reports removed that this Mac didn't remove, for the user to decide.
    func finishRemovals(_ session: VaultSession) async {
        guard let stale = try? await session.removeStaleDevices(), self.session === session else { return }
        unconfirmedRemovals = stale.unconfirmed.map { StaleKey(id: $0.id, name: $0.name) }
        if !stale.removed.isEmpty { syncNow() }
    }

    // MARK: Status

    public struct QueuedChange: Identifiable, Sendable {
        public var id: String { path }
        public let path: String
        public let queuedAt: Date
    }

    /// The local changes waiting to upload, oldest first.
    public func queuedChanges() async -> [QueuedChange] {
        guard let engine else { return [] }
        return ((try? await engine.pending()) ?? []).map { QueuedChange(path: $0.path, queuedAt: Date(timeIntervalSince1970: $0.queuedAt / 1000)) }
    }

    /// This Mac's id in the vault, once connected.
    public func deviceId() async -> String? { await session?.deviceId() }

    // MARK: Recovery key (crypto.md 9)

    public struct RecoveryState: Equatable, Sendable {
        public let isSet: Bool
        /// The name of the device that set it.
        public let setBy: String?
    }

    public var recoveryState: RecoveryState? {
        guard let k = session?.keyring else { return nil }
        let by = k.recoverySetBy.flatMap { id in k.devices.first { $0.id == id }?.name ?? id }
        return RecoveryState(isSet: k.recovery != nil, setBy: by)
    }

    /// A new recovery key, not yet in the vault: show `identity` once, then `setRecovery`.
    public func newRecoveryKey() -> RecoveryKey { Keyrings.generateRecoveryKey() }

    /// Put `key` in the vault (replacing any other), or remove the recovery key with nil.
    public func setRecovery(_ key: RecoveryKey?) async throws {
        try await connected().setRecovery(key)
    }

    // MARK: History

    public func syncedPaths() async throws -> [String] { try await connectedEngine().syncedPaths() }

    public func deletedPaths() async throws -> [String] { try await connectedEngine().deletedPaths() }

    public func history(_ path: String, before: Int? = nil) async throws -> HistoryPage {
        try await connectedEngine().history(path, before: before)
    }

    public func readRevision(_ path: String, rev: Int) async throws -> Bytes? {
        try await connectedEngine().readRevision(path, rev: rev)
    }

    /// Make revision `rev` the current version of `path` on every device.
    public func restore(_ path: String, rev: Int) async throws {
        try await connectedEngine().restore(path, rev: rev)
    }

    /// Device names by id, for history entries.
    public func deviceNames() async -> [String: String] {
        guard let session else { return [:] }
        var names = Dictionary(session.keyring.devices.map { ($0.id, $0.name) }, uniquingKeysWith: { a, _ in a })
        for d in (try? await session.devices()) ?? [] where names[d.id] == nil { names[d.id] = d.name }
        return names
    }

    // MARK: Replacing this Mac's key

    /// Replace this folder's key: the new key joins the vault, this key approves it, the new
    /// key is saved, and its session removes the old one and rotates the vault key.
    public func replaceKey() async throws {
        let session = try connected()
        let key = OpenSSH.generate(comment: "syncryption \(config.username)@\(config.deviceName)")
        let api = try ApiClient(endpoint: config.endpoint, username: config.username, vaultName: config.vaultName, seed: key.seed,
                                deviceName: config.deviceName, transport: transport())
        try await session.handOver(to: api, deviceName: config.deviceName)
        try saveReplacementKey(key)
    }
}
