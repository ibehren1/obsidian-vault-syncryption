import Foundation
import Observation
import ServiceManagement
import SyncryptionAPI
import SyncryptionCrypto

/// The app's vaults and their controllers.
@MainActor @Observable
public final class AppModel {
    public private(set) var vaults: [VaultController] = []
    public private(set) var loadError: String?
    private let configs: ConfigStore
    private let keys: KeyStore
    private let transport: @Sendable () -> any Transport

    /// `transport`: how each folder reaches its server (tests pass their own).
    public init(configs: ConfigStore = ConfigStore(), keys: KeyStore = KeyStore(),
                transport: @escaping @Sendable () -> any Transport = { URLSessionTransport() })
    {
        self.configs = configs
        self.keys = keys
        self.transport = transport
        do {
            vaults = try configs.load().map(makeController)
        } catch {
            loadError = "Couldn't read the vault list: \(error)"
        }
    }

    /// Called when keys start waiting for approval in a vault.
    public var onPendingApproval: (VaultController, [VaultController.PendingDevice]) -> Void = { _, _ in } {
        didSet { for v in vaults { v.onPendingApproval = onPendingApproval } }
    }

    private func makeController(_ config: VaultConfig) -> VaultController {
        let c = VaultController(config: config, configs: configs, keys: keys, transport: transport) { [weak self] updated in self?.saved(updated) }
        c.onPendingApproval = { [weak self] f, d in self?.onPendingApproval(f, d) }
        c.allVaults = { [weak self] in self?.vaults.map(\.config) ?? [] }
        return c
    }

    private func saved(_ updated: VaultConfig) {
        var all = vaults.map(\.config)
        if let i = all.firstIndex(where: { $0.id == updated.id }) { all[i] = updated }
        try? configs.save(all)
    }

    public func startAll() { for v in vaults { v.start() } }
    public func stopAll() { for v in vaults { v.stop() } }

    /// Stop every vault, and return once their syncs have stopped (before an update).
    public func stopAllAndWait() async { for v in vaults { await v.stopAndWait() } }

    /// A summary for the menu bar icon.
    public var hasProblem: Bool {
        vaults.contains {
            switch $0.status {
            case .error, .refused, .revoked, .needsSecret, .pairing, .keyProblem: true
            default: !$0.pendingApprovals.isEmpty || !$0.unconfirmedRemovals.isEmpty || !$0.folderProblems.isEmpty
            }
        }
    }

    /// The state of all vaults together, for the menu's header.
    public var overallName: String {
        if hasProblem { return "Attention" }
        if isSyncing { return "Syncing" }
        if allPaused { return "Paused" }
        return vaults.isEmpty ? "Idle" : "Synced"
    }

    public var overallKind: VaultController.Kind {
        if hasProblem { return .warn }
        if isSyncing { return .busy }
        if allPaused { return .warn }
        return vaults.isEmpty ? .off : .ok
    }

    /// Every vault is paused on this Mac.
    public var allPaused: Bool { !vaults.isEmpty && vaults.allSatisfy(\.config.paused) }

    /// The menu bar icon's color: a problem, syncing, or every vault synced. Anything else
    /// (offline, paused, no vaults) is `.off`, the plain menu bar icon.
    public var menuBarKind: VaultController.Kind {
        if hasProblem { return .error }
        if isSyncing { return .busy }
        let synced = vaults.allSatisfy { if case .synced = $0.status { true } else { false } }
        return !vaults.isEmpty && synced ? .ok : .off
    }

    public var isSyncing: Bool {
        vaults.contains {
            switch $0.status {
            case .syncing, .connecting: true
            default: false
            }
        }
    }

    public struct AddError: Error, CustomStringConvertible {
        public let description: String
    }

    /// Link this Mac to a vault: a new encryption key goes in the Keychain, and the vault
    /// starts connecting. Its controller then asks for the shared secret (a new vault) or
    /// shows the pairing code (an existing one). Folders are added once it is connected.
    @discardableResult
    public func addVault(endpoint: String, username: String, vaultName: String, deviceName: String) throws -> VaultController {
        let origin = try normalizeEndpoint(endpoint)
        let user = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let vault = normalizeVaultName(vaultName)
        let device = String(deviceName.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64))
        guard !user.isEmpty else { throw AddError(description: "Enter a username.") }
        guard !vault.isEmpty else { throw AddError(description: "Enter a vault name.") }
        guard !device.isEmpty else { throw AddError(description: "Enter a device name.") }
        let key = OpenSSH.generate(comment: "syncryption \(user)@\(device)")
        let config = VaultConfig(endpoint: origin, username: user, vaultName: vault, deviceName: device,
                                 publicKey: OpenSSH.publicKeyText(key.publicKey))
        try ConfigStore.check(config, against: vaults.map(\.config))
        try keys.save(key, slot: config.keySlot)
        let controller = makeController(config)
        vaults.append(controller)
        try configs.save(vaults.map(\.config))
        controller.start()
        return controller
    }

    /// Stop syncing a vault and forget it: this Mac's key is removed from the vault (if it can
    /// still reach the server) and from the Keychain, and the sync state is deleted. The
    /// folders stay in place, or with `keepFiles` false go to the Trash.
    public func removeVault(_ controller: VaultController, keepFiles: Bool = true) async {
        if let session = controller.session {
            let me = await session.deviceId()
            try? await session.api.removeDevice(session.vault.id, me)
        }
        controller.stop()
        for f in controller.config.folders where FileManager.default.fileExists(atPath: f.path) {
            if f.showsFolderIcon { FolderIcon.remove(from: f.url) }
            if !keepFiles { try? FileManager.default.trashItem(at: f.url, resultingItemURL: nil) }
        }
        try? keys.delete(controller.config.keySlot)
        configs.removeState(controller.id)
        vaults.removeAll { $0.id == controller.id }
        try? configs.save(vaults.map(\.config))
    }

    // MARK: Login item

    public var opensAtLogin: Bool { SMAppService.mainApp.status == .enabled }

    public func setOpensAtLogin(_ on: Bool) throws {
        if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
    }
}
