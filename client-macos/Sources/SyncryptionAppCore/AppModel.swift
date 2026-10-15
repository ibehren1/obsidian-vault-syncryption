import Foundation
import Observation
import ServiceManagement
import SyncryptionAPI
import SyncryptionCrypto

/// The app's folders and their controllers.
@MainActor @Observable
public final class AppModel {
    public private(set) var folders: [FolderController] = []
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
            folders = try configs.load().map(makeController)
        } catch {
            loadError = "Couldn't read the folder list: \(error)"
        }
    }

    /// Called when keys start waiting for approval in a folder's vault.
    public var onPendingApproval: (FolderController, [FolderController.PendingDevice]) -> Void = { _, _ in } {
        didSet { for f in folders { f.onPendingApproval = onPendingApproval } }
    }

    private func makeController(_ config: FolderConfig) -> FolderController {
        let c = FolderController(config: config, configs: configs, keys: keys, transport: transport) { [weak self] updated in self?.saved(updated) }
        c.onPendingApproval = { [weak self] f, d in self?.onPendingApproval(f, d) }
        return c
    }

    private func saved(_ updated: FolderConfig) {
        var all = folders.map(\.config)
        if let i = all.firstIndex(where: { $0.id == updated.id }) { all[i] = updated }
        try? configs.save(all)
    }

    public func startAll() { for f in folders { f.start() } }
    public func stopAll() { for f in folders { f.stop() } }

    /// A summary for the menu bar icon.
    public var hasProblem: Bool {
        folders.contains {
            switch $0.status {
            case .error, .refused, .revoked, .needsSecret, .pairing, .keyProblem: true
            default: !$0.pendingApprovals.isEmpty || !$0.unconfirmedRemovals.isEmpty
            }
        }
    }

    /// The state of all folders together, for the menu's header.
    public var overallName: String {
        if hasProblem { return "Attention" }
        if isSyncing { return "Syncing" }
        return folders.isEmpty ? "Idle" : "Synced"
    }

    public var overallKind: FolderController.Kind {
        if hasProblem { return .warn }
        if isSyncing { return .busy }
        return folders.isEmpty ? .off : .ok
    }

    /// The menu bar icon's color: a problem, syncing, or every folder synced. Anything else
    /// (offline, paused, no folders) is `.off`, the plain menu bar icon.
    public var menuBarKind: FolderController.Kind {
        if hasProblem { return .error }
        if isSyncing { return .busy }
        let synced = folders.allSatisfy { if case .synced = $0.status { true } else { false } }
        return !folders.isEmpty && synced ? .ok : .off
    }

    public var isSyncing: Bool {
        folders.contains {
            switch $0.status {
            case .syncing, .connecting: true
            default: false
            }
        }
    }

    public struct AddError: Error, CustomStringConvertible {
        public let description: String
    }

    /// Link a folder to a vault: a new encryption key goes in the Keychain, and the folder
    /// starts connecting. Its controller then asks for the shared secret (a new vault) or
    /// shows the pairing code (an existing one).
    @discardableResult
    public func addFolder(path: String, endpoint: String, username: String, vaultName: String, deviceName: String) throws -> FolderController {
        let origin = try normalizeEndpoint(endpoint)
        let user = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let vault = normalizeVaultName(vaultName)
        let device = String(deviceName.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64))
        guard !user.isEmpty else { throw AddError(description: "Enter a username.") }
        guard !vault.isEmpty else { throw AddError(description: "Enter a vault name.") }
        guard !device.isEmpty else { throw AddError(description: "Enter a device name.") }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue else {
            throw AddError(description: "Choose an existing folder.")
        }
        let key = OpenSSH.generate(comment: "syncryption \(user)@\(device)")
        let config = FolderConfig(path: URL(filePath: path).standardizedFileURL.path, endpoint: origin, username: user, vaultName: vault,
                                  deviceName: device, publicKey: OpenSSH.publicKeyText(key.publicKey))
        try ConfigStore.check(config, against: folders.map(\.config))
        try keys.save(key, slot: config.keySlot)
        let controller = makeController(config)
        folders.append(controller)
        try configs.save(folders.map(\.config))
        controller.start()
        return controller
    }

    /// Stop syncing a folder and forget it: this Mac's key is removed from the vault (if it
    /// can still reach the server) and from the Keychain, and the sync state is deleted. The
    /// files stay in the folder.
    public func removeFolder(_ controller: FolderController) async {
        if let session = controller.session {
            let me = await session.deviceId()
            try? await session.api.removeDevice(session.vault.id, me)
        }
        controller.stop()
        if controller.config.showsFolderIcon { FolderIcon.remove(from: controller.config.url) }
        try? keys.delete(controller.config.keySlot)
        configs.removeState(controller.id)
        folders.removeAll { $0.id == controller.id }
        try? configs.save(folders.map(\.config))
    }

    // MARK: Login item

    public var opensAtLogin: Bool { SMAppService.mainApp.status == .enabled }

    public func setOpensAtLogin(_ on: Bool) throws {
        if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
    }
}
