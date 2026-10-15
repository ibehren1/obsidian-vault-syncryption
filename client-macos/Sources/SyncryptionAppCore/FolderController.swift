import AppKit
import Foundation
import Network
import Observation
import SyncryptionAPI
import SyncryptionCrypto
import SyncryptionStore
import SyncryptionSync

/// One synced folder at run time: connects to its vault, runs the engine on file events,
/// on a timer and on long-poll wake-ups, and turns errors into a status for the menu.
@MainActor @Observable
public final class FolderController: Identifiable {
    public enum Status: Equatable {
        case idle
        case connecting
        /// The server needs the shared secret to create this vault: `provideSecret`.
        case needsSecret
        /// Waiting for a device of the vault to approve this key. `canRecover`: `recover` can
        /// add it with the vault's recovery key instead.
        case pairing(code: String, canRecover: Bool)
        case syncing(String)
        case synced(Date)
        /// Can't reach the server, or it is in maintenance: retried by itself.
        case offline(String)
        case paused
        /// Stopped until the user acts.
        case error(String)
        /// This key is remote-only, which the macOS client doesn't do.
        case refused
        /// This key was removed from the vault.
        case revoked
        /// The folder's key can't be read from the Keychain: `retry`, or `resetKey`.
        case keyProblem(String)
    }

    public nonisolated let id: UUID
    public private(set) var config: FolderConfig
    public private(set) var status: Status = .idle
    public private(set) var fileCount = 0
    /// The plaintext size of those files, in bytes.
    public private(set) var totalSize = 0
    public private(set) var pendingCount = 0
    public private(set) var lastSync: Date?
    public private(set) var lastReport: SyncReport?
    /// Recent problems that skipped a file (never plaintext).
    public private(set) var warnings: [String] = []
    /// The connected session, for the vault-management views.
    public private(set) var session: VaultSession?
    public private(set) var engine: SyncEngine?
    /// Keys of the vault waiting for approval, with the pairing code computed here.
    public private(set) var pendingApprovals: [PendingDevice] = []
    /// Keys the server reports removed that this Mac didn't remove: Remove or Keep is the user's.
    public internal(set) var unconfirmedRemovals: [StaleKey] = []
    /// This folder's public key and fingerprint, for the Encryption Key view.
    public var publicKeyText: String { config.publicKey }

    private let configs: ConfigStore
    private let keys: KeyStore
    private let onConfigChange: (FolderConfig) -> Void
    private var api: ApiClient?
    private var seed: Bytes?
    private var watcher: FolderWatcher?
    private var live: LiveLoop?
    private var connectTask: Task<Void, Never>?
    private var debounce: Task<Void, Never>?
    private var fallback: Task<Void, Never>?
    private var retry: Task<Void, Never>?
    private var secret: CheckedContinuation<String?, Never>?
    private var pendingVault: Vault?
    private var pathMonitor: NWPathMonitor?
    private var wakeObserver: (any NSObjectProtocol)?

    /// Push this long after the last local change.
    static let debounceDelay: Duration = .seconds(2)
    /// Sync this often even without events (the scan catches what they missed).
    static let fallbackInterval: Duration = .seconds(120)

    let transport: @Sendable () -> any Transport

    public init(config: FolderConfig, configs: ConfigStore, keys: KeyStore, transport: @escaping @Sendable () -> any Transport,
                onConfigChange: @escaping (FolderConfig) -> Void)
    {
        self.transport = transport
        id = config.id
        self.config = config
        self.configs = configs
        self.keys = keys
        self.onConfigChange = onConfigChange
    }

    // MARK: Lifecycle

    /// Show or hide the synced-folder icon in Finder.
    public func setShowsFolderIcon(_ on: Bool) {
        config.showsFolderIcon = on
        onConfigChange(config)
        updateFolderIcon()
    }

    /// Put the icon on the folder (or take it off) to match the setting.
    public func updateFolderIcon() {
        if config.showsFolderIcon {
            if !FolderIcon.isApplied(to: config.url) { FolderIcon.apply(to: config.url) }
        } else if FolderIcon.isApplied(to: config.url) {
            FolderIcon.remove(from: config.url)
        }
    }

    /// Connect and start syncing, unless paused.
    public func start() {
        updateFolderIcon()
        guard !config.paused else {
            status = .paused
            return
        }
        guard connectTask == nil, session == nil else { return }
        status = .connecting
        connectTask = Task { await self.connectAndRun() }
    }

    /// Stop syncing. A running sync stops at its next write or commit.
    public func stop() {
        connectTask?.cancel()
        connectTask = nil
        debounce?.cancel()
        fallback?.cancel()
        retry?.cancel()
        watcher?.stop()
        watcher = nil
        pathMonitor?.cancel()
        pathMonitor = nil
        if let wakeObserver { NSWorkspace.shared.notificationCenter.removeObserver(wakeObserver) }
        wakeObserver = nil
        if let live { Task { await live.stop() } }
        live = nil
        if let engine { Task { await engine.close() } }
        engine = nil
        session = nil
        api = nil
        secret?.resume(returning: nil)
        secret = nil
    }

    public func setPaused(_ paused: Bool) {
        config.paused = paused
        onConfigChange(config)
        if paused {
            stop()
            status = .paused
        } else {
            status = .idle
            start()
        }
    }

    public func updateExclude(_ text: String) {
        config.exclude = text
        onConfigChange(config)
        if session != nil {
            stop()
            start()
        }
    }

    /// The shared secret from the user, or nil if they cancelled.
    public func provideSecret(_ value: String?) {
        secret?.resume(returning: value)
        secret = nil
    }

    /// Add this device to its vault with the vault's recovery key (crypto.md 9).
    public func recover(identity: String) async throws {
        guard let api, let seed, let vault = pendingVault else { return }
        try await recoverVault(api, vault: vault, seed: seed, deviceName: config.deviceName, identity: identity)
    }

    /// Try connecting again after an error.
    public func tryAgain() {
        stop()
        status = .idle
        start()
    }

    /// After a hand-over: store the new key and reconnect with it, which removes the old one.
    func saveReplacementKey(_ key: OpenSshKey) throws {
        stop()
        try keys.save(key, slot: config.keySlot)
        config.publicKey = OpenSSH.publicKeyText(key.publicKey)
        onConfigChange(config)
        status = .idle
        start()
    }

    /// Replace a key the Keychain lost or refuses: a new key is stored and connects as a new
    /// device, which another device of the vault approves (or the shared secret, for a vault
    /// that doesn't exist yet). The old key stays in the vault until a device removes it.
    public func resetKey() throws {
        stop()
        try? keys.delete(config.keySlot)
        let key = OpenSSH.generate(comment: "syncryption \(config.username)@\(config.deviceName)")
        try keys.save(key, slot: config.keySlot)
        config.publicKey = OpenSSH.publicKeyText(key.publicKey)
        onConfigChange(config)
        status = .idle
        start()
    }

    public func syncNow() {
        if session == nil {
            retry?.cancel()
            start()
        } else {
            scheduleSync(after: .zero)
        }
    }

    // MARK: Connecting

    private final class Callbacks: ConnectCallbacks, @unchecked Sendable {
        weak var owner: FolderController?
        init(_ owner: FolderController) { self.owner = owner }

        func askSharedSecret() async -> String? {
            await withCheckedContinuation { c in
                Task { @MainActor in
                    guard let owner = self.owner else { return c.resume(returning: nil) }
                    owner.secret = c
                    owner.status = .needsSecret
                }
            }
        }

        func showPairing(code: String, canRecover: Bool) async {
            await MainActor.run { self.owner?.status = .pairing(code: code, canRecover: canRecover) }
        }
    }

    private func connectAndRun() async {
        do {
            let loaded: OpenSshKey?
            // Off the main thread: macOS may ask the user to allow access first.
            let keys = keys, slot = config.keySlot
            do { loaded = try await Task.detached { try keys.load(slot) }.value } catch {
                status = .keyProblem("This Mac's Keychain refused to give the app this folder's encryption key (\(error)). Choose Try Again and allow access, or create a new key, which pairs this Mac with the vault again.")
                connectTask = nil
                return
            }
            guard let key = loaded else {
                status = .keyProblem("This folder's encryption key isn't in the Keychain. Create a new key to pair this Mac with the vault again.")
                connectTask = nil
                return
            }
            seed = key.seed
            let api = try ApiClient(endpoint: config.endpoint, username: config.username, vaultName: config.vaultName, seed: key.seed,
                                    deviceName: config.deviceName, transport: transport())
            self.api = api
            let stateURL = configs.stateURL(config.id)
            let session = try await connect(api: api, seed: key.seed, deviceName: config.deviceName, callbacks: Callbacks(self),
                                            openStore: { _ in try SQLiteStore(url: stateURL) },
                                            onPending: { [weak self] vault in Task { @MainActor in self?.pendingVault = vault } })
            try Task.checkCancellation()
            _ = try? await session.finishReplace()
            run(session)
        } catch is CancellationError {
        } catch is SetupCancelled {
            if !Task.isCancelled { status = .error("Setup was cancelled.") }
        } catch {
            handle(error)
        }
        connectTask = nil
    }

    private func run(_ session: VaultSession) {
        self.session = session
        status = .syncing("Starting")
        let config = config
        let id = Task { await session.deviceId() }
        Task {
            let deviceId = await id.value
            var o = EngineOptions(api: session.api, vaultId: session.vault.id, cipher: session.cipher, fs: PlainFolderFs(root: config.url),
                                  store: session.store, deviceId: deviceId, deviceName: config.deviceName,
                                  filter: PathFilter(exclude: PathFilter.parseExcludes(config.exclude)), keyring: session)
            o.onWarning = { [weak self] w in Task { @MainActor in self?.warn(w) } }
            o.onProgress = { [weak self] p in Task { @MainActor in self?.progress(p) } }
            let engine = SyncEngine(o)
            guard self.session === session else { return }
            self.engine = engine
            Task { await self.finishRemovals(session) }

            watcher = FolderWatcher(root: config.url) { [weak self] paths in
                Task { @MainActor in self?.noteChanges(paths) }
            }
            let store = session.store
            let live = LiveLoop(LiveLoop.Options(
                api: session.api, vaultId: session.vault.id,
                cursor: { (try? store.meta(MetaKey.cursor, as: Int.self)) ?? 0 },
                keyringVersion: { await session.version() },
                onChanges: { [weak self] in await self?.runSync() }))
            self.live = live
            await live.start()
            watchSystem()
            fallback = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(for: Self.fallbackInterval)
                    guard !Task.isCancelled else { return }
                    await self?.runSync()
                }
            }
            await runSync()
        }
    }

    /// Wake the long-poll and sync when the network comes back or the Mac wakes.
    private func watchSystem() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            let ok = path.status == .satisfied
            Task { @MainActor in self?.networkChanged(satisfied: ok) }
        }
        monitor.start(queue: DispatchQueue(label: "syncryption.network"))
        pathMonitor = monitor
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didWakeNotification, object: nil,
                                                                         queue: .main) { [weak self] _ in
            Task { @MainActor in self?.wakeUp() }
        }
    }

    private var online = true

    private func networkChanged(satisfied: Bool) {
        defer { online = satisfied }
        if satisfied && !online { wakeUp() }
    }

    private func wakeUp() {
        if let live { Task { await live.wake() } }
        scheduleSync(after: .seconds(1))
    }

    // MARK: Syncing

    private func noteChanges(_ paths: [String]) {
        guard let engine else { return }
        Task {
            for p in paths { try? await engine.noteChange(p) }
            self.scheduleSync(after: Self.debounceDelay)
        }
    }

    private func scheduleSync(after delay: Duration) {
        debounce?.cancel()
        debounce = Task { [weak self] in
            if delay > .zero { try? await Task.sleep(for: delay) }
            guard !Task.isCancelled else { return }
            await self?.runSync()
        }
    }

    private func runSync() async {
        guard let engine else { return }
        do {
            let report = try await engine.sync()
            lastReport = report
            lastSync = Date()
            status = .synced(Date())
            await refreshCounts()
            await refreshPending()
        } catch is SyncStopped {
        } catch is CancellationError {
        } catch {
            handle(error)
            await refreshCounts()
        }
    }

    public struct StaleKey: Identifiable, Equatable, Sendable {
        public let id: String
        public let name: String
    }

    public struct PendingDevice: Identifiable, Equatable, Sendable {
        public let id: String
        public let name: String
        public let publicKey: String
        public let code: String
        public let fingerprint: String
    }

    func refreshPending() async {
        guard let session else { return }
        let before = Set(pendingApprovals.map(\.id))
        guard let list = try? await session.pendingDevices() else { return }
        pendingApprovals = list.map { PendingDevice(id: $0.device.id, name: $0.device.name, publicKey: $0.device.publicKey, code: $0.code,
                                                     fingerprint: $0.fingerprint) }
        let new = pendingApprovals.filter { !before.contains($0.id) }
        if !new.isEmpty { onPendingApproval(self, new) }
    }

    /// Called when keys start waiting for approval in this folder's vault.
    public var onPendingApproval: (FolderController, [PendingDevice]) -> Void = { _, _ in }

    private func refreshCounts() async {
        guard let engine else { return }
        fileCount = (try? await engine.fileCount()) ?? fileCount
        totalSize = (try? await engine.totalSize()) ?? totalSize
        pendingCount = (try? await engine.pending().count) ?? pendingCount
    }

    private func progress(_ p: SyncProgress) {
        guard session != nil else { return }
        switch p {
        case .pull(let done, _, let path): status = .syncing(path == nil ? "Receiving (\(done))" : "Receiving \(done + 1)")
        case .scan(let done, let total): status = .syncing("Checking files \(done + 1) of \(total)")
        case .push(let done, let total): status = .syncing("Uploading \(done + 1) of \(total)")
        }
    }

    private func warn(_ w: String) {
        warnings.append(w)
        if warnings.count > 50 { warnings.removeFirst(warnings.count - 50) }
    }

    // MARK: Errors

    struct ControllerError: Error, CustomStringConvertible {
        let description: String
        init(_ d: String) { description = d }
    }

    private func handle(_ error: any Error) {
        switch error {
        case let e as ApiError where e.isRevoked:
            stop()
            status = .revoked
        case let e as ApiError where e.isMaintenance:
            status = .offline(e.maintenanceText)
            retryLater(seconds: e.retryAfter ?? 60)
        case let e as ApiError where e.isDisabled:
            stop()
            status = .error(e.disabledText)
        case let e as ApiError where e.status == 429:
            status = .offline(e.message)
            retryLater(seconds: e.retryAfter ?? 60)
        case is ConnectionError, is URLError:
            status = .offline("Can't reach the server. Sync resumes by itself.")
            retryLater(seconds: 30)
        case is RemoteOnlyRefused:
            stop()
            status = .refused
        case let e as KeyringError:
            // Something is wrong with what the server sent: stop rather than trust it.
            stop()
            status = .error("The vault's keyring failed its checks (\(e.code.rawValue)). Sync is stopped.")
        case let e as DeviceMismatchError:
            stop()
            status = .error(e.description)
        default:
            status = .error("\(error)")
            if session == nil { retryLater(seconds: 60) }
        }
    }

    /// Try again later: connect if not connected, else sync.
    private func retryLater(seconds: Int) {
        retry?.cancel()
        retry = Task { [weak self] in
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled, let self else { return }
            if self.session == nil { self.start() } else { await self.runSync() }
        }
    }
}
