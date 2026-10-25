import AppKit
import Foundation
import Network
import Observation
import SyncryptionAPI
import SyncryptionCrypto
import SyncryptionStore
import SyncryptionSync

/// One vault at run time: connects to it, runs the engine over the vault folders this Mac
/// syncs on file events, on a timer and on long-poll wake-ups, and turns errors into a status
/// for the menu.
@MainActor @Observable
public final class VaultController: Identifiable {
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
        /// The vault's key can't be read from the Keychain: `retry`, or `resetKey`.
        case keyProblem(String)
    }

    public nonisolated let id: UUID
    public private(set) var config: VaultConfig
    public private(set) var status: Status = .idle
    public private(set) var fileCount = 0
    /// The plaintext size of those files, in bytes.
    public private(set) var totalSize = 0
    /// Changes waiting to upload, a package counting as one.
    public private(set) var pendingCount = 0
    /// Packages whose changes wait, after the last sync.
    public private(set) var heldPackages: [String: HoldReason] = [:]
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
    /// This vault's public key on this Mac, for the Encryption Key view.
    public var publicKeyText: String { config.publicKey }
    /// The vault's folders: every top-level folder with files, mapped here or on another
    /// device, with each device's local folder.
    public internal(set) var vaultFolders: [VaultFolder] = []
    /// The other active devices of the vault, the columns of the folder table.
    public internal(set) var otherDevices: [OtherDevice] = []
    /// Folders this Mac maps but can't sync now (the local folder is missing), by name.
    public private(set) var folderProblems: [String: String] = [:]
    /// The file the running sync is receiving or uploading, with how far it is.
    public struct FileProgress: Equatable, Sendable {
        /// The vault path (folder/…), shown only on this Mac.
        public let path: String
        public let done: Int
        public let total: Int
        public var fraction: Double { total > 0 ? min(1, Double(done) / Double(total)) : 1 }
    }

    public private(set) var currentFile: FileProgress?
    /// Folders with a file received or pushed in the running sync.
    public private(set) var busyFolders: Set<String> = []
    /// Folders the last finished sync covered: a folder just mapped or resumed isn't synced
    /// until a sync with it finishes.
    public private(set) var syncedFolders: Set<String> = []

    let configs: ConfigStore
    private let keys: KeyStore
    private let onConfigChange: (VaultConfig) -> Void
    private var api: ApiClient?
    private var seed: Bytes?
    private var watchers: [FolderWatcher] = []
    /// This Mac's folder list as last stored on the server, and the epoch it was stored under.
    struct Published: Equatable {
        let epoch: Int
        let folders: [DeviceMeta.Folder]
    }

    var published: Published?
    var publishing = false
    /// The last engine rebuild, so rebuilds run one after another.
    var rebuild: Task<Void, Never>?
    /// The folders the engine syncs.
    private var engineFolders: [String] = []
    private var live: LiveLoop?
    private var connectTask: Task<Void, Never>?
    private var debounce: Task<Void, Never>?
    /// When the scheduled sync runs, while one is scheduled.
    private var debounceDue: ContinuousClock.Instant?
    /// The next sync was asked for by the user: packages don't wait for their quiet period.
    private var forceNext = false
    private var fallback: Task<Void, Never>?
    private var retry: Task<Void, Never>?
    private var secret: CheckedContinuation<String?, Never>?
    private var pendingVault: Vault?
    private var pathMonitor: NWPathMonitor?
    private var wakeObserver: (any NSObjectProtocol)?

    /// Push this long after the last local change.
    static let debounceDelay: Duration = .seconds(2)
    /// A package is pushed once nothing in it changed for this long.
    static let packageQuiet: Duration = .seconds(30)
    /// Sync this often even without events (the scan catches what they missed).
    static let fallbackInterval: Duration = .seconds(120)

    let transport: @Sendable () -> any Transport

    public init(config: VaultConfig, configs: ConfigStore, keys: KeyStore, transport: @escaping @Sendable () -> any Transport,
                onConfigChange: @escaping (VaultConfig) -> Void)
    {
        self.transport = transport
        id = config.id
        self.config = config
        self.configs = configs
        self.keys = keys
        self.onConfigChange = onConfigChange
    }

    // MARK: Lifecycle

    /// Put the icon on each folder (or take it off) to match its setting.
    public func updateFolderIcons() {
        for f in config.folders where FileManager.default.fileExists(atPath: f.path) {
            if f.showsFolderIcon {
                if !FolderIcon.isApplied(to: f.url) { FolderIcon.apply(to: f.url) }
            } else if FolderIcon.isApplied(to: f.url) {
                FolderIcon.remove(from: f.url)
            }
        }
    }

    /// Connect and start syncing, unless paused.
    public func start() {
        updateFolderIcons()
        guard !config.paused else {
            status = .paused
            return
        }
        guard connectTask == nil, session == nil else { return }
        status = .connecting
        connectTask = Task { await self.connectAndRun() }
    }

    /// Stop syncing. A running sync is cancelled now, with its requests in flight.
    public func stop() {
        connectTask?.cancel()
        connectTask = nil
        debounce?.cancel()
        fallback?.cancel()
        retry?.cancel()
        for w in watchers { w.stop() }
        watchers = []
        published = nil
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

    /// Stop, and return once the running sync (if any) has stopped.
    public func stopAndWait() async {
        let running = engine
        stop()
        await running?.close()
    }

    public func setPaused(_ paused: Bool) {
        config.paused = paused
        onConfigChange(config)
        if paused {
            stop()
            currentFile = nil
            busyFolders = []
            status = .paused
        } else {
            status = .idle
            start()
        }
    }

    /// Every vault linked on this Mac, to check a new folder against (set by the app model).
    public var allVaults: () -> [VaultConfig] = { [] }

    /// Save folders without reconnecting: for settings the engine doesn't use.
    func setFoldersWithoutRestart(_ folders: [FolderMapping]) {
        config.folders = folders
        onConfigChange(config)
    }

    /// Save a change to the folders and sync with it: the running sync is cancelled now (a
    /// folder just paused or unmapped gets nothing more), and the engine is rebuilt over the
    /// new set, on the same session (no new login).
    func changeFolders(_ change: (inout [FolderMapping]) -> Void) {
        change(&config.folders)
        onConfigChange(config)
        updateFolderIcons()
        guard let session, !config.paused else {
            if !config.paused && connectTask == nil { restart() }
            return
        }
        let old = engine
        engine = nil
        for w in watchers { w.stop() }
        watchers = []
        let previous = rebuild
        let next = Task {
            await old?.close()
            await previous?.value
            await buildEngine(session)
        }
        rebuild = next
        Task {
            await next.value
            await runSync()
        }
    }

    private func restart() {
        stop()
        status = .idle
        start()
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
            forceNext = true
            scheduleSync(after: .zero)
        }
    }

    // MARK: Connecting

    private final class Callbacks: ConnectCallbacks, @unchecked Sendable {
        weak var owner: VaultController?
        init(_ owner: VaultController) { self.owner = owner }

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
                status = .keyProblem("This Mac's Keychain refused to give the app this vault's encryption key (\(error)). Choose Try Again and allow access, or create a new key, which pairs this Mac with the vault again.")
                connectTask = nil
                return
            }
            guard let key = loaded else {
                status = .keyProblem("This vault's encryption key isn't in the Keychain. Create a new key to pair this Mac with the vault again.")
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

    /// The folders to sync now: mapped, not paused, and there on disk. A missing folder isn't
    /// synced (its files would look deleted) and shows as a problem.
    private func activeFolders() -> [FolderMapping] {
        var problems: [String: String] = [:]
        let active = config.folders.filter { f in
            guard !f.paused else { return false }
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: f.path, isDirectory: &isDir), isDir.boolValue else {
                problems[f.name] = "The folder \(f.path) isn't there. Sync of \(f.name) resumes when it is back (or unmap it)."
                return false
            }
            return true
        }
        folderProblems = problems
        return active
    }

    private func run(_ session: VaultSession) {
        self.session = session
        status = .syncing("Starting")
        Task {
            await buildEngine(session)
            guard self.session === session else { return }
            Task { await self.finishRemovals(session) }
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

    /// The engine and file watchers over the folders to sync now. A running sync of the
    /// previous engine is cancelled first.
    private func buildEngine(_ session: VaultSession) async {
        if let engine { await engine.close() }
        engine = nil
        for w in watchers { w.stop() }
        watchers = []
        let config = config
        let active = activeFolders()
        let deviceId = await session.deviceId()
        let fs = MappedFs(roots: Dictionary(active.map { ($0.name, $0.url) }, uniquingKeysWith: { a, _ in a }))
        let filter = PathFilter(folders: Dictionary(active.map { ($0.name, PathFilter.parseExcludes($0.exclude)) },
                                                    uniquingKeysWith: { a, _ in a }))
        var o = EngineOptions(api: session.api, vaultId: session.vault.id, cipher: session.cipher, fs: fs,
                              store: session.store, deviceId: deviceId, deviceName: config.deviceName,
                              filter: filter, keyring: session)
        o.onWarning = { [weak self] w in Task { @MainActor in self?.warn(w) } }
        o.onProgress = { [weak self] p in Task { @MainActor in self?.progress(p) } }
        o.quietPeriod = Self.packageQuiet
        guard self.session === session else { return }
        engine = SyncEngine(o)
        engineFolders = active.map(\.name)
        watchers = active.map { f in
            FolderWatcher(root: f.url) { [weak self] paths in
                Task { @MainActor in self?.noteChanges(paths.map { f.name + "/" + $0 }) }
            }
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
            var plain = false
            for p in paths where (try? await engine.noteChange(p)) != true { plain = true }
            // A change inside a package waits for the package to be quiet anyway.
            if plain { self.scheduleSync(after: Self.debounceDelay) } else { self.scheduleSync(noLaterThan: Self.packageQuiet) }
        }
    }

    private func scheduleSync(after delay: Duration) {
        debounce?.cancel()
        debounceDue = .now + delay
        debounce = Task { [weak self] in
            if delay > .zero { try? await Task.sleep(for: delay) }
            guard !Task.isCancelled else { return }
            self?.debounceDue = nil
            await self?.runSync()
        }
    }

    /// Sync in `delay`, unless a sync is scheduled sooner already.
    private func scheduleSync(noLaterThan delay: Duration) {
        if let due = debounceDue, due <= .now + delay { return }
        scheduleSync(after: delay)
    }

    /// When to look at held packages again.
    private func scheduleHeld(_ held: [String: HoldReason]) {
        guard !held.isEmpty else { return }
        var delay = Self.packageQuiet
        for reason in held.values {
            if case .settling(let until) = reason { delay = min(delay, .seconds(max(1, until.timeIntervalSinceNow + 1))) }
        }
        scheduleSync(noLaterThan: delay)
    }

    private func runSync() async {
        // A missing folder that is back (or one that went missing) changes what to sync.
        if let session, engine != nil, activeFolders().map(\.name) != engineFolders { await buildEngine(session) }
        guard let engine else { return }
        let folders = engineFolders
        defer {
            if self.engine === engine {
                busyFolders = []
                currentFile = nil
            }
        }
        let force = forceNext
        forceNext = false
        do {
            let report = try await engine.sync(force: force)
            guard self.engine === engine else { return }
            heldPackages = report.held
            scheduleHeld(report.held)
            syncedFolders = Set(folders)
            lastReport = report
            lastSync = Date()
            status = .synced(Date())
            await publishFolders()
            await refreshCounts()
            await refreshPending()
            await refreshFolders()
        } catch is SyncStopped {
        } catch is CancellationError {
        } catch {
            // Stopped (paused, or its folders changed) while it ran: not an error.
            guard self.engine === engine else { return }
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

    /// Called when keys start waiting for approval in this vault.
    public var onPendingApproval: (VaultController, [PendingDevice]) -> Void = { _, _ in }

    private func refreshCounts() async {
        guard let engine else { return }
        fileCount = (try? await engine.fileCount()) ?? fileCount
        totalSize = (try? await engine.totalSize()) ?? totalSize
        if let entries = try? await engine.pending() {
            pendingCount = Set(entries.map { PathKey(engine.packageRoot($0.path) ?? $0.path) }).count
        }
    }

    private func progress(_ p: SyncProgress) {
        guard session != nil else { return }
        switch p {
        case .pull(let done, _, let path):
            status = .syncing(path == nil ? "Receiving (\(done))" : "Receiving \(done + 1)")
            if let path { noteBusy(path) }
        case .scan(let done, let total): status = .syncing("Checking files \(done + 1) of \(total)")
        case .push(let done, let total, let path):
            status = .syncing("Uploading \(done + 1) of \(total)")
            noteBusy(path)
        case .file(let path, let done, let total):
            // Late events of a sync that has finished are dropped.
            guard case .syncing = status else { return }
            currentFile = FileProgress(path: path, done: done, total: total)
            noteBusy(path)
        }
    }

    private func noteBusy(_ path: String) {
        guard let slash = path.firstIndex(of: "/") else { return }
        let name = String(path[..<slash])
        if !busyFolders.contains(name) { busyFolders.insert(name) }
    }

    func warn(_ w: String) {
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
