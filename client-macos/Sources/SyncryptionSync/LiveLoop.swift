import Foundation
import SyncryptionAPI

/// Live updates through long-poll (docs/protocol.md 10.2): wait until the vault or its
/// keyring changes, then sync, and wait again. A port of client-obsidian-plugin/src/sync/live.ts without
/// locks (the macOS client doesn't use them).
public actor LiveLoop {
    public struct Options: Sendable {
        public var api: ApiClient
        public var vaultId: String
        /// The change-feed cursor the engine has applied up to.
        public var cursor: @Sendable () async -> Int
        /// The keyring version this device has. A newer one on the server also triggers `onChanges`.
        public var keyringVersion: @Sendable () async -> Int
        /// Pull and push. Errors are the caller's to report; the loop backs off after them.
        public var onChanges: @Sendable () async -> Void
        /// A failed wait, before the loop backs off.
        public var onError: @Sendable (any Error) -> Void = { _ in }
        /// Seconds per wait, at most 25.
        public var timeout = 25
        public var minBackoff: Duration = .seconds(1)
        public var maxBackoff: Duration = .seconds(60)

        public init(api: ApiClient, vaultId: String, cursor: @escaping @Sendable () async -> Int,
                    keyringVersion: @escaping @Sendable () async -> Int, onChanges: @escaping @Sendable () async -> Void)
        {
            self.api = api
            self.vaultId = vaultId
            self.cursor = cursor
            self.keyringVersion = keyringVersion
            self.onChanges = onChanges
        }
    }

    /// Cap a server's `Retry-After`, so a wrong value can't stop live updates for long.
    private static let maxRetryAfter: Duration = .seconds(600)

    private let o: Options
    private var task: Task<Void, Never>?
    private var backoff: Duration
    private var sleeper: Task<Void, any Error>?
    private var woken = false
    /// This client doesn't use locks, so it leaves `locksSince` out and lock changes don't end
    /// its waits. A server that counts locks anyway answers at once while its `locksSeq` is past
    /// 0; then the loop sends back the last `locksSeq` it got.
    private var locksSince: Int?

    public init(_ options: Options) {
        o = options
        backoff = options.minBackoff
    }

    public func start() {
        guard task == nil else { return }
        task = Task { await self.run() }
    }

    /// Stop. A wait in flight is abandoned; the server ends the oldest wait when a device
    /// opens too many.
    public func stop() {
        task?.cancel()
        task = nil
        sleeper?.cancel()
    }

    /// End a backoff now, for example after the Mac wakes or the network comes back.
    public func wake() {
        woken = true
        sleeper?.cancel()
    }

    private func run() async {
        while !Task.isCancelled {
            do {
                let since = await o.cursor()
                let keyring = await o.keyringVersion()
                let r = try await o.api.wait(o.vaultId, since: since, locksSince: locksSince, timeout: o.timeout, keyringSince: keyring)
                if Task.isCancelled { break }
                if r.seq > since || r.keyringVersion > keyring {
                    await o.onChanges()
                    // The sync failed or didn't catch up: don't spin on the same answer.
                    let cursor = await o.cursor()
                    let version = await o.keyringVersion()
                    if cursor < r.seq || version < r.keyringVersion { await pause() } else { backoff = o.minBackoff }
                } else if r.changed {
                    // The wait ended early with nothing this client follows. Follow the locks if
                    // they moved, and back off on the same answer again, so the loop never spins.
                    if r.locksSeq != locksSince { locksSince = r.locksSeq } else { await pause() }
                } else {
                    backoff = o.minBackoff
                }
            } catch {
                if Task.isCancelled { break }
                o.onError(error)
                // Maintenance (503) and rate limits say when to come back.
                let retryAfter: Duration = (error as? ApiError)?.retryAfter.map { .seconds($0) } ?? .zero
                await pause(min: Swift.min(retryAfter, Self.maxRetryAfter))
            }
        }
    }

    /// Back off, for at least `min`.
    private func pause(min: Duration = .zero) async {
        woken = false
        let wait = Swift.max(backoff, min)
        let s = Task { try await Task.sleep(for: wait) }
        sleeper = s
        _ = try? await s.value
        sleeper = nil
        backoff = woken ? o.minBackoff : Swift.min(backoff * 2, o.maxBackoff)
    }
}
