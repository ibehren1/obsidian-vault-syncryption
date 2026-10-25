import Foundation
import SyncryptionAPI
import SyncryptionCrypto
import SyncryptionStore
import TestBackend
import Testing

@testable import SyncryptionSync

/// Devices (one key each) of one user syncing one vault against the real backend.

struct Callbacks: ConnectCallbacks {
    var secret: String? = TestBackend.sharedSecret
    var onPairing: @Sendable (String) -> Void = { _ in }
    var onAsk: @Sendable () -> Void = {}

    func askSharedSecret() async -> String? {
        onAsk()
        return secret
    }

    func showPairing(code: String, canRecover: Bool) async { onPairing(code) }
}

final class Log: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String] = []
    func add(_ s: String) { lock.withLock { items.append(s) } }
    var all: [String] { lock.withLock { items } }
}

struct TestDevice {
    let name: String
    let seed: Bytes
    let session: VaultSession
    let transport: HookTransport
    let fs: MemoryFs
    let store: MemoryStore
    let engine: SyncEngine
    let warnings: Log
}

func client(_ username: String, _ vaultName: String, _ seed: Bytes, _ name: String, _ transport: HookTransport) throws -> ApiClient {
    try ApiClient(endpoint: TestBackend.url()!, username: username, vaultName: vaultName, seed: seed, deviceName: name, transport: transport)
}

func engineFor(_ session: VaultSession, fs: any VaultFs, store: any SyncStore, name: String, deviceId: String, warnings: Log,
               exclude: [String] = [], filter: PathFilter? = nil, configure: (inout EngineOptions) -> Void = { _ in }) -> SyncEngine
{
    var o = EngineOptions(api: session.api, vaultId: session.vault.id, cipher: session.cipher, fs: fs, store: store, deviceId: deviceId,
                          deviceName: name, filter: filter ?? PathFilter(exclude: exclude), keyring: session)
    o.onWarning = { warnings.add($0) }
    o.blobRetries = [.milliseconds(10), .milliseconds(20)]
    configure(&o)
    return SyncEngine(o)
}

func device(_ username: String, _ vaultName: String, _ name: String, seed: Bytes = Primitives.random(32)) async throws -> TestDevice {
    let store = MemoryStore()
    let transport = TestBackend.transport()
    let session = try await connect(api: try client(username, vaultName, seed, name, transport), seed: seed, deviceName: name,
                                    callbacks: Callbacks(), openStore: { _ in store }, pollInterval: .milliseconds(20))
    let fs = MemoryFs()
    let warnings = Log()
    let id = await session.deviceId()
    return TestDevice(name: name, seed: seed, session: session, transport: transport, fs: fs, store: store,
                      engine: engineFor(session, fs: fs, store: store, name: name, deviceId: id, warnings: warnings), warnings: warnings)
}

/// Connects a second device and approves it from `first` once it waits.
func pairedDevice(_ first: TestDevice, _ username: String, _ vaultName: String, _ name: String,
                  remoteOnly: Bool = false) async throws -> TestDevice
{
    let second = Task { try await device(username, vaultName, name) }
    while true {
        if let p = try await first.session.pendingDevices().first {
            try await first.session.approve(id: p.device.id, name: p.device.name, publicKey: p.device.publicKey, remoteOnly: remoteOnly)
            break
        }
        try await Task.sleep(for: .milliseconds(20))
    }
    return try await second.value
}

func twoDevices() async throws -> (TestDevice, TestDevice) {
    let username = TestBackend.uniqueName("sync")
    let vaultName = TestBackend.uniqueName("Vault ")
    let a = try await device(username, vaultName, "Laptop")
    let b = try await pairedDevice(a, username, vaultName, "Phone")
    return (a, b)
}

func syncAll(_ devices: TestDevice...) async throws {
    for d in devices { try await d.engine.sync() }
    for d in devices { try await d.engine.sync() }
}

func texts(_ fs: MemoryFs) -> [String: String] {
    Dictionary(uniqueKeysWithValues: fs.paths.map { ($0, fs.text($0)!) })
}
