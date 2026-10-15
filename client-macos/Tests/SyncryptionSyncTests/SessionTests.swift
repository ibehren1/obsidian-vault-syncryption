import Foundation
import SyncryptionAPI
import SyncryptionCrypto
import SyncryptionStore
import TestBackend
import Testing

@testable import SyncryptionSync

@Suite(.enabled(if: TestBackend.available, "needs uv to start the backend"))
struct SessionTests {
    func connectNew(_ username: String, _ vaultName: String, name: String, seed: Bytes = Primitives.random(32), store: MemoryStore = MemoryStore(),
                    callbacks: Callbacks, onPending: (@Sendable (Vault) -> Void)? = nil) async throws -> VaultSession
    {
        try await connect(api: try client(username, vaultName, seed, name, TestBackend.transport()), seed: seed, deviceName: name,
                          callbacks: callbacks, openStore: { _ in store }, pollInterval: .milliseconds(20), onPending: onPending)
    }

    @Test func createsTheVaultOnFirstUseAndPinsItsKeyring() async throws {
        let vaultName = TestBackend.uniqueName("Notes ")
        let a = try await device(TestBackend.uniqueName("create"), " \(vaultName) ", "Laptop")
        #expect(a.session.vault.name == vaultName)
        #expect(a.session.keyring.devices.map(\.id) == [await a.session.deviceId()])
        #expect(try a.store.meta(MetaKey.vaultId, as: String.self) == a.session.vault.id)
        #expect(try a.store.meta(MetaKey.keyringPin, as: KeyringPin.self)?.version == 1)
    }

    @Test func stopsWhenTheUserDoesntGiveTheSharedSecret() async throws {
        await #expect(throws: SetupCancelled.self) {
            try await connectNew(TestBackend.uniqueName("cancel"), "Vault", name: "Laptop", callbacks: Callbacks(secret: nil))
        }
    }

    @Test func pairsASecondDevice() async throws {
        let username = TestBackend.uniqueName("pair")
        let vaultName = TestBackend.uniqueName("Vault ")
        let a = try await device(username, vaultName, "Laptop")
        let b = try await pairedDevice(a, username, vaultName, "Phone")
        #expect(b.session.vault.id == a.session.vault.id)
        #expect(b.session.keyring.version == 2)
        #expect(b.session.keyring.devices.map(\.name).sorted() == ["Laptop", "Phone"])
        #expect(try await a.session.pendingDevices().isEmpty)
        #expect(try await a.session.devices().map(\.status) == ["active", "active"])
        try await a.session.refreshKeyring()
        #expect(a.session.keyring.version == 2)
    }

    @Test func showsThePairingCodeAndWaitsWithoutTheSharedSecret() async throws {
        let username = TestBackend.uniqueName("wait")
        let vaultName = TestBackend.uniqueName("Vault ")
        let a = try await device(username, vaultName, "Laptop")
        let codes = Log()
        let asked = Log()
        let seed = Primitives.random(32)
        let waiting = Task {
            try await connectNew(username, " \(vaultName) ", name: "Tablet", seed: seed,
                                 callbacks: Callbacks(secret: nil, onPairing: { codes.add($0) }, onAsk: { asked.add("asked") }))
        }
        while codes.all.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        waiting.cancel()
        await #expect(throws: SetupCancelled.self) { try await waiting.value }
        #expect(asked.all.isEmpty)
        let pending = try await a.session.pendingDevices()
        #expect(codes.all == pending.map(\.code))
        #expect(pending.map(\.fingerprint) == [OpenSSH.fingerprint(Primitives.ed25519PublicKey(seed: seed))])
    }

    @Test func catchesUpOnKeyringVersionsItMissed() async throws {
        let username = TestBackend.uniqueName("chain")
        let vaultName = TestBackend.uniqueName("Vault ")
        let a = try await device(username, vaultName, "Laptop")
        let first = try a.store.meta(MetaKey.keyringPin, as: KeyringPin.self)
        _ = try await pairedDevice(a, username, vaultName, "Phone")
        _ = try await pairedDevice(a, username, vaultName, "Tablet")
        try a.store.setMeta(MetaKey.keyringPin, first)
        let again = try await connect(api: a.session.api, seed: a.seed, deviceName: "Laptop", callbacks: Callbacks(secret: nil),
                                      openStore: { _ in a.store })
        #expect(again.keyring.version == 3)
        #expect(try a.store.meta(MetaKey.keyringPin, as: KeyringPin.self)?.version == 3)
    }

    @Test func refusesAServerThatSwappedThePinnedKeyring() async throws {
        let a = try await device(TestBackend.uniqueName("swap"), TestBackend.uniqueName("Vault "), "Laptop")
        try a.store.setMeta(MetaKey.keyringPin, KeyringPin(version: 1, sha256: String(repeating: "0", count: 64)))
        await #expect { try await connect(api: a.session.api, seed: a.seed, deviceName: "Laptop", callbacks: Callbacks(secret: nil),
                                          openStore: { _ in a.store }) } throws: { ($0 as? KeyringError)?.code == .rollback }
    }

    @Test func recoversTheVaultWithTheRecoveryKey() async throws {
        let username = TestBackend.uniqueName("recover")
        let vaultName = TestBackend.uniqueName("Vault ")
        let a = try await device(username, vaultName, "Laptop")
        let recovery = Keyrings.generateRecoveryKey()
        try await a.session.setRecovery(recovery)
        #expect(a.session.keyring.version == 2)
        #expect(a.session.keyring.recoverySetBy == (await a.session.deviceId()))

        let seed = Primitives.random(32)
        let api = try client(username, vaultName, seed, "New laptop", TestBackend.transport())
        let store = MemoryStore()
        let errors = Log()
        let recovered = try await connect(api: api, seed: seed, deviceName: "New laptop", callbacks: Callbacks(), openStore: { _ in store },
                                          pollInterval: .milliseconds(20), onPending: { vault in
            _ = Task {
                // A wrong key first, then the right one.
                do { try await recoverVault(api, vault: vault, seed: seed, deviceName: "New laptop", identity: Keyrings.generateRecoveryKey().identity) }
                catch { errors.add("\(error)") }
                try await recoverVault(api, vault: vault, seed: seed, deviceName: "New laptop", identity: recovery.identity)
            }
        })
        #expect(errors.all.count == 1)
        #expect(recovered.keyring.version == 3)
        #expect(recovered.keyring.devices.map(\.name) == ["Laptop", "New laptop"])
        #expect(try store.meta(MetaKey.keyringPin, as: KeyringPin.self)?.version == 3)
        try await a.session.refreshKeyring()
        #expect(a.session.keyring.version == 3)
    }

    @Test func keepsTheRecoveryKeyAndRemovesItOnRequest() async throws {
        let username = TestBackend.uniqueName("recovery")
        let vaultName = TestBackend.uniqueName("Vault ")
        let a = try await device(username, vaultName, "Laptop")
        let recovery = Keyrings.generateRecoveryKey()
        try await a.session.setRecovery(recovery)
        let b = try await pairedDevice(a, username, vaultName, "Phone")
        #expect(b.session.keyring.recoverySigner == recovery.signer)
        #expect(try await a.session.api.keyring(a.session.vault.id).recoverySigner == recovery.signer)
        try await b.session.setRecovery(nil)
        try await a.session.refreshKeyring()
        #expect(a.session.keyring.recovery == nil)
        await #expect { try await a.session.api.recoveryKeyring(a.session.vault.id) } throws: { ($0 as? ApiError)?.code == "no_recovery" }
    }

    @Test func refusesTheKeyOfOneVaultForASecondVault() async throws {
        let username = TestBackend.uniqueName("reuse")
        let seed = Primitives.random(32)
        _ = try await device(username, TestBackend.uniqueName("Notes "), "Laptop", seed: seed)
        await #expect(throws: ApiError.self) {
            try await connectNew(username, TestBackend.uniqueName("Work "), name: "Laptop", seed: seed, callbacks: Callbacks())
        }
    }

    @Test func refusesToSyncAsARemoteOnlyDevice() async throws {
        let username = TestBackend.uniqueName("remote")
        let vaultName = TestBackend.uniqueName("Vault ")
        let a = try await device(username, vaultName, "Laptop")
        await #expect(throws: RemoteOnlyRefused.self) { try await pairedDevice(a, username, vaultName, "Mac", remoteOnly: true) }
        // A full device made remote-only later is refused at its next connect.
        let b = try await pairedDevice(a, username, vaultName, "Phone")
        try await a.session.setPolicy(deviceId: await b.session.deviceId(), remoteOnly: true)
        try await b.session.refreshKeyring()
        #expect(try await b.session.isRemoteOnly())
        await #expect(throws: RemoteOnlyRefused.self) {
            try await connect(api: b.session.api, seed: b.seed, deviceName: "Phone", callbacks: Callbacks(secret: nil), openStore: { _ in b.store })
        }
    }

    @Test func removesADeviceRotatesAndReencrypts() async throws {
        let username = TestBackend.uniqueName("revoke")
        let vaultName = TestBackend.uniqueName("Vault ")
        let a = try await device(username, vaultName, "Laptop")
        let b = try await pairedDevice(a, username, vaultName, "Phone")
        a.fs.set("one.md", "1")
        a.fs.set("two.md", "2")
        try await syncAll(a, b)
        try await a.session.removeDevice(await b.session.deviceId())
        #expect(a.session.keyring.currentEpoch == 2)
        #expect(a.session.keyring.devices.count == 1)
        #expect(try await a.engine.sync().reencrypted == 2)
        await #expect { try await b.engine.sync() } throws: { ($0 as? ApiError)?.isRevoked == true }
        await #expect(throws: VaultSession.Refused.self) { try await a.session.removeDevice(await a.session.deviceId()) }
    }

    @Test func finishesItsOwnRemovalWhoseRotationDidntHappen() async throws {
        let username = TestBackend.uniqueName("stale")
        let vaultName = TestBackend.uniqueName("Vault ")
        let a = try await device(username, vaultName, "Laptop")
        let b = try await pairedDevice(a, username, vaultName, "Phone")
        let c = try await pairedDevice(a, username, vaultName, "Tablet")
        let tablet = await c.session.deviceId()
        // Revoked on the server, but this device stopped before rotating.
        try a.store.setMeta(MetaKey.revokingDevices, [tablet])
        try await a.session.api.removeDevice(a.session.vault.id, tablet)
        #expect(try await a.session.removeStaleDevices() == .init(removed: ["Tablet"], unconfirmed: []))
        #expect(a.session.keyring.currentEpoch == 2)
        #expect(try a.store.meta(MetaKey.revokingDevices, as: [String].self) == [])
        #expect(try await b.session.removeStaleDevices() == .init(removed: [], unconfirmed: []))
        #expect(b.session.keyring.devices.map(\.name).sorted() == ["Laptop", "Phone"])
    }

    @Test func leavesAnotherDevicesRemovalToTheUser() async throws {
        let username = TestBackend.uniqueName("stale")
        let vaultName = TestBackend.uniqueName("Vault ")
        let a = try await device(username, vaultName, "Laptop")
        let b = try await pairedDevice(a, username, vaultName, "Phone")
        let c = try await pairedDevice(a, username, vaultName, "Tablet")
        let tablet = await c.session.deviceId()
        // The server reports Tablet removed, but no device here removed it.
        try await a.session.api.removeDevice(a.session.vault.id, tablet)
        let stale = try await b.session.removeStaleDevices()
        #expect(stale.removed.isEmpty)
        #expect(stale.unconfirmed.map(\.name) == ["Tablet"])
        #expect(b.session.keyring.currentEpoch == 1)

        try await b.session.keepDevices([tablet])
        #expect(try await b.session.removeStaleDevices() == .init(removed: [], unconfirmed: []))
        #expect(b.session.keyring.devices.map(\.name).contains("Tablet"))

        // Removing it later still works, and forgets the choice.
        try await b.session.removeDevices([tablet])
        #expect(b.session.keyring.currentEpoch == 2)
        #expect(try b.store.meta(MetaKey.keptDevices, as: [String].self) == [])
    }

    @Test func replacesThisDevicesKey() async throws {
        let username = TestBackend.uniqueName("replace")
        let vaultName = TestBackend.uniqueName("Vault ")
        let a = try await device(username, vaultName, "Laptop")
        let b = try await pairedDevice(a, username, vaultName, "Phone")
        a.fs.set("note.md", "hello\n")
        try await a.engine.sync()
        let oldId = await a.session.deviceId()
        let seed = Primitives.random(32)
        let api = try client(username, vaultName, seed, "Laptop", TestBackend.transport())
        try await a.session.handOver(to: api, deviceName: "Laptop")
        try await a.engine.sync()
        #expect(a.session.keyring.devices.count == 3)
        let replaced = try await connect(api: api, seed: seed, deviceName: "Laptop", callbacks: Callbacks(secret: nil),
                                         openStore: { _ in a.store })
        #expect(try await replaced.finishReplace())
        #expect(try await !replaced.finishReplace())
        #expect(Set(replaced.keyring.devices.map(\.id)) == [await b.session.deviceId(), await replaced.deviceId()])
        #expect(replaced.keyring.currentEpoch == 2)
        await #expect { try await a.engine.sync() } throws: { ($0 as? ApiError)?.status == 403 }
        let status = Dictionary(try await replaced.devices().map { ($0.id, $0.status) }, uniquingKeysWith: { x, _ in x })
        #expect(status[oldId] == "revoked")
        let engine = engineFor(replaced, fs: a.fs, store: a.store, name: "Laptop", deviceId: await replaced.deviceId(), warnings: Log())
        #expect(try await engine.sync().reencrypted == 1)
    }
}

@Suite(.enabled(if: TestBackend.available, "needs uv to start the backend"))
struct LiveLoopTests {
    @Test func syncsWhenAnotherDeviceCommits() async throws {
        let (a, b) = try await twoDevices()
        let engine = b.engine
        let store = b.store
        let session = b.session
        var o = LiveLoop.Options(api: b.session.api, vaultId: b.session.vault.id,
                                 cursor: { (try? store.meta(MetaKey.cursor, as: Int.self)) ?? 0 },
                                 keyringVersion: { await session.version() },
                                 onChanges: { _ = try? await engine.sync() })
        o.timeout = 5
        let live = LiveLoop(o)
        await live.start()
        a.fs.set("live.md", "hi")
        try await a.engine.sync()
        for _ in 0..<200 where b.fs.text("live.md") == nil { try await Task.sleep(for: .milliseconds(25)) }
        await live.stop()
        #expect(b.fs.text("live.md") == "hi")
    }
}
