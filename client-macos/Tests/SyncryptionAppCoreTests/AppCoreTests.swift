import Foundation
import Security
import SyncryptionCrypto
import TestBackend
import Testing

@testable import SyncryptionAppCore

/// The tests' own keychain, a file in the temporary folder kept out of the search list: the
/// tests never touch the login keychain, and run as a user without one (the CI runner).
enum TestKeychain {
    nonisolated(unsafe) static let shared: SecKeychain = {
        let path = FileManager.default.temporaryDirectory.appending(path: "syncryption-tests.keychain-db").path
        let password = "syncryption-tests"
        var keychain: SecKeychain?
        var status = FileManager.default.fileExists(atPath: path)
            ? SecKeychainOpen(path, &keychain)
            : SecKeychainCreate(path, UInt32(password.utf8.count), password, false, nil, &keychain)
        precondition(status == errSecSuccess && keychain != nil, "test keychain: \(status)")
        status = SecKeychainUnlock(keychain, UInt32(password.utf8.count), password, true)
        precondition(status == errSecSuccess, "test keychain unlock: \(status)")
        var list: CFArray?
        if SecKeychainCopySearchList(&list) == errSecSuccess, let all = list as? [SecKeychain], all.contains(keychain!) {
            SecKeychainSetSearchList(all.filter { $0 != keychain! } as CFArray)
        }
        return keychain!
    }()
}

@Suite struct ConfigTests {
    @Test func keySlotMatchesThePlugin() {
        // client-obsidian-plugin/src/keys.ts: secretId("https://sync.example.com", "alice", " Notes ")
        let slot = KeyStore.slot(origin: "https://sync.example.com", username: "alice", vaultName: " Notes ")
        #expect(slot.hasPrefix("syncryption-key-") && slot.count == "syncryption-key-".count + 16)
        #expect(slot == KeyStore.slot(origin: "https://sync.example.com", username: "alice", vaultName: "Notes"))
        #expect(slot != KeyStore.slot(origin: "https://sync.example.com", username: "alice", vaultName: "Work"))
    }

    @Test func savesAndLoadsFolders() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "cfg-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = ConfigStore(directory: dir)
        #expect(try store.load().isEmpty)
        let f = FolderConfig(path: "/tmp/x", endpoint: "https://s.example.com", username: "u", vaultName: "V", deviceName: "Mac")
        try store.save([f])
        #expect(try store.load() == [f])
    }

    @Test func olderFolderListsGetTheFolderIcon() throws {
        let json = #"[{"id":"281B21F2-AE50-4EBB-A71E-7F72894138CF","path":"/tmp/x","endpoint":"https://s.example.com","username":"u","vaultName":"V","deviceName":"Mac","publicKey":"","exclude":"","paused":false}]"#
        let f = try JSONDecoder().decode([FolderConfig].self, from: Data(json.utf8))
        #expect(f.first?.showsFolderIcon == true)
    }

    @Test func refusesTheSameVaultTwiceAndNestedFolders() throws {
        let a = FolderConfig(path: "/Users/me/Notes", endpoint: "https://s.example.com", username: "u", vaultName: "V", deviceName: "Mac")
        let sameVault = FolderConfig(path: "/Users/me/Other", endpoint: "https://s.example.com", username: "u", vaultName: "V",
                                     deviceName: "Mac")
        let nested = FolderConfig(path: "/Users/me/Notes/Sub", endpoint: "https://s.example.com", username: "u", vaultName: "W",
                                  deviceName: "Mac")
        let fine = FolderConfig(path: "/Users/me/Notes2", endpoint: "https://s.example.com", username: "u", vaultName: "W", deviceName: "Mac")
        #expect(throws: ConfigStore.Invalid.self) { try ConfigStore.check(sameVault, against: [a]) }
        #expect(throws: ConfigStore.Invalid.self) { try ConfigStore.check(nested, against: [a]) }
        try ConfigStore.check(fine, against: [a])
    }

    @Test func keychainRoundTrip() throws {
        let keys = KeyStore(service: "Vault Syncryption tests", keychain: TestKeychain.shared)
        let slot = "syncryption-key-test-\(UUID().uuidString)"
        defer { try? keys.delete(slot) }
        #expect(try keys.load(slot) == nil)
        let key = OpenSSH.generate(comment: "test")
        try keys.save(key, slot: slot)
        #expect(try keys.load(slot)?.seed == key.seed)
        try keys.delete(slot)
        #expect(try keys.load(slot) == nil)
    }
}

@MainActor
@Suite(.enabled(if: TestBackend.available, "needs uv to start the backend"))
struct AppModelTests {
    @Test func addsAFolderCreatesTheVaultAndSyncsIt() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "app-\(UUID().uuidString)")
        let folder = dir.appending(path: "Notes")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try Data("hello\n".utf8).write(to: folder.appending(path: "a.md"))
        let keys = KeyStore(service: "Vault Syncryption tests", keychain: TestKeychain.shared)
        let model = AppModel(configs: ConfigStore(directory: dir.appending(path: "support")), keys: keys, transport: { TestBackend.transport() })
        let c = try model.addFolder(path: folder.path, endpoint: try TestBackend.url()!, username: TestBackend.uniqueName("app"),
                                    vaultName: TestBackend.uniqueName("Vault "), deviceName: "Test Mac")
        defer { try? keys.delete(c.config.keySlot) }
        for _ in 0..<200 where c.status != .needsSecret { try await Task.sleep(for: .milliseconds(25)) }
        #expect(c.status == .needsSecret)
        #expect(model.menuBarKind == .error)
        c.provideSecret(TestBackend.sharedSecret)
        for _ in 0..<400 where c.fileCount != 1 { try await Task.sleep(for: .milliseconds(25)) }
        #expect(c.fileCount == 1)
        guard case .synced = c.status else { Issue.record("status \(c.status)"); return }
        #expect(model.menuBarKind == .ok)
        #expect(throws: (any Error).self) {
            try model.addFolder(path: folder.path, endpoint: try TestBackend.url()!, username: c.config.username,
                                vaultName: c.config.vaultName, deviceName: "Test Mac")
        }
        await model.removeFolder(c)
        #expect(model.folders.isEmpty)
        #expect(try keys.load(c.config.keySlot) == nil)
    }
}

@MainActor
func waitFor(_ what: String, timeout: Int = 400, _ cond: () -> Bool) async throws {
    for _ in 0..<timeout where !cond() { try await Task.sleep(for: .milliseconds(25)) }
    #expect(cond(), "timed out waiting for \(what)")
}

@MainActor
@Suite(.enabled(if: TestBackend.available, "needs uv to start the backend"), .serialized)
struct TwoMacsTests {
    @Test func pairApproveSyncManage() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "twomacs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let (fa, fb) = (dir.appending(path: "A"), dir.appending(path: "B"))
        for f in [fa, fb] { try FileManager.default.createDirectory(at: f, withIntermediateDirectories: true) }
        let keys = KeyStore(service: "Vault Syncryption tests", keychain: TestKeychain.shared)
        let a = AppModel(configs: ConfigStore(directory: dir.appending(path: "supportA")), keys: keys, transport: { TestBackend.transport() })
        let b = AppModel(configs: ConfigStore(directory: dir.appending(path: "supportB")), keys: keys, transport: { TestBackend.transport() })
        let url = try TestBackend.url()!
        let user = TestBackend.uniqueName("mac"), vault = TestBackend.uniqueName("Vault ")

        try Data("from A\n".utf8).write(to: fa.appending(path: "a.md"))
        let ca = try a.addFolder(path: fa.path, endpoint: url, username: user, vaultName: vault, deviceName: "Mac A")
        defer { try? keys.delete(ca.config.keySlot) }
        try await waitFor("A asks for the secret") { ca.status == .needsSecret }
        ca.provideSecret(TestBackend.sharedSecret)
        try await waitFor("A synced") { ca.fileCount == 1 }

        // B's key is in another Keychain slot only if its endpoint differs; same vault on two
        // Macs is two keychains, so give B its own service.
        let keysB = KeyStore(service: "Vault Syncryption tests B", keychain: TestKeychain.shared)
        let b2 = AppModel(configs: ConfigStore(directory: dir.appending(path: "supportB2")), keys: keysB, transport: { TestBackend.transport() })
        _ = b
        let cb = try b2.addFolder(path: fb.path, endpoint: url, username: user, vaultName: vault, deviceName: "Mac B")
        defer { try? keysB.delete(cb.config.keySlot) }
        try await waitFor("B pairing") { if case .pairing = cb.status { true } else { false } }
        guard case .pairing(let code, let canRecover) = cb.status else { return }
        #expect(code == cb.keyInfo?.pairingCode)
        #expect(canRecover)

        ca.syncNow()
        try await waitFor("A sees B waiting") { !ca.pendingApprovals.isEmpty }
        let p = try #require(ca.pendingApprovals.first)
        #expect(p.code == code && p.name == "Mac B")
        try await ca.approve(p, remoteOnly: false)
        try await waitFor("B synced") { cb.fileCount == 1 }
        #expect(try String(contentsOf: fb.appending(path: "a.md"), encoding: .utf8) == "from A\n")

        // Devices view.
        let devices = try await ca.vaultKeys()
        #expect(devices.map(\.name).sorted() == ["Mac A", "Mac B"])
        #expect(devices.first { $0.isThisMac }?.name == "Mac A")

        // B edits; A gets it through the long-poll or the next sync.
        try Data("edited on B\n".utf8).write(to: fb.appending(path: "a.md"))
        cb.syncNow()
        ca.syncNow()
        try await waitFor("A received") { (try? String(contentsOf: fa.appending(path: "a.md"), encoding: .utf8)) == "edited on B\n" }

        // History and restore.
        #expect(try await ca.syncedPaths() == ["a.md"])
        let history = try await ca.history("a.md")
        #expect(history.entries.count == 2)
        try await ca.restore("a.md", rev: history.entries[1].rev)
        #expect(try String(contentsOf: fa.appending(path: "a.md"), encoding: .utf8) == "from A\n")
        #expect(await ca.deviceNames().values.sorted() == ["Mac A", "Mac B"])

        // Recovery key.
        #expect(ca.recoveryState == .init(isSet: false, setBy: nil))
        let rk = ca.newRecoveryKey()
        try await ca.setRecovery(rk)
        #expect(ca.recoveryState == .init(isSet: true, setBy: "Mac A"))

        // B replaces its key: the old one is removed and the vault key rotates.
        let oldKey = cb.config.publicKey
        try await cb.replaceKey()
        #expect(cb.config.publicKey != oldKey)
        try await waitFor("B back in sync") { if case .synced = cb.status { cb.session != nil } else { false } }
        let after = try await ca.vaultKeys()
        #expect(after.filter { $0.status == "active" }.count == 2)
        #expect(after.first { $0.publicKey == oldKey }?.status == "revoked")

        // A removes B.
        let bId = try #require(after.first { $0.name == "Mac B" && $0.status == "active" }?.id)
        try await ca.removeKey(bId)
        cb.syncNow()
        try await waitFor("B revoked") { cb.status == .revoked }
        if cb.status != .revoked { Issue.record("B status: \(cb.status)") }
        await a.removeFolder(ca)
    }
}
