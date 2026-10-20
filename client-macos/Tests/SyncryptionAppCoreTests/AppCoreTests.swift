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

    @Test func savesAndLoadsVaults() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "cfg-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = ConfigStore(directory: dir)
        #expect(try store.load().isEmpty)
        let v = VaultConfig(endpoint: "https://s.example.com", username: "u", vaultName: "V", deviceName: "Mac",
                            folders: [FolderMapping(name: "Notes", path: "/tmp/Notes", exclude: "drafts", paused: true)])
        try store.save([v])
        #expect(try store.load() == [v])
        #expect(v.folder("Notes")?.paused == true && v.folder("notes") == nil)
    }

    @Test func refusesTheSameVaultTwice() throws {
        let a = VaultConfig(endpoint: "https://s.example.com", username: "u", vaultName: "V", deviceName: "Mac")
        let same = VaultConfig(endpoint: "https://s.example.com", username: "u", vaultName: "V", deviceName: "Other")
        let other = VaultConfig(endpoint: "https://s.example.com", username: "u", vaultName: "W", deviceName: "Mac")
        #expect(throws: ConfigStore.Invalid.self) { try ConfigStore.check(same, against: [a]) }
        try ConfigStore.check(other, against: [a])
    }

    @Test func refusesDuplicateNamesAndNestedFolders() throws {
        let vaults = [VaultConfig(endpoint: "https://s.example.com", username: "u", vaultName: "V", deviceName: "Mac",
                                  folders: [FolderMapping(name: "Notes", path: "/Users/me/Notes")])]
        func check(_ name: String, _ path: String, taken: [String] = ["Notes", "Caf\u{e9}"]) throws {
            try ConfigStore.checkFolder(name: name, path: path, taken: taken, vaults: vaults)
        }
        for (name, path) in [("notes", "/Users/me/x/notes"), ("Cafe\u{301}", "/x/Cafe\u{301}"), ("CAF\u{c9}", "/x/CAF\u{c9}"),
                             ("Sub", "/Users/me/Notes/Sub"), ("me", "/Users/me"), (".git", "/x/.git")] {
            #expect(throws: ConfigStore.Invalid.self, "\(name)") { try check(name, path) }
        }
        try check("Notes2", "/Users/me/Notes2")
        // Mapping a vault folder that exists: only this Mac's own folders count as taken.
        try check("Code", "/Users/me/remote/Code", taken: ["Notes"])
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
    @Test func addsAVaultCreatesItThenAddsAFolder() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "app-\(UUID().uuidString)")
        let folder = dir.appending(path: "Notes")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try Data("hello\n".utf8).write(to: folder.appending(path: "a.md"))
        let keys = KeyStore(service: "Vault Syncryption tests", keychain: TestKeychain.shared)
        let model = AppModel(configs: ConfigStore(directory: dir.appending(path: "support")), keys: keys, transport: { TestBackend.transport() })
        let c = try model.addVault(endpoint: try TestBackend.url()!, username: TestBackend.uniqueName("app"),
                                   vaultName: TestBackend.uniqueName("Vault "), deviceName: "Test Mac")
        defer { try? keys.delete(c.config.keySlot) }
        try await waitFor("the secret prompt") { c.status == .needsSecret }
        #expect(model.menuBarKind == .error)
        c.provideSecret(TestBackend.sharedSecret)
        try await waitFor("synced") { if case .synced = c.status { true } else { false } }
        #expect(c.fileCount == 0 && c.vaultFolders.isEmpty)

        try c.addFolder(path: folder.path)
        try await waitFor("the folder synced") { c.fileCount == 1 }
        // The upload wakes the long-poll, so another short sync may still be running.
        try await waitFor("everything synced") { model.menuBarKind == .ok }
        try await waitFor("the folder listed") { c.vaultFolders.map(\.name) == ["Notes"] && c.vaultFolders.first?.files == 1 }
        #expect(c.vaultFolders.first?.mapping?.path == folder.path && c.vaultFolders.first?.files == 1)
        #expect(c.folderState("Notes") == .active)
        #expect(c.folderStatus("Notes")?.name == "Synced")
        c.setPaused(true)
        #expect(c.folderStatus("Notes")?.name == "Paused" && model.overallName == "Paused")
        c.setPaused(false)
        try await waitFor("synced again") { c.folderStatus("Notes")?.name == "Synced" }
        let other = dir.appending(path: "x/notes")
        try FileManager.default.createDirectory(at: other, withIntermediateDirectories: true)
        #expect(throws: (any Error).self) { try c.addFolder(path: other.path) }
        #expect(throws: (any Error).self) {
            try model.addVault(endpoint: try TestBackend.url()!, username: c.config.username, vaultName: c.config.vaultName,
                               deviceName: "Test Mac")
        }

        // A missing folder isn't synced (its files would look deleted) and needs attention.
        let moved = dir.appending(path: "Moved")
        try FileManager.default.moveItem(at: folder, to: moved)
        c.setFolderPaused("Notes", false)  // reconnects with the folder gone
        try await waitFor("the missing folder noticed") { c.folderState("Notes") == .missing }
        #expect(model.hasProblem)
        try FileManager.default.moveItem(at: moved, to: folder)
        c.setFolderPaused("Notes", true)
        #expect(c.folderState("Notes") == .paused && c.folderStatus("Notes")?.name == "Paused")

        // Still mapped here: it can't be deleted from the vault. Unmapped, it can.
        try await waitFor("connected") { c.engine != nil }
        await #expect(throws: (any Error).self) { try await c.deleteFromVault("Notes") }
        try await c.unmapFolder("Notes", keepFiles: true)
        #expect(c.config.folders.isEmpty)
        try await waitFor("unmapped") { c.vaultFolders.first?.isUnmapped == true }
        #expect(try await c.deleteFromVault("Notes") == 1)
        #expect(c.vaultFolders.isEmpty)
        #expect(FileManager.default.fileExists(atPath: folder.appending(path: "a.md").path))

        await model.removeVault(c)
        #expect(model.vaults.isEmpty)
        #expect(try keys.load(c.config.keySlot) == nil)
        #expect(FileManager.default.fileExists(atPath: folder.appending(path: "a.md").path))
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
        let ca = try a.addVault(endpoint: url, username: user, vaultName: vault, deviceName: "Mac A")
        defer { try? keys.delete(ca.config.keySlot) }
        try await waitFor("A asks for the secret") { ca.status == .needsSecret }
        ca.provideSecret(TestBackend.sharedSecret)
        try await waitFor("A connected") { if case .synced = ca.status { true } else { false } }
        try ca.addFolder(path: fa.path)
        try await waitFor("A synced") { ca.fileCount == 1 }

        // B's key is in another Keychain slot only if its endpoint differs; same vault on two
        // Macs is two keychains, so give B its own service.
        let keysB = KeyStore(service: "Vault Syncryption tests B", keychain: TestKeychain.shared)
        let b2 = AppModel(configs: ConfigStore(directory: dir.appending(path: "supportB2")), keys: keysB, transport: { TestBackend.transport() })
        _ = b
        let cb = try b2.addVault(endpoint: url, username: user, vaultName: vault, deviceName: "Mac B")
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
        // B sees A's folder and where A keeps it, and maps it under another parent.
        try await waitFor("B sees the folder") { cb.vaultFolders.map(\.name) == ["A"] }
        let aId = try #require(await ca.deviceId())
        #expect(cb.vaultFolders.first?.mapping == nil && cb.vaultFolders.first?.elsewhere == [aId: fa.path], "\(cb.vaultFolders)")
        #expect(cb.otherDevices.map(\.name) == ["Mac A"])
        try cb.mapFolder("A", parent: fb.path)
        try await waitFor("B synced") { cb.fileCount == 1 }
        let fbA = fb.appending(path: "A")
        #expect(try String(contentsOf: fbA.appending(path: "a.md"), encoding: .utf8) == "from A\n")
        ca.syncNow()
        let bId0 = try #require(await cb.deviceId())
        try await waitFor("A sees B's mapping") { ca.vaultFolders.first?.elsewhere[bId0] == fbA.path }

        // Devices view.
        let devices = try await ca.vaultKeys()
        #expect(devices.map(\.name).sorted() == ["Mac A", "Mac B"])
        #expect(devices.first { $0.isThisMac }?.name == "Mac A")

        // B edits; A gets it through the long-poll or the next sync.
        try Data("edited on B\n".utf8).write(to: fbA.appending(path: "a.md"))
        cb.syncNow()
        ca.syncNow()
        try await waitFor("A received") { (try? String(contentsOf: fa.appending(path: "a.md"), encoding: .utf8)) == "edited on B\n" }

        // History and restore.
        #expect(try await ca.syncedPaths() == ["A/a.md"])
        let history = try await ca.history("A/a.md")
        #expect(history.entries.count == 2)
        try await ca.restore("A/a.md", rev: history.entries[1].rev)
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
        await a.removeVault(ca)
    }
}
