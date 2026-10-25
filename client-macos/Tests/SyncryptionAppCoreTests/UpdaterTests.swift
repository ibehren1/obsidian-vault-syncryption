import Foundation
import SyncryptionCrypto
import Testing

@testable import SyncryptionAppCore

private func release(_ tag: String, draft: Bool = false, prerelease: Bool = false, assets: [String]? = nil) -> [String: Any] {
    let version = tag.hasPrefix("client-macos-v") ? String(tag.dropFirst("client-macos-v".count)) : tag
    let names = assets ?? ["VaultSyncryptionClient-\(version).dmg", "VaultSyncryptionClient-\(version).dmg.sig"]
    return ["tag_name": tag, "draft": draft, "prerelease": prerelease,
            "assets": names.map { ["name": $0, "browser_download_url": "https://example.com/\(tag)/\($0)"] }]
}

private func releases(_ list: [[String: Any]]) throws -> [Updater.Release] {
    try JSONDecoder().decode([Updater.Release].self, from: JSONSerialization.data(withJSONObject: list))
}

private func tempDir() throws -> URL {
    let u = FileManager.default.temporaryDirectory.appending(path: "updater-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}

/// A minimal app bundle, signed ad hoc.
private func fakeApp(at url: URL, id: String = "com.behrenshome.syncryption.mac", version: String) throws {
    let contents = url.appending(path: "Contents")
    try FileManager.default.createDirectory(at: contents.appending(path: "MacOS"), withIntermediateDirectories: true)
    try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: contents.appending(path: "MacOS/VaultSyncryptionClient").path)
    let info: NSDictionary = ["CFBundleIdentifier": id, "CFBundleShortVersionString": version, "CFBundleExecutable": "VaultSyncryptionClient",
                              "CFBundlePackageType": "APPL"]
    try info.write(to: contents.appending(path: "Info.plist"))
    try Updater.run("/usr/bin/codesign", ["--force", "--sign", "-", url.path])
}

@Suite struct UpdaterTests {
    @Test func picksTheNewestSignedClientRelease() throws {
        let list = try releases([
            release("0.1.99"), release("backend-v0.9.0"),
            release("client-macos-v0.1.9"), release("client-macos-v0.1.10"),
            release("client-macos-v0.2.0", draft: true), release("client-macos-v0.3.0", prerelease: true),
            release("client-macos-v0.4.0", assets: ["VaultSyncryptionClient-0.4.0.dmg"]),
        ])
        let c = try #require(Updater.pick(list, current: "0.1.8"))
        #expect(c.version == "0.1.10")
        #expect(c.dmg.lastPathComponent == "VaultSyncryptionClient-0.1.10.dmg")
        #expect(c.sig.lastPathComponent == "VaultSyncryptionClient-0.1.10.dmg.sig")
        #expect(Updater.pick(list, current: "0.1.10") == nil)
        #expect(Updater.pick(list, current: "1.0.0") == nil)
        #expect(Updater.newer("0.1.10", "0.1.9") && !Updater.newer("0.1.9", "0.1.10") && !Updater.newer("0.1.9", "0.1.9"))
        #expect(!Updater.newer("0.1", "0.0.1") && !Updater.newer("0.1.x", "0.0.1"))
    }

    @Test func acceptsOnlyTheUpdateKeysSignature() throws {
        let seed = Primitives.random(32)
        let trusted = Primitives.ed25519PublicKey(seed: seed)
        let dmg = Bytes(utf8: "a disk image")
        let sig = SshSig.sign(seed: seed, namespace: Updater.namespace, message: dmg)
        #expect(Updater.verify(dmg: dmg, signature: sig, trusted: trusted))
        #expect(!Updater.verify(dmg: dmg + [0], signature: sig, trusted: trusted))
        #expect(!Updater.verify(dmg: dmg, signature: sig, trusted: Primitives.ed25519PublicKey(seed: Primitives.random(32))))
        #expect(!Updater.verify(dmg: dmg, signature: SshSig.sign(seed: seed, namespace: SshSig.namespaceAuth, message: dmg), trusted: trusted))
        #expect(!Updater.verify(dmg: dmg, signature: "junk", trusted: trusted))
    }

    @Test(.enabled(if: FileManager.default.isExecutableFile(atPath: "/usr/bin/ssh-keygen")))
    func acceptsASignatureFromSshKeygen() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let key = dir.appending(path: "update-key"), file = dir.appending(path: "u.dmg")
        try Data("a disk image".utf8).write(to: file)
        try Updater.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", key.path])
        try Updater.run("/usr/bin/ssh-keygen", ["-Y", "sign", "-f", key.path, "-n", Updater.namespace, file.path])
        let pub = try OpenSSH.parsePublicKeyText(try String(contentsOf: dir.appending(path: "update-key.pub"), encoding: .utf8))
        let sig = try String(contentsOf: dir.appending(path: "u.dmg.sig"), encoding: .utf8)
        #expect(Updater.verify(dmg: Bytes(try Data(contentsOf: file)), signature: sig, trusted: pub))
    }

    @Test func stagesTheAppFromTheDiskImage() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let src = dir.appending(path: "src")
        try fakeApp(at: src.appending(path: "VaultSyncryptionClient.app"), version: "9.9.9")
        let dmg = dir.appending(path: "u.dmg")
        try Updater.run("/usr/bin/hdiutil", ["create", "-quiet", "-srcfolder", src.path, "-format", "UDZO", dmg.path])
        let apps = dir.appending(path: "Applications")
        try FileManager.default.createDirectory(at: apps, withIntermediateDirectories: true)
        let current = apps.appending(path: "VaultSyncryptionClient.app")
        let staged = try Updater.stage(dmg: dmg, nextTo: current, version: "9.9.9")
        #expect(staged == apps.appending(path: ".VaultSyncryptionClient-9.9.9.app"))
        #expect(FileManager.default.fileExists(atPath: staged.appending(path: "Contents/MacOS/VaultSyncryptionClient").path))
        // Another version, or another app, isn't staged.
        #expect(throws: (any Error).self) { try Updater.stage(dmg: dmg, nextTo: current, version: "9.9.8") }
        #expect(!FileManager.default.fileExists(atPath: apps.appending(path: ".VaultSyncryptionClient-9.9.8.app").path))
        #expect(throws: (any Error).self) { try Updater.stage(dmg: dmg, nextTo: current, version: "9.9.9", bundleId: "com.example.other") }
    }

    @Test func helperSwapsTheAppOnceTheProcessExits() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let current = dir.appending(path: "VaultSyncryptionClient.app"), staged = dir.appending(path: ".VaultSyncryptionClient-2.0.0.app")
        for (u, text) in [(current, "old"), (staged, "new")] {
            try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
            try Data(text.utf8).write(to: u.appending(path: "marker"))
        }
        func runHelper(staged: URL) throws {
            let sleeper = Process()
            sleeper.executableURL = URL(fileURLWithPath: "/bin/sleep")
            sleeper.arguments = ["0.3"]
            try sleeper.run()
            let script = dir.appending(path: "helper-\(UUID().uuidString).sh")
            try Updater.helperScript(pid: sleeper.processIdentifier, current: current, staged: staged, open: "/usr/bin/true")
                .write(to: script, atomically: true, encoding: .utf8)
            try Updater.run("/bin/sh", [script.path])
            #expect(!sleeper.isRunning)
            #expect(!FileManager.default.fileExists(atPath: script.path))
        }
        try runHelper(staged: staged)
        #expect(try String(contentsOf: current.appending(path: "marker"), encoding: .utf8) == "new")
        #expect(!FileManager.default.fileExists(atPath: staged.path))
        #expect(!FileManager.default.fileExists(atPath: dir.appending(path: ".VaultSyncryptionClient-old.app").path))
        // A staged app that isn't there: the current one stays.
        try runHelper(staged: dir.appending(path: ".missing.app"))
        #expect(try String(contentsOf: current.appending(path: "marker"), encoding: .utf8) == "new")
    }

    @Test @MainActor func trustsTheBuiltInUpdateKey() throws {
        let pk = try OpenSSH.parsePublicKeyText(Updater.publicKey)
        #expect(OpenSSH.fingerprint(pk) == "SHA256:Ad6V3xi6kQlMkRdk4NioE6rSiBRyjRfYjvk5nV+NOss")
        #expect(Updater(isSyncing: { false }, stop: {}).isEnabled)
    }

    @Test func refusesToReplaceAnAppItCantWriteOrThatIsTranslocated() throws {
        #expect(Updater.cantInstallReason(URL(fileURLWithPath: "/private/var/folders/x/AppTranslocation/ABC/d/VaultSyncryptionClient.app")) != nil)
        #expect(Updater.cantInstallReason(URL(fileURLWithPath: "/Volumes/Vault Syncryption Client 0.1.32/VaultSyncryptionClient.app")) != nil)
        #expect(Updater.cantInstallReason(URL(fileURLWithPath: "/System/Applications/VaultSyncryptionClient.app")) != nil)
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(Updater.cantInstallReason(dir.appending(path: "VaultSyncryptionClient.app")) == nil)
    }
}
