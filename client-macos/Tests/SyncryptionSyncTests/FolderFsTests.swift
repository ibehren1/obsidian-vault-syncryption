import Foundation
import SyncryptionCrypto
import SyncryptionStore
import TestBackend
import Testing

@testable import SyncryptionSync

func tempFolder() throws -> URL {
    let u = FileManager.default.temporaryDirectory.appending(path: "folder-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}

@Suite struct FolderFsTests {
    @Test func writesReadsListsAndRemoves() async throws {
        let root = try tempFolder()
        defer { try? FileManager.default.removeItem(at: root) }
        let fs = PlainFolderFs(root: root)
        try fs.write("a/b/c.md", Bytes(utf8: "hello"), mtime: 1_790_000_000_123, ctime: 1_780_000_000_456)
        let st = try #require(try fs.stat("a/b/c.md"))
        #expect(st.mtime == 1_790_000_000_123 && st.ctime == 1_780_000_000_456 && st.size == 5)
        #expect(try fs.read("a/b/c.md") == Bytes(utf8: "hello"))
        #expect(try fs.hash("a/b/c.md") == Primitives.sha256(Bytes(utf8: "hello")).hex)
        try fs.write(".hidden", [1], mtime: 1_790_000_000_000, ctime: nil)
        #expect(Set(try fs.list(skip: { _ in false }).map(\.path)) == ["a/b/c.md", ".hidden"])
        #expect(try fs.list(skip: { $0 == "a" }).map(\.path) == [".hidden"])
        // No temp files left behind.
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.appending(path: "a/b").path) == ["c.md"])
        try fs.remove("a/b/c.md")
        #expect(!FileManager.default.fileExists(atPath: root.appending(path: "a").path))
        #expect(try fs.stat("a/b/c.md") == nil)
    }

    @Test func streamsChunksAndThrowsAwayAFailedWrite() async throws {
        let root = try tempFolder()
        defer { try? FileManager.default.removeItem(at: root) }
        let fs = PlainFolderFs(root: root)
        let w = try fs.beginWrite("big.bin")
        try w.append([1, 2])
        try w.append([3])
        try w.commit(mtime: 1_790_000_000_000, ctime: nil)
        #expect(try fs.read("big.bin") == [1, 2, 3])
        let failed = try fs.beginWrite("big.bin")
        try failed.append([9])
        failed.abort()
        #expect(try fs.read("big.bin") == [1, 2, 3])
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["big.bin"])
    }

    @Test func refusesNamesThatAPFSSeesAsTheSameFile() async throws {
        let root = try tempFolder()
        defer { try? FileManager.default.removeItem(at: root) }
        let fs = PlainFolderFs(root: root)
        try fs.write("Notes/Plan.md", Bytes(utf8: "1"), mtime: 1, ctime: nil)
        #expect(throws: NameClash.self) { try fs.write("notes/x.md", Bytes(utf8: "2"), mtime: 1, ctime: nil) }
        #expect(throws: NameClash.self) { try fs.write("Notes/plan.md", Bytes(utf8: "2"), mtime: 1, ctime: nil) }
        #expect(try fs.stat("Notes/plan.md") == nil)  // only the exact name is this file
        // NFC and NFD: one file on APFS, so the second name clashes too.
        try fs.write("caf\u{e9}.md", Bytes(utf8: "nfc"), mtime: 1, ctime: nil)
        #expect(throws: NameClash.self) { try fs.write("cafe\u{301}.md", Bytes(utf8: "nfd"), mtime: 1, ctime: nil) }
        #expect(try fs.read("caf\u{e9}.md") == Bytes(utf8: "nfc"))
        // Both forms land on disk as sent, in folder names too.
        try fs.write("D\u{e9}j\u{e0}/n.md", [1], mtime: 1, ctime: nil)
        try fs.write("Nai\u{308}ve/n.md", [1], mtime: 1, ctime: nil)
        let names = Set(try FileManager.default.contentsOfDirectory(atPath: root.path).map { Array($0.utf8) })
        #expect(names == [Array("Notes".utf8), Array("caf\u{e9}.md".utf8), Array("D\u{e9}j\u{e0}".utf8), Array("Nai\u{308}ve".utf8)])
        #expect(Set(try fs.list(skip: { _ in false }).map { Array($0.path.utf8) }).contains(Array("D\u{e9}j\u{e0}/n.md".utf8)))
    }

    @Test func watcherReportsChangedFiles() async throws {
        let root = try tempFolder()
        defer { try? FileManager.default.removeItem(at: root) }
        let seen = Log()
        let watcher = FolderWatcher(root: root, latency: 0.05) { for p in $0 { seen.add(p) } }
        defer { watcher.stop() }
        try await Task.sleep(for: .milliseconds(200))
        try Data("x".utf8).write(to: root.appending(path: "new.md"))
        for _ in 0..<100 where !seen.all.contains("new.md") { try await Task.sleep(for: .milliseconds(20)) }
        #expect(seen.all.contains("new.md"))
    }
}

@Suite(.enabled(if: TestBackend.available, "needs uv to start the backend"))
struct TwoFoldersTests {
    @Test func syncsTwoRealFolders() async throws {
        let (a, b) = try await twoDevices()
        let (ra, rb) = (try tempFolder(), try tempFolder())
        defer {
            try? FileManager.default.removeItem(at: ra)
            try? FileManager.default.removeItem(at: rb)
        }
        let (fa, fb) = (PlainFolderFs(root: ra), PlainFolderFs(root: rb))
        let ea = engineFor(a.session, fs: fa, store: MemoryStore(), name: "Laptop", deviceId: await a.session.deviceId(), warnings: a.warnings)
        let eb = engineFor(b.session, fs: fb, store: MemoryStore(), name: "Phone", deviceId: await b.session.deviceId(), warnings: b.warnings)
        let big = Primitives.random(Objects.chunkSize + 1000)
        try Data(big).write(to: ra.appending(path: "big.bin"))
        try FileManager.default.createDirectory(at: ra.appending(path: "Notes"), withIntermediateDirectories: true)
        try Data("nfd\n".utf8).write(to: ra.appending(path: "Notes/cafe\u{301}.md"))
        try Data("x".utf8).write(to: ra.appending(path: ".DS_Store"))
        try await ea.sync()
        try await eb.sync()
        #expect(try Data(contentsOf: rb.appending(path: "big.bin")) == Data(big))
        // Written under the name as sent (NFD).
        #expect(try FileManager.default.contentsOfDirectory(atPath: rb.appending(path: "Notes").path).map { Array($0.utf8) }
            == [Array("cafe\u{301}.md".utf8)])
        #expect(!FileManager.default.fileExists(atPath: rb.appending(path: ".DS_Store").path))
        try FileManager.default.removeItem(at: rb.appending(path: "big.bin"))
        try await eb.sync()
        try await ea.sync()
        #expect(!FileManager.default.fileExists(atPath: ra.appending(path: "big.bin").path))
        #expect(a.warnings.all.isEmpty && b.warnings.all.isEmpty)
    }
}
