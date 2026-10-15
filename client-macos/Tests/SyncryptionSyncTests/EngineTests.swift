import Foundation
import SyncryptionAPI
import SyncryptionCrypto
import SyncryptionStore
import TestBackend
import Testing

@testable import SyncryptionSync

@Suite(.enabled(if: TestBackend.available, "needs uv to start the backend"))
struct EngineTests {
    @Test func copiesNewFilesEditsAndDeletions() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("Note.md", "hello\n")
        a.fs.set("Folder/Deep/photo.png", [0, 1, 2, 255])
        #expect(try await a.engine.sync().pushed == 2)
        #expect(try await b.engine.sync().pulled == 2)
        #expect(b.fs.text("Note.md") == "hello\n")
        #expect(try b.fs.read("Folder/Deep/photo.png") == [0, 1, 2, 255])
        // The remote mtime is kept.
        #expect(try b.fs.stat("Note.md")?.mtime == a.fs.stat("Note.md")?.mtime)
        b.fs.set("Note.md", "hello again\n")
        try await syncAll(b, a)
        #expect(a.fs.text("Note.md") == "hello again\n")
        a.fs.delete("Note.md")
        try await syncAll(a, b)
        #expect(b.fs.text("Note.md") == nil)
        #expect(texts(a.fs) == texts(b.fs))
        #expect(try await a.engine.fileCount() == 1)
        #expect(try await b.engine.fileCount() == 1)
        #expect(a.warnings.all.isEmpty && b.warnings.all.isEmpty)
    }

    @Test func triesAChunkDownloadAgainWhenTheServerCantBeReached() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("photo.png", [1, 2, 3])
        try await a.engine.sync()
        let failures = Log()
        b.transport.before = { r in
            if r.url.path.contains("/blobs/") && r.method == "GET" && failures.all.isEmpty {
                failures.add("x")
                throw URLError(.networkConnectionLost)
            }
            return nil
        }
        try await b.engine.sync()
        #expect(try b.fs.read("photo.png") == [1, 2, 3])
    }

    @Test func writesNothingOfAFileWhoseChunkWasTamperedWith() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("photo.png", [1, 2, 3])
        try await a.engine.sync()
        b.transport.after = { r, resp in
            guard r.url.path.contains("/blobs/"), r.method == "GET" else { return resp }
            var t = resp
            t.body[t.body.count - 1] ^= 1
            return t
        }
        let report = try await b.engine.sync()
        #expect(report.rejected == 1)
        #expect(b.fs.text("photo.png") == nil)
        #expect(b.warnings.all.joined().contains("integrity check"))
    }

    @Test func doesntPushFilesThatWereOnlyTouched() async throws {
        let (a, _) = try await twoDevices()
        a.fs.set("a.md", "same")
        try await a.engine.sync()
        a.fs.set("a.md", "same")
        #expect(try await a.engine.sync().pushed == 0)
        #expect(try a.store.file("a.md")?.mtime == a.fs.stat("a.md")?.mtime)
    }

    @Test func doesntPushAFileItJustReceived() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("Note.md", "hello\n")
        try await a.engine.sync()
        try await b.engine.sync()
        // FSEvents report every file the pull writes.
        try await b.engine.noteChange("Note.md")
        #expect(try await b.engine.sync().pushed == 0)
        #expect(try b.store.outbox().isEmpty)
    }

    @Test func mergesEditsToDifferentLines() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("Plan.md", "one\ntwo\nthree\n")
        try await syncAll(a, b)
        a.fs.set("Plan.md", "ONE\ntwo\nthree\n")
        b.fs.set("Plan.md", "one\ntwo\nTHREE\n")
        try await a.engine.sync()
        let report = try await b.engine.sync()
        #expect(report.merged == 1 && report.conflicts.isEmpty)
        try await a.engine.sync()
        #expect(a.fs.text("Plan.md") == "ONE\ntwo\nTHREE\n")
        #expect(b.fs.text("Plan.md") == "ONE\ntwo\nTHREE\n")
    }

    @Test func keepsBothVersionsWhenTheEditsConflict() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("Plan.md", "draft\n")
        try await syncAll(a, b)
        a.fs.set("Plan.md", "laptop version\n")
        b.fs.set("Plan.md", "phone version\n")
        try await a.engine.sync()
        let report = try await b.engine.sync()
        #expect(report.conflicts.count == 1)
        let copy = try #require(report.conflicts.first)
        #expect(copy.wholeMatch(of: /Plan \(conflict Phone \d{4}-\d{2}-\d{2} \d{4}\)\.md/) != nil)
        try await a.engine.sync()
        for d in [a, b] {
            #expect(d.fs.text("Plan.md") == "laptop version\n")
            #expect(d.fs.text(copy) == "phone version\n")
        }
    }

    @Test func keepsABinaryFileFromTheServerAndTheLocalOneAsACopy() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("img.png", [1])
        try await syncAll(a, b)
        a.fs.set("img.png", [2])
        b.fs.set("img.png", [3])
        try await a.engine.sync()
        let report = try await b.engine.sync()
        #expect(report.conflicts.count == 1)
        #expect(try b.fs.read("img.png") == [2])
        #expect(try b.fs.read(report.conflicts[0]) == [3])
    }

    @Test func keepsAnEditOverADeletion() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("a.md", "v1\n")
        try await syncAll(a, b)
        a.fs.delete("a.md")
        b.fs.set("a.md", "v2\n")
        try await a.engine.sync()
        try await syncAll(b, a)
        #expect(a.fs.text("a.md") == "v2\n" && b.fs.text("a.md") == "v2\n")
        b.fs.delete("a.md")
        a.fs.set("a.md", "v3\n")
        try await a.engine.sync()
        try await syncAll(b, a)
        #expect(a.fs.text("a.md") == "v3\n" && b.fs.text("a.md") == "v3\n")
    }

    @Test func adoptsTheSameFileCreatedOnBothDevices() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("same.md", "identical\n")
        b.fs.set("same.md", "identical\n")
        try await a.engine.sync()
        let report = try await b.engine.sync()
        #expect(report.conflicts.isEmpty && report.pushed == 0)
        #expect(b.fs.paths == ["same.md"])
    }

    @Test func convergesAfterManyOfflineEdits() async throws {
        let (a, b) = try await twoDevices()
        for i in 0..<10 { a.fs.set("a/\(i).md", "a \(i)\n") }
        for i in 0..<10 { b.fs.set("b/\(i).md", "b \(i)\n") }
        a.fs.set("shared.md", "x\ny\nz\n")
        try await syncAll(a, b)
        a.fs.set("shared.md", "X\ny\nz\n")
        b.fs.set("shared.md", "x\ny\nZ\n")
        a.fs.delete("b/3.md")
        b.fs.set("a/5.md", "edited on b\n")
        try await syncAll(a, b, a)
        #expect(texts(a.fs) == texts(b.fs))
        #expect(a.fs.text("shared.md") == "X\ny\nZ\n")
        #expect(a.fs.text("b/3.md") == nil)
        #expect(a.fs.text("a/5.md") == "edited on b\n")
        #expect(try a.store.outbox().isEmpty && b.store.outbox().isEmpty)
    }

    @Test func skipsExcludedPathsAndSyncsDotFiles() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set(".obsidian/workspace.json", "{}")
        a.fs.set(".DS_Store", "x")
        a.fs.set("a/._x.md", "x")
        a.fs.set(".git/config", "x")
        a.fs.set("a/.hidden.md", "hidden")
        a.fs.set("kept.md", "kept")
        try await syncAll(a, b)
        #expect(b.fs.paths == ["a/.hidden.md", "kept.md"])
    }

    @Test func runsOneSyncAtATime() async throws {
        let (a, _) = try await twoDevices()
        a.fs.set("a.md", "1")
        async let first = a.engine.sync()
        a.fs.set("b.md", "2")
        async let second = a.engine.sync()
        let (r1, r2) = try await (first, second)
        #expect(r1.pushed + r2.pushed >= 2)
        #expect(try a.store.files().count == 2)
    }

    @Test func startsOverFromAnEmptyStateWithoutDuplicates() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("a.md", "1")
        try await syncAll(a, b)
        let fresh = MemoryStore()
        let engine = engineFor(b.session, fs: b.fs, store: fresh, name: "Phone", deviceId: await b.session.deviceId(), warnings: b.warnings)
        let report = try await engine.sync()
        #expect(report.pushed == 0 && report.conflicts.isEmpty)
        #expect(try fresh.meta(MetaKey.cursor, as: Int.self) ?? 0 > 0)
    }

    @Test func storesOnlyCiphertextOnTheServer() async throws {
        let (a, _) = try await twoDevices()
        let marker = "plaintext-marker-7f3a9c"
        a.fs.set("Secret \(marker)/\(marker).md", String(repeating: "\(marker)\n", count: 100))
        try await a.engine.sync()
        let dir = try #require(TestBackend.dataDirectory)
        let files = FileManager.default.enumerator(atPath: dir.path)!.compactMap { $0 as? String }
            .map { dir.appending(path: $0) }.filter { (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true }
        #expect(!files.isEmpty)
        for f in files { #expect(!(try Data(contentsOf: f)).contains(Data(marker.utf8)), "\(f.lastPathComponent)") }
    }

    @Test func listsHistoryAndRestoresAnOldVersionEverywhere() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("Note.md", "first\n")
        try await syncAll(a, b)
        b.fs.set("Note.md", "second\n")
        try await syncAll(b, a)
        a.fs.set("Note.md", "third, not synced yet\n")
        let history = try await a.engine.history("Note.md")
        #expect(history.next == nil && history.rejected == 0)
        let aId = await a.session.deviceId(), bId = await b.session.deviceId()
        #expect(history.entries.map(\.device) == [bId, aId])
        #expect(history.entries.map(\.size) == [7, 6])
        let oldest = history.entries[1]
        #expect(try await a.engine.readRevision("Note.md", rev: oldest.rev) == Bytes(utf8: "first\n"))
        try await a.engine.restore("Note.md", rev: oldest.rev)
        #expect(a.fs.text("Note.md") == "first\n")
        try await b.engine.sync()
        #expect(b.fs.text("Note.md") == "first\n")
        let after = try await b.engine.history("Note.md")
        #expect(after.entries.count == 4)
        #expect(try await b.engine.readRevision("Note.md", rev: after.entries[1].rev) == Bytes(utf8: "third, not synced yet\n"))
    }

    @Test func restoresADeletedFile() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("Gone.md", "keep me")
        a.fs.set("Folder/photo.png", [1, 2, 3])
        try await syncAll(a, b)
        a.fs.delete("Gone.md")
        a.fs.delete("Folder/photo.png")
        try await syncAll(a, b)
        #expect(try await b.engine.deletedPaths() == ["Folder/photo.png", "Gone.md"])
        let history = try await b.engine.history("Folder/photo.png")
        #expect(history.entries[0].deleted)
        #expect(try await b.engine.readRevision("Folder/photo.png", rev: history.entries[0].rev) == nil)
        await #expect(throws: SyncEngine.RestoreError.self) { try await b.engine.restore("Folder/photo.png", rev: history.entries[0].rev) }
        try await b.engine.restore("Folder/photo.png", rev: history.entries[1].rev)
        try await a.engine.sync()
        #expect(try a.fs.read("Folder/photo.png") == [1, 2, 3])
        #expect(try await a.engine.deletedPaths() == ["Gone.md"])
    }

    @Test func appliesTheHeadWhenAPulledRevisionWasPruned() async throws {
        let (a, b) = try await twoDevices()
        a.fs.set("Note.md", "one")
        try await a.engine.sync()
        a.fs.set("Note.md", "two")
        try await a.engine.sync()
        let pruned = Log()
        b.transport.before = { r in
            guard r.url.path.contains("/blobs/"), r.method == "GET", pruned.all.isEmpty else { return nil }
            pruned.add("x")
            return HttpResponse(status: 404, headers: ["x-syncryption-version": "0.1.1", "x-syncryption-protocol": "1"],
                                body: Data(#"{"error":"not_found","message":"Not found.","details":{}}"#.utf8))
        }
        try await b.engine.sync()
        #expect(b.fs.text("Note.md") == "two")
        #expect(b.warnings.all.isEmpty)
        #expect(try b.store.meta(MetaKey.failed, as: [Revision].self) == [])
    }

    @Test func keepsGoingWhenARemoteChangeCantBeWrittenAndWritesItLater() async throws {
        let (a, b) = try await twoDevices()
        // b already has a file whose name differs only in case: one file on a Mac's disk.
        let folder = FileManager.default.temporaryDirectory.appending(path: "clash-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let disk = PlainFolderFs(root: folder)
        let engine = engineFor(b.session, fs: disk, store: MemoryStore(), name: "Phone", deviceId: await b.session.deviceId(),
                               warnings: b.warnings, exclude: ["bad.md"])
        try disk.write("bad.md", Bytes(utf8: "local\n"), mtime: 1_790_000_000_000, ctime: nil)
        a.fs.set("Bad.md", "bad\n")
        a.fs.set("Good.md", "good\n")
        try await a.engine.sync()
        try await engine.sync()
        #expect(b.warnings.all.count == 1)
        #expect(try disk.read("Good.md") == Bytes(utf8: "good\n"))
        try await engine.sync()
        #expect(b.warnings.all.count == 1)  // warned once
        try FileManager.default.removeItem(at: folder.appending(path: "bad.md"))
        try await engine.sync()
        #expect(try disk.read("Bad.md") == Bytes(utf8: "bad\n"))
        try? FileManager.default.removeItem(at: folder)
    }
}
