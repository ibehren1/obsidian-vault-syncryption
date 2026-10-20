import Foundation
import SyncryptionAPI
import SyncryptionCrypto
import SyncryptionStore
import TestBackend
import Testing

@testable import SyncryptionSync

@Suite struct MappedFsTests {
    @Test func mapsTopLevelFoldersAndRefusesTheRoot() throws {
        let notes = MemoryFs(), code = MemoryFs()
        let fs = MappedFs(folders: ["Notes": notes, "Code": code])
        try fs.write("Notes/a.md", Bytes(utf8: "a"), mtime: 1000, ctime: nil)
        code.set("x/main.swift", "x")
        #expect(notes.paths == ["a.md"])
        #expect(try fs.list(skip: { _ in false }).map(\.path) == ["Code/x/main.swift", "Notes/a.md"])
        #expect(try fs.list(skip: { $0 == "Code" }).map(\.path) == ["Notes/a.md"])
        #expect(try fs.read("Code/x/main.swift") == Bytes(utf8: "x"))
        #expect(try fs.stat("Photos/a.jpg") == nil)
        #expect(throws: NotMapped.self) { try fs.write("a.md", [], mtime: 1000, ctime: nil) }
        #expect(throws: NotMapped.self) { try fs.write("Photos/a.jpg", [], mtime: 1000, ctime: nil) }
        try fs.remove("Notes/a.md")
        #expect(notes.paths.isEmpty)
    }
}

/// A device whose engine syncs some top-level folders of the vault, each in its own MemoryFs.
struct Mapped {
    let device: TestDevice
    var folders: [String: MemoryFs]
    var paused: Set<String> = []

    func engine() async -> SyncEngine {
        let active = folders.filter { !paused.contains($0.key) }
        return engineFor(device.session, fs: MappedFs(folders: active), store: device.store, name: device.name,
                         deviceId: await device.session.deviceId(), warnings: device.warnings,
                         filter: PathFilter(folders: active.mapValues { _ in [] }))
    }
}

@Suite(.enabled(if: TestBackend.available, "needs uv to start the backend"))
struct VaultFoldersTests {
    @Test func eachDeviceSyncsTheFoldersItMaps() async throws {
        let (a, b) = try await twoDevices()
        let notesA = MemoryFs(), codeA = MemoryFs(), notesB = MemoryFs()
        let ma = Mapped(device: a, folders: ["Notes": notesA, "Code": codeA])
        var mb = Mapped(device: b, folders: ["Notes": notesB])
        notesA.set("a.md", "note")
        codeA.set("main.swift", "code v1")
        try await (await ma.engine()).sync()
        var eb = await mb.engine()
        try await eb.sync()
        #expect(texts(notesB) == ["a.md": "note"])
        let folders = try await eb.remoteFolders()
        #expect(Set(folders.keys) == ["Notes", "Code"])
        #expect(folders["Code"]?.files == 1 && folders["Code"]?.size == 7)

        // Mapping Code later brings its files without replaying the feed.
        let codeB = MemoryFs()
        mb.folders["Code"] = codeB
        eb = await mb.engine()
        try await eb.sync()
        #expect(texts(codeB) == ["main.swift": "code v1"])

        // Unmapping it: nothing is pushed for it, and its changes no longer arrive.
        try await eb.forgetFolder("Code")
        mb.folders["Code"] = nil
        eb = await mb.engine()
        codeB.delete("main.swift")
        try await eb.sync()
        let ea = await ma.engine()
        codeA.set("main.swift", "code v2")
        try await ea.sync()
        try await ea.sync()
        #expect(texts(codeA) == ["main.swift": "code v2"])
        try await eb.sync()
        #expect(codeB.paths.isEmpty)
        #expect(a.warnings.all.isEmpty && b.warnings.all.isEmpty)
    }

    @Test func aPausedFolderCatchesUpWhenResumed() async throws {
        let (a, b) = try await twoDevices()
        let notesA = MemoryFs(), notesB = MemoryFs()
        let ma = Mapped(device: a, folders: ["Notes": notesA])
        var mb = Mapped(device: b, folders: ["Notes": notesB])
        notesA.set("a.md", "one\ntwo\nthree\n")
        notesA.set("b.md", "b")
        let ea = await ma.engine()
        try await ea.sync()
        try await (await mb.engine()).sync()
        mb.paused = ["Notes"]
        var eb = await mb.engine()
        // While paused: edits on both sides, and a deletion there.
        notesA.set("a.md", "ONE\ntwo\nthree\n")
        notesA.delete("b.md")
        try await ea.sync()
        notesB.set("a.md", "one\ntwo\nTHREE\n")
        notesB.set("c.md", "new here")
        try await eb.sync()
        #expect(notesB.text("b.md") == "b")
        mb.paused = []
        eb = await mb.engine()
        try await eb.sync()
        try await ea.sync()
        #expect(texts(notesB) == ["a.md": "ONE\ntwo\nTHREE\n", "c.md": "new here"])
        #expect(texts(notesA) == texts(notesB))
    }

    @Test func deletesAnUnmappedFolderFromTheVault() async throws {
        let (a, b) = try await twoDevices()
        let archive = MemoryFs()
        var ma = Mapped(device: a, folders: ["Notes": MemoryFs(), "Archive": archive])
        archive.set("old.md", "old")
        archive.set("x/older.md", "older")
        try await (await ma.engine()).sync()
        let mb = Mapped(device: b, folders: ["Archive": MemoryFs()])
        let eb = await mb.engine()
        try await eb.sync()
        await #expect(throws: SyncEngine.FolderSynced.self) { try await eb.deleteFolder("Archive") }

        try await (await ma.engine()).forgetFolder("Archive")
        ma.folders["Archive"] = nil
        let ea = await ma.engine()
        #expect(try await ea.deleteFolder("Archive") == 2)
        #expect(try await ea.remoteFolders()["Archive"] == nil)
        #expect(archive.paths.count == 2)  // unmapped here: the local copy stays
        try await eb.sync()
        #expect(try await eb.remoteFolders().isEmpty)
    }

    @Test func devicesReadEachOthersFolders() async throws {
        let (a, b) = try await twoDevices()
        try await a.session.publishFolders([.init(name: "Notes", path: "/Users/a/Notes")])
        let listed = try await b.session.deviceFolders()
        #expect(listed.count == 2)
        let aId = await a.session.deviceId()
        #expect(listed.first { $0.device.id == aId }?.folders == [.init(name: "Notes", path: "/Users/a/Notes")])
        #expect(listed.first { $0.device.id != aId }?.folders == nil)
    }
}
