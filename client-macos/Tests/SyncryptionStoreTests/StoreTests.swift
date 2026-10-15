import Foundation
import Testing

@testable import SyncryptionStore

@Suite struct StoreTests {
    static func stores() throws -> [any SyncStore] {
        let url = FileManager.default.temporaryDirectory.appending(path: "store-\(UUID().uuidString)/state.db")
        return [MemoryStore(), try SQLiteStore(url: url)]
    }

    @Test(arguments: try stores())
    func roundTrips(store: any SyncStore) throws {
        try store.setMeta(MetaKey.cursor, 42)
        #expect(try store.meta(MetaKey.cursor, as: Int.self) == 42)
        try store.setMeta(MetaKey.replacedDevice, String?.none)
        #expect(try store.meta(MetaKey.replacedDevice, as: String.self) == nil)

        let f = SyncedFile(fileId: "id", rev: 3, deleted: false, sha256: "ab", size: 2, mtime: 5, epoch: 1)
        let nfc = "caf\u{e9}.md", nfd = "cafe\u{301}.md"
        try store.putFile(nfc, f)
        #expect(try store.file(nfc) == f)
        #expect(try store.file(nfd) == nil)
        try store.putFile(nfd, f)
        #expect(try store.files().count == 2)
        #expect(try store.countFiles() == 2)
        #expect(try store.totalSize() == 2 * f.size)
        try store.removeFile(nfd)
        #expect(try Array(store.files().keys) == [PathKey(nfc)])

        try store.enqueue("a.md")
        try store.enqueue("b.md")
        let first = try store.outbox()
        #expect(first.map(\.path) == ["a.md", "b.md"])
        try store.enqueue("a.md")  // queued again while being pushed
        try store.dequeue(first[0])
        try store.dequeue(first[1])
        #expect(try store.outbox().map(\.path) == ["a.md"])

        try store.clear()
        #expect(try store.files().isEmpty && store.outbox().isEmpty && store.meta(MetaKey.cursor, as: Int.self) == nil)
    }
}
