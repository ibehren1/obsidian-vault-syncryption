import Foundation
import SyncryptionAPI
import SyncryptionCrypto
import SyncryptionStore
import TestBackend
import Testing

@testable import SyncryptionSync

/// A settable clock, in ms, for the quiet period of packages.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    var ms: Int {
        get { lock.withLock { value } }
        set { lock.withLock { value = newValue } }
    }
    var date: Date { Date(timeIntervalSince1970: Double(ms) / 1000) }
}

/// `d`'s engine again, on `clock`.
func clocked(_ d: TestDevice, _ clock: TestClock) async -> SyncEngine {
    engineFor(d.session, fs: d.fs, store: d.store, name: d.name, deviceId: await d.session.deviceId(), warnings: d.warnings) {
        $0.now = { clock.date }
    }
}

let pkg = "Money.quicken"

/// A package with two files on `fs`.
func makeMoney(_ fs: MemoryFs, data: String = "v1") {
    fs.makePackage(pkg)
    fs.set("\(pkg)/data", data)
    fs.set("\(pkg)/attach/r.txt", "receipt")
}

@Suite(.enabled(if: TestBackend.available, "needs uv to start the backend"))
struct PackageTests {
    @Test func uploadsAPackageWholeOnceItIsQuiet() async throws {
        let (a, b) = try await twoDevices()
        let clock = TestClock()
        let engine = await clocked(a, clock)
        makeMoney(a.fs)
        let last = a.fs.now
        a.fs.set("Note.md", "x")
        clock.ms = a.fs.now + 1000
        var r = try await engine.sync()
        #expect(r.pushed == 1)
        guard case .settling(let until)? = r.held[pkg] else { Issue.record("not held: \(r.held)"); return }
        #expect(until == Date(timeIntervalSince1970: Double(last + 30_000) / 1000))
        #expect(try a.store.outbox().count == 2)
        clock.ms = a.fs.now + 31_000
        r = try await engine.sync()
        #expect(r.pushed == 2 && r.held.isEmpty)
        try await b.engine.sync()
        #expect(b.fs.text("\(pkg)/data") == "v1" && b.fs.text("\(pkg)/attach/r.txt") == "receipt")
        // A deletion in it waits too.
        a.fs.delete("\(pkg)/attach/r.txt")
        clock.ms = a.fs.now + 1000
        r = try await engine.sync()
        #expect(r.pushed == 0 && r.held[pkg] != nil)
        clock.ms = a.fs.now + 31_000
        #expect(try await engine.sync().pushed == 1)
        #expect(a.warnings.all.isEmpty)
    }

    @Test func waitsWhileAnAppHasItOpenEvenWhenForced() async throws {
        let (a, _) = try await twoDevices()
        let clock = TestClock()
        let engine = await clocked(a, clock)
        makeMoney(a.fs)
        a.fs.setOpen("\(pkg)/data", by: 4242)
        clock.ms = a.fs.now + 3_600_000
        #expect(try await engine.sync().held[pkg] == .inUse(pid: 4242))
        #expect(try await engine.sync(force: true).held[pkg] == .inUse(pid: 4242))
        a.fs.setOpen("\(pkg)/data", by: nil)
        a.fs.set("\(pkg)/data", "v2")
        clock.ms = a.fs.now + 1000
        #expect(try await engine.sync().pushed == 0)
        // Sync now doesn't wait for the quiet period.
        let r = try await engine.sync(force: true)
        #expect(r.pushed == 2 && r.held.isEmpty)
    }

    @Test func writesNothingIntoAPackageAnAppHasOpen() async throws {
        let (a, b) = try await twoDevices()
        makeMoney(a.fs)
        try await a.engine.sync(force: true)
        try await b.engine.sync()
        b.fs.makePackage(pkg)
        a.fs.set("\(pkg)/data", "v2")
        try await a.engine.sync(force: true)
        b.fs.setOpen("\(pkg)/attach/r.txt", by: 99)
        let r = try await b.engine.sync()
        #expect(r.held[pkg] == .inUse(pid: 99))
        #expect(b.fs.text("\(pkg)/data") == "v1")
        #expect(b.warnings.all.isEmpty)
        b.fs.setOpen("\(pkg)/attach/r.txt", by: nil)
        try await b.engine.sync()
        #expect(b.fs.text("\(pkg)/data") == "v2")
        #expect(b.warnings.all.isEmpty)
    }

    @Test func makesAConflictCopyOfAPackageChangedOnBothSides() async throws {
        let (a, b) = try await twoDevices()
        makeMoney(a.fs)
        try await a.engine.sync(force: true)
        try await b.engine.sync()
        b.fs.makePackage(pkg)
        a.fs.set("\(pkg)/data", "from laptop")
        try await a.engine.sync(force: true)
        b.fs.set("\(pkg)/data", "from phone")
        b.fs.set("\(pkg)/new.txt", "only on the phone")
        let r = try await b.engine.sync(force: true)
        let copy = try #require(r.conflicts.first)
        #expect(copy.hasPrefix("Money (conflict Phone ") && copy.hasSuffix(").quicken"))
        #expect(r.merged == 0)
        // The vault's version keeps the name; this Mac's goes to the copy, whole.
        #expect(b.fs.text("\(pkg)/data") == "from laptop")
        #expect(b.fs.text("\(pkg)/new.txt") == nil)
        #expect(b.fs.text("\(copy)/data") == "from phone")
        #expect(b.fs.text("\(copy)/new.txt") == "only on the phone")
        #expect(b.fs.text("\(copy)/attach/r.txt") == "receipt")
        try await syncAll(b, a)
        #expect(texts(a.fs) == texts(b.fs))
        #expect(a.warnings.all.isEmpty && b.warnings.all.isEmpty)
    }

    @Test func filesItJustReceivedArentALocalChange() async throws {
        let (a, b) = try await twoDevices()
        makeMoney(a.fs)
        try await a.engine.sync(force: true)
        try await b.engine.sync()
        b.fs.makePackage(pkg)
        // FSEvents report every file the pull wrote; the package's quiet period keeps them queued.
        for p in b.fs.paths { try await b.engine.noteChange(p) }
        a.fs.set("\(pkg)/data", "v2")
        try await a.engine.sync(force: true)
        let r = try await b.engine.sync()
        #expect(r.conflicts.isEmpty)
        #expect(b.fs.text("\(pkg)/data") == "v2")
    }

    @Test func waitsWhileAnotherDeviceUploadsThePackage() async throws {
        let (a, b) = try await twoDevices()
        makeMoney(a.fs)
        let lockId = try b.session.cipher.fileId(pkg)
        let holder = String(repeating: "B", count: 22)
        try await b.session.api.acquireLock(b.session.vault.id, lockId, clientId: holder)
        let r = try await a.engine.sync(force: true)
        #expect(r.held[pkg] == .uploading(device: "Phone") && r.pushed == 0)
        try await b.session.api.releaseLock(b.session.vault.id, lockId, clientId: holder)
        #expect(try await a.engine.sync(force: true).pushed == 2)
    }

    @Test func takesBackItsCommitsWhenAnotherWriterInterleaves() async throws {
        let (a, b) = try await twoDevices()
        makeMoney(a.fs)
        a.fs.set("\(pkg)/meta", "m1")
        try await a.engine.sync(force: true)
        try await b.engine.sync()
        // The phone commits into the package without its lock (it doesn't see a package).
        b.fs.set("\(pkg)/meta", "m2 phone")
        try await b.engine.sync()
        a.fs.set("\(pkg)/data", "v2 laptop")
        try await a.engine.noteChange("\(pkg)/data")
        try await Task.sleep(for: .milliseconds(5))
        a.fs.set("\(pkg)/meta", "m2 laptop")
        try await a.engine.noteChange("\(pkg)/meta")
        // Hide the phone's commit from the pulls until the laptop commits, as if it came a
        // moment later.
        let state = Log()
        a.transport.after = { req, resp in
            if req.method == "POST" && req.url.path.contains("/locks/") { state.add("locked") }
            if req.method == "PUT" && req.url.path.contains("/files/") && !state.all.contains("committed") { state.add("committed") }
            guard !state.all.contains("committed"), req.method == "GET", req.url.path.hasSuffix("/changes"),
                  let since = URLComponents(url: req.url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "since" })?.value,
                  var json = try? JSONSerialization.jsonObject(with: resp.body) as? [String: Any] else { return resp }
            state.add("hidden")
            json["changes"] = []
            json["cursor"] = Int(since)
            json["more"] = false
            var t = resp
            t.body = try! JSONSerialization.data(withJSONObject: json)
            return t
        }
        let r = try await a.engine.sync(force: true)
        #expect(state.all.contains("locked") && state.all.contains("hidden") && state.all.contains("committed"))
        let copy = try #require(r.conflicts.first)
        #expect(a.fs.text("\(pkg)/data") == "v1" && a.fs.text("\(pkg)/meta") == "m2 phone")
        #expect(a.fs.text("\(copy)/data") == "v2 laptop" && a.fs.text("\(copy)/meta") == "m2 laptop")
        try await syncAll(a, b)
        // The phone has the vault's package as it left it, unmixed, and the copy.
        #expect(b.fs.text("\(pkg)/data") == "v1" && b.fs.text("\(pkg)/meta") == "m2 phone")
        #expect(texts(a.fs) == texts(b.fs))
    }
}
