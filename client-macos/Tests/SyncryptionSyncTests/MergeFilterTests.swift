import Foundation
import Testing

@testable import SyncryptionSync

private func enc(_ s: String) -> [UInt8] { Array(s.utf8) }
private func dec(_ b: [UInt8]?) -> String? { b.map { String(decoding: $0, as: UTF8.self) } }

@Suite struct MergeTests {
    @Test func mergesEditsToDifferentLines() {
        #expect(dec(Merge.mergeText(path: "a.md", base: enc("one\ntwo\nthree\n"), local: enc("ONE\ntwo\nthree\n"),
                                    remote: enc("one\ntwo\nTHREE\n"))) == "ONE\ntwo\nTHREE\n")
    }

    @Test func keepsLineEndingsAndAMissingFinalNewline() {
        #expect(dec(Merge.mergeText(path: "a.md", base: enc("a\r\nb\r\nc"), local: enc("A\r\nb\r\nc"), remote: enc("a\r\nb\r\nC")))
            == "A\r\nb\r\nC")
    }

    @Test func acceptsTheSameChangeOnBothSides() {
        #expect(dec(Merge.mergeText(path: "a.md", base: enc("x\n"), local: enc("y\n"), remote: enc("y\n"))) == "y\n")
    }

    @Test func returnsNilForConflictingEdits() {
        #expect(Merge.mergeText(path: "a.md", base: enc("x\n"), local: enc("local\n"), remote: enc("remote\n")) == nil)
    }

    @Test func mergesFilesWithoutABase() {
        #expect(dec(Merge.mergeText(path: "a.md", base: nil, local: enc("same\n"), remote: enc("same\n"))) == "same\n")
        #expect(Merge.mergeText(path: "a.md", base: nil, local: enc("one\n"), remote: enc("two\n")) == nil)
    }

    @Test func refusesBinaryAndInvalidUTF8() {
        #expect(Merge.mergeText(path: "a.png", base: enc("x"), local: enc("y"), remote: enc("x")) == nil)
        #expect(Merge.mergeText(path: "a.md", base: enc("x"), local: [0xff, 0xfe], remote: enc("x")) == nil)
    }

    @Test func refusesInvalidJSON() throws {
        #expect(Merge.mergeText(path: "data.json", base: enc("{\n\"a\": 1\n}\n"), local: enc("{\n\"a\": 1,\n\"b\": 2\n}\n"),
                                remote: enc("{\n\"a\": 1\n}\n,\n")) == nil)
        let canvas = { (a: Int, z: Int) in enc("{\n\"a\": \(a),\n\"m\": 0,\n\"z\": \(z)\n}\n") }
        let ok = try #require(Merge.mergeText(path: "x.canvas", base: canvas(1, 0), local: canvas(2, 0), remote: canvas(1, 9)))
        let obj = try JSONSerialization.jsonObject(with: Data(ok)) as! [String: Int]
        #expect(obj == ["a": 2, "m": 0, "z": 9])
    }

    @Test func mergesInsertionsAtBothEnds() {
        let base = "a\nb\nc\nd\ne\n"
        #expect(dec(Merge.mergeText(path: "n.md", base: enc(base), local: enc("top\n" + base), remote: enc(base + "bottom\n")))
            == "top\na\nb\nc\nd\ne\nbottom\n")
        #expect(dec(Merge.mergeText(path: "n.md", base: enc(base), local: enc("a\nc\nd\ne\n"), remote: enc("a\nb\nc\nd\nE\n")))
            == "a\nc\nd\nE\n")
    }

    @Test func knowsWhichFilesAreText() {
        #expect(Merge.isMergeable("Notes/x.MD"))
        #expect(Merge.isMergeable("x.canvas"))
        #expect(!Merge.isMergeable(".md"))
        #expect(!Merge.isMergeable("dir.md/file"))
        #expect(!Merge.isMergeable("photo.jpg"))
    }

    @Test func conflictPaths() {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let date = cal.date(from: DateComponents(year: 2026, month: 10, day: 2, hour: 15, minute: 3))!
        #expect(Merge.conflictPath("Notes/Plan.md", device: "MacBook", date: date, calendar: cal) { _ in false }
            == "Notes/Plan (conflict MacBook 2026-10-02 1503).md")
        #expect(Merge.conflictPath("README", device: "Phone", date: date, calendar: cal) { _ in false } == "README (conflict Phone 2026-10-02 1503)")
        #expect(Merge.conflictPath(".hidden", device: "Phone", date: date, calendar: cal) { _ in false } == ".hidden (conflict Phone 2026-10-02 1503)")
        let taken: Set = ["a (conflict device 2026-10-02 1503).md"]
        #expect(Merge.conflictPath("a.md", device: "  /:*  ", date: date, calendar: cal) { taken.contains($0) }
            == "a (conflict device 2026-10-02 1503 2).md")
    }
}

@Suite struct FilterTests {
    let f = PathFilter(exclude: PathFilter.parseExcludes("# comment\nPrivate\n*.tmp\nArchive/**/old\n\n"))

    @Test func syncsNormalAndDotFiles() {
        for p in ["a.md", "Notes/b.md", ".hidden", "Notes/.config/x.json", ".obsidian/app.json", ".obsidian/workspace.json",
                  ".obsidian/plugins/vault-syncryption/data.json"] {
            #expect(f.includes(p), "\(p)")
        }
    }

    @Test func skipsClutter() {
        for p in [".DS_Store", "x/.DS_Store", "x/._a.md", ".git/config", "a/node_modules/x.js", ".trash/a.md", "Icon\r",
                  "Notes/.syncryption-tmp-1234", ".fseventsd/x", "a\\b.md", "C:/x.md"] {
            #expect(!f.includes(p), "\(p.debugDescription)")
        }
    }

    @Test func appliesTheExcludeList() {
        #expect(!f.includes("Private"))
        #expect(!f.includes("Private/a.md"))
        #expect(f.includes("Private2/a.md"))
        // Patterns are folder-relative, as in the plugin: `*` stays within one segment.
        #expect(!f.includes("y.tmp"))
        #expect(f.includes("x/y.tmp"))
        #expect(!f.includes("Archive/2020/x/old"))
        #expect(!f.includes("Archive/2020/x/old/file.md"))
        #expect(f.skipsFolder("Private"))
        #expect(f.skipsFolder("a/.git"))
        #expect(!f.skipsFolder("Notes"))
    }

    @Test func syncsOnlyMappedFoldersWithTheirOwnExcludes() {
        let f = PathFilter(folders: ["Notes": ["drafts", "*.tmp"], "Code": []])
        for p in ["Notes/a.md", "Notes/x/b.tmp", "Code/drafts/a.swift", "Code/a.tmp", "Notes/.hidden"] {
            #expect(f.includes(p), "\(p)")
        }
        // Root-level files, unmapped folders, and each folder's own excludes.
        for p in ["a.md", "Notes", "Photos/a.jpg", "notes/a.md", "Notes/drafts/a.md", "Notes/a.tmp", "Code/.git/HEAD"] {
            #expect(!f.includes(p), "\(p)")
        }
        #expect(f.skipsFolder("Photos"))
        #expect(!f.skipsFolder("Notes"))
        #expect(f.skipsFolder("Notes/drafts"))
        #expect(!f.skipsFolder("Code/drafts"))
    }

    @Test func checksFolderNames() {
        for n in ["Notes", ".config", "My Files", "Ünïcode"] { #expect(PathFilter.isFolderName(n), "\(n)") }
        for n in ["", ".git", "node_modules", ".DS_Store", "a/b", "..", "._x", "C:"] { #expect(!PathFilter.isFolderName(n), "\(n)") }
    }
}
