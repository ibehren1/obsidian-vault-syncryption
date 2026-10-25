import Foundation
import Testing

@testable import SyncryptionAppCore

@Suite struct RecentProblemsTests {
    @Test func keepsTheTimeAndDropsProblemsAfterSixHours() {
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        var p = RecentProblems()
        p.add("old", at: start)
        p.add("Conflict copy: a.md", conflict: true, at: start.addingTimeInterval(3600))
        #expect(p.current(now: start.addingTimeInterval(60)).map(\.at) == [start, start.addingTimeInterval(3600)])
        #expect(p.current(now: start.addingTimeInterval(6 * 3600)).map(\.text) == ["Conflict copy: a.md"])
        #expect(p.current(now: start.addingTimeInterval(7 * 3600)).isEmpty)
        // A new problem prunes the expired ones.
        p.add("new", at: start.addingTimeInterval(6 * 3600 + 1))
        #expect(p.all.map(\.text) == ["Conflict copy: a.md", "new"])
        #expect(p.all.first?.isConflict == true)
    }

    @Test func keepsAtMostFifty() {
        var p = RecentProblems()
        for i in 0..<60 { p.add("\(i)") }
        #expect(p.all.count == 50 && p.all.first?.text == "10")
    }
}
