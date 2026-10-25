import Foundation

/// A problem that skipped a file, or a conflict copy a sync made, with when it happened.
/// Never plaintext.
public struct Problem: Equatable, Sendable {
    public let text: String
    public let at: Date
    public let isConflict: Bool
}

/// The problems of the last 6 hours, newest last, at most 50.
public struct RecentProblems: Equatable, Sendable {
    public static let lifetime: TimeInterval = 6 * 3600
    static let limit = 50

    private(set) var all: [Problem] = []

    public init() {}

    mutating func add(_ text: String, conflict: Bool = false, at: Date = Date()) {
        all.append(Problem(text: text, at: at, isConflict: conflict))
        prune(now: at)
        if all.count > Self.limit { all.removeFirst(all.count - Self.limit) }
    }

    mutating func prune(now: Date = Date()) {
        all.removeAll { now.timeIntervalSince($0.at) >= Self.lifetime }
    }

    /// The problems younger than 6 hours at `now`.
    public func current(now: Date = Date()) -> [Problem] {
        all.filter { now.timeIntervalSince($0.at) < Self.lifetime }
    }
}
