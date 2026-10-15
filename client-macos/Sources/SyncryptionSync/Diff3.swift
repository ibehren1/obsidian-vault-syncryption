/// A port of node-diff3's `diff3Merge` (MIT, used by the plugin) with
/// `excludeFalseConflicts`, so both clients merge the same way.
enum Diff3 {
    enum Region<T> {
        case ok([T])
        case conflict
    }

    private final class Candidate {
        let i: Int, j: Int
        let chain: Candidate?
        init(_ i: Int, _ j: Int, _ chain: Candidate?) {
            self.i = i
            self.j = j
            self.chain = chain
        }
    }

    private static func lcs<T: Hashable>(_ b1: [T], _ b2: [T]) -> Candidate {
        var classes: [T: [Int]] = [:]
        for (j, item) in b2.enumerated() { classes[item, default: []].append(j) }
        var candidates = [Candidate(-1, -1, nil)]
        for (i, item) in b1.enumerated() {
            var r = 0
            var c = candidates[0]
            for j in classes[item] ?? [] {
                var s = r
                while s < candidates.count {
                    if candidates[s].j < j && (s == candidates.count - 1 || candidates[s + 1].j > j) { break }
                    s += 1
                }
                if s < candidates.count {
                    let new = Candidate(i, j, candidates[s])
                    if r == candidates.count { candidates.append(c) } else { candidates[r] = c }
                    r = s + 1
                    c = new
                    if r == candidates.count { break }
                }
            }
            if r == candidates.count { candidates.append(c) } else { candidates[r] = c }
        }
        return candidates[candidates.count - 1]
    }

    private struct Hunk {
        let ab: Character
        let oStart: Int, oLength: Int, abStart: Int, abLength: Int
    }

    /// (start1, length1, start2, length2) for each mismatch between the buffers.
    private static func diffIndices<T: Hashable>(_ b1: [T], _ b2: [T]) -> [(Int, Int, Int, Int)] {
        var result: [(Int, Int, Int, Int)] = []
        var tail1 = b1.count, tail2 = b2.count
        var candidate: Candidate? = lcs(b1, b2)
        while let c = candidate {
            let m1 = tail1 - c.i - 1
            let m2 = tail2 - c.j - 1
            tail1 = c.i
            tail2 = c.j
            if m1 != 0 || m2 != 0 { result.append((tail1 + 1, m1, tail2 + 1, m2)) }
            candidate = c.chain
        }
        return result.reversed()
    }

    /// Merge `a` and `b`, both changed from `o`.
    static func merge<T: Hashable>(_ a: [T], _ o: [T], _ b: [T]) -> [Region<T>] {
        var hunks = diffIndices(o, a).map { Hunk(ab: "a", oStart: $0.0, oLength: $0.1, abStart: $0.2, abLength: $0.3) }
            + diffIndices(o, b).map { Hunk(ab: "b", oStart: $0.0, oLength: $0.1, abStart: $0.2, abLength: $0.3) }
        // A stable sort, as JavaScript's.
        hunks = hunks.enumerated().sorted { ($0.element.oStart, $0.offset) < ($1.element.oStart, $1.offset) }.map(\.element)

        var results: [Region<T>] = []
        var okBuffer: [T] = []
        func flushOk() {
            if !okBuffer.isEmpty { results.append(.ok(okBuffer)) }
            okBuffer = []
        }
        var curr = 0
        func advance(to end: Int) {
            if end > curr {
                okBuffer += o[curr..<end]
                curr = end
            }
        }

        var index = 0
        while index < hunks.count {
            let hunk = hunks[index]
            index += 1
            let regionStart = hunk.oStart
            var regionEnd = hunk.oStart + hunk.oLength
            var regionHunks = [hunk]
            advance(to: regionStart)
            while index < hunks.count {
                let next = hunks[index]
                if next.oStart > regionEnd { break }
                regionEnd = max(regionEnd, next.oStart + next.oLength)
                regionHunks.append(next)
                index += 1
            }
            if regionHunks.count == 1 {
                if hunk.abLength > 0 {
                    let buffer = hunk.ab == "a" ? a : b
                    okBuffer += buffer[hunk.abStart..<(hunk.abStart + hunk.abLength)]
                }
            } else {
                var boundsA = [a.count, -1, o.count, -1]
                var boundsB = [b.count, -1, o.count, -1]
                for h in regionHunks {
                    let oEnd = h.oStart + h.oLength
                    let abEnd = h.abStart + h.abLength
                    if h.ab == "a" {
                        boundsA = [min(h.abStart, boundsA[0]), max(abEnd, boundsA[1]), min(h.oStart, boundsA[2]), max(oEnd, boundsA[3])]
                    } else {
                        boundsB = [min(h.abStart, boundsB[0]), max(abEnd, boundsB[1]), min(h.oStart, boundsB[2]), max(oEnd, boundsB[3])]
                    }
                }
                let aStart = boundsA[0] + (regionStart - boundsA[2])
                let aEnd = boundsA[1] + (regionEnd - boundsA[3])
                let bStart = boundsB[0] + (regionStart - boundsB[2])
                let bEnd = boundsB[1] + (regionEnd - boundsB[3])
                let aContent = Array(a[max(0, aStart)..<max(aStart, min(aEnd, a.count))])
                let bContent = Array(b[max(0, bStart)..<max(bStart, min(bEnd, b.count))])
                if aContent == bContent {
                    okBuffer += aContent  // a false conflict: both sides made the same change
                } else {
                    flushOk()
                    results.append(.conflict)
                }
            }
            curr = regionEnd
        }
        advance(to: o.count)
        flushOk()
        return results
    }
}
