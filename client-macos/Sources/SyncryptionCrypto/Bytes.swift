import Foundation

/// Byte helpers for the wire formats in docs/crypto.md.

public typealias Bytes = [UInt8]

extension Array where Element == UInt8 {
    public init(utf8 s: String) { self = Array(s.utf8) }

    public var data: Data { Data(self) }

    public var hex: String { map { String(format: "%02x", $0) }.joined() }

    public init?(hex s: String) {
        guard s.count % 2 == 0 else { return nil }
        var out = Bytes()
        out.reserveCapacity(s.count / 2)
        var it = s.utf8.makeIterator()
        while let hi = it.next(), let lo = it.next() {
            guard let h = hexValue(hi), let l = hexValue(lo) else { return nil }
            out.append(h << 4 | l)
        }
        self = out
    }

    /// Standard base64 with padding.
    public var base64: String { Data(self).base64EncodedString() }

    /// Standard base64 without padding, as in age headers.
    public var base64NoPad: String {
        var s = base64
        while s.hasSuffix("=") { s.removeLast() }
        return s
    }

    /// base64url without padding (`b64u` in the specs).
    public var b64u: String {
        base64NoPad.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
    }

    /// Standard base64 with padding; nil on invalid input.
    public init?(base64 s: String) {
        guard let d = Data(base64Encoded: s) else { return nil }
        self = Bytes(d)
    }

    /// Strict unpadded base64: rejects padding, whitespace and non-canonical encodings.
    public init?(base64NoPad s: String) {
        guard s.utf8.allSatisfy({ isBase64Char($0) }), s.count % 4 != 1 else { return nil }
        guard let d = Data(base64Encoded: s + String(repeating: "=", count: (4 - s.count % 4) % 4)) else { return nil }
        let out = Bytes(d)
        guard out.base64NoPad == s else { return nil }
        self = out
    }

    /// Strict base64url without padding.
    public init?(b64u s: String) {
        guard !s.contains("+"), !s.contains("/") else { return nil }
        self.init(base64NoPad: s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/"))
    }
}

private func hexValue(_ c: UInt8) -> UInt8? {
    switch c {
    case UInt8(ascii: "0")...UInt8(ascii: "9"): c - UInt8(ascii: "0")
    case UInt8(ascii: "a")...UInt8(ascii: "f"): c - UInt8(ascii: "a") + 10
    case UInt8(ascii: "A")...UInt8(ascii: "F"): c - UInt8(ascii: "A") + 10
    default: nil
    }
}

private func isBase64Char(_ c: UInt8) -> Bool {
    (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c == 0x2b || c == 0x2f
}

// Expressions here are written with explicit types: older Swift compilers (6.2, as on the CI
// runner) give up type-checking long chains of operators on integer and array literals.

/// `u32be(n)`.
public func u32be(_ n: UInt32) -> Bytes {
    var out = Bytes(repeating: 0, count: 4)
    for i in 0..<4 {
        let shift = UInt32(24 - 8 * i)
        out[i] = UInt8(truncatingIfNeeded: n >> shift)
    }
    return out
}

/// The big-endian u32 at `offset` in `b`.
public func readU32be(_ b: Bytes, at offset: Int) -> UInt32 {
    var n: UInt32 = 0
    for i in 0..<4 {
        let byte = UInt32(b[offset + i])
        n = (n << 8) | byte
    }
    return n
}

/// The parts joined into one byte array.
public func concat(_ parts: Bytes...) -> Bytes {
    var out = Bytes()
    out.reserveCapacity(parts.reduce(0) { $0 + $1.count })
    for p in parts { out.append(contentsOf: p) }
    return out
}

/// SSH wire `string`: u32be(length) || bytes.
public func sshString(_ x: Bytes) -> Bytes { u32be(UInt32(x.count)) + x }

/// Constant-time comparison.
public func constantTimeEqual(_ a: Bytes, _ b: Bytes) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<a.count { diff |= a[i] ^ b[i] }
    return diff == 0
}

/// Overwrite secret bytes in place.
public func wipe(_ b: inout Bytes) {
    for i in b.indices { b[i] = 0 }
}

/// Wrap text at `width` columns, as in PEM armor.
func wrapLines(_ s: String, width: Int) -> [String] {
    var lines: [String] = []
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: width, limitedBy: s.endIndex) ?? s.endIndex
        lines.append(String(s[i..<j]))
        i = j
    }
    return lines
}

/// Bounds-checked reader for the SSH wire format. Throws `error` on any overrun.
struct SshReader {
    private let buf: Bytes
    private var off = 0
    private let error: any Error

    init(_ buf: Bytes, error: any Error) {
        self.buf = buf
        self.error = error
    }

    var remaining: Int { buf.count - off }

    mutating func bytes(_ n: Int) throws -> Bytes {
        guard n >= 0, n <= remaining else { throw error }
        defer { off += n }
        return Array(buf[off..<(off + n)])
    }

    mutating func u32() throws -> UInt32 {
        let b = try bytes(4)
        return readU32be(b, at: 0)
    }

    mutating func string() throws -> Bytes { try bytes(Int(try u32())) }

    mutating func rest() throws -> Bytes { try bytes(remaining) }
}

extension String {
    /// Bytes as Latin-1, for ASCII protocol identifiers.
    init(latin1 b: Bytes) { self = String(b.map { Character(Unicode.Scalar($0)) }) }
}
