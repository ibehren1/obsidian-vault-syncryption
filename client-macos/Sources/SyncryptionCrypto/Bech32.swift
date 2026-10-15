import Foundation

/// Bech32 (BIP 173), as age uses it for `age1...` recipients and `AGE-SECRET-KEY-1...`
/// identities, without the 90-character limit.
enum Bech32 {
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        let gen: [UInt32] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3]
        var chk: UInt32 = 1
        for v in values {
            let b = chk >> 25
            chk = (chk & 0x1ff_ffff) << 5 ^ UInt32(v)
            for i in 0..<5 where (b >> i) & 1 == 1 { chk ^= gen[i] }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: [UInt8]) -> [UInt8] {
        let high: [UInt8] = hrp.map { $0 >> 5 }
        let low: [UInt8] = hrp.map { $0 & 31 }
        return concat(high, [0], low)
    }

    private static func convert(_ data: [UInt8], from: Int, to: Int, pad: Bool) -> [UInt8]? {
        var acc = 0, bits = 0
        var out: [UInt8] = []
        let maxv = (1 << to) - 1
        for v in data {
            guard Int(v) >> from == 0 else { return nil }
            acc = acc << from | Int(v)
            bits += from
            while bits >= to {
                bits -= to
                out.append(UInt8(acc >> bits & maxv))
            }
        }
        if pad {
            if bits > 0 { out.append(UInt8(acc << (to - bits) & maxv)) }
        } else if bits >= from || (acc << (to - bits)) & maxv != 0 {
            return nil
        }
        return out
    }

    /// Lowercase bech32 of `data` under `hrp`.
    static func encode(hrp: String, _ data: Bytes) -> String {
        let h = Array(hrp.lowercased().utf8)
        let values = convert(data, from: 8, to: 5, pad: true)!
        let zeros = [UInt8](repeating: 0, count: 6)
        let mod: UInt32 = polymod(concat(hrpExpand(h), values, zeros)) ^ 1
        var checksum = [UInt8](repeating: 0, count: 6)
        for i in 0..<6 {
            let shift = UInt32(5 * (5 - i))
            checksum[i] = UInt8(truncatingIfNeeded: (mod >> shift) & 31)
        }
        let data: [UInt8] = concat(values, checksum).map { charset[Int($0)] }
        let separator: [UInt8] = [UInt8(ascii: "1")]
        return String(decoding: concat(h, separator, data), as: UTF8.self)
    }

    /// Decode bech32 of either case (not mixed). Returns the lowercase hrp and the data.
    static func decode(_ s: String) -> (hrp: String, data: Bytes)? {
        guard s == s.lowercased() || s == s.uppercased() else { return nil }
        let lower = Array(s.lowercased().utf8)
        guard let sep = lower.lastIndex(of: UInt8(ascii: "1")), sep >= 1, lower.count - sep >= 7 else { return nil }
        let hrp = Array(lower[..<sep])
        guard hrp.allSatisfy({ $0 >= 33 && $0 <= 126 }) else { return nil }
        var values: [UInt8] = []
        for c in lower[(sep + 1)...] {
            guard let i = charset.firstIndex(of: c) else { return nil }
            values.append(UInt8(i))
        }
        guard polymod(concat(hrpExpand(hrp), values)) == 1 else { return nil }
        guard let data = convert(Array(values.dropLast(6)), from: 5, to: 8, pad: false) else { return nil }
        return (String(decoding: hrp, as: UTF8.self), data)
    }
}
