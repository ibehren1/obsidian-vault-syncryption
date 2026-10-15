import Foundation

/// Three-way merge of text files and conflict-copy names (docs/architecture.md 4.2).
public enum Merge {
    static let textExtensions: Set<String> = ["md", "txt", "canvas", "base", "json", "css", "js", "csv", "tsv", "yaml", "yml",
                                              "html", "xml", "svg"]
    static let jsonExtensions: Set<String> = ["json", "canvas"]

    static func fileExtension(_ path: String) -> String {
        let name = path.split(separator: "/", omittingEmptySubsequences: false).last.map(String.init) ?? path
        guard let dot = name.lastIndex(of: "."), dot > name.startIndex else { return "" }
        return name[name.index(after: dot)...].lowercased()
    }

    public static func isMergeable(_ path: String) -> Bool { textExtensions.contains(fileExtension(path)) }

    /// Lines with their line endings, as UTF-8 bytes, so joining them gives back the exact text.
    static func lines(_ data: [UInt8]) -> [[UInt8]] {
        var out: [[UInt8]] = []
        var start = 0
        for (i, b) in data.enumerated() where b == 0x0a {
            out.append(Array(data[start...i]))
            start = i + 1
        }
        if start < data.count { out.append(Array(data[start...])) }
        return out
    }

    /// Merge `local` and `remote`, both changed from `base` (nil if the file didn't exist
    /// there). Returns the merged bytes, or nil if the changes conflict or the file isn't text.
    public static func mergeText(path: String, base: [UInt8]?, local: [UInt8], remote: [UInt8]) -> [UInt8]? {
        guard isMergeable(path) else { return nil }
        let b = base ?? []
        guard String(validating: b, as: UTF8.self) != nil, String(validating: local, as: UTF8.self) != nil,
              String(validating: remote, as: UTF8.self) != nil
        else { return nil }
        var merged: [UInt8] = []
        for region in Diff3.merge(lines(local), lines(b), lines(remote)) {
            guard case .ok(let ls) = region else { return nil }
            for l in ls { merged += l }
        }
        if jsonExtensions.contains(fileExtension(path)) {
            guard (try? JSONSerialization.jsonObject(with: Data(merged), options: [.fragmentsAllowed])) != nil else { return nil }
        }
        return merged
    }

    /// `Notes/Plan (conflict MacBook 2026-10-02 1530).md`. `taken` says whether a path is in
    /// use, so a second conflict in the same minute gets a number.
    public static func conflictPath(_ path: String, device: String, date: Date, calendar: Calendar = .current,
                                    taken: (String) -> Bool) -> String
    {
        let slash = path.lastIndex(of: "/")
        let dir = slash.map { String(path[...$0]) } ?? ""
        let name = slash.map { String(path[path.index(after: $0)...]) } ?? path
        var stem = name, ext = ""
        if let dot = name.lastIndex(of: "."), dot > name.startIndex {
            stem = String(name[..<dot])
            ext = String(name[dot...])
        }
        let banned = Set("\\/:*?\"<>|#^[]")
        var safeDevice = String(device.filter { !banned.contains($0) }).trimmingCharacters(in: .whitespaces)
        if safeDevice.isEmpty { safeDevice = "device" }
        let c = calendar.dateComponents([.year, .month, .day, .hour, .minute], from: date)
        let stamp = String(format: "%04d-%02d-%02d %02d%02d", c.year!, c.month!, c.day!, c.hour!, c.minute!)
        var i = 1
        while true {
            let suffix = i == 1 ? "" : " \(i)"
            let candidate = "\(dir)\(stem) (conflict \(safeDevice) \(stamp)\(suffix))\(ext)"
            if !taken(candidate) { return candidate }
            i += 1
        }
    }
}
