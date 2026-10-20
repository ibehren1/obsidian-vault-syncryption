import Foundation
import SyncryptionCrypto
import SyncryptionStore

/// Which paths a macOS vault syncs: generic rules for plain folders.
/// Dot files sync; OS clutter, version-control and package folders, the client's own temp
/// files and names no vault path may have don't.
///
/// A vault on the Mac holds only top-level folders, each mapped to a local folder (or not, on
/// this Mac). With `folders`, only paths inside a mapped folder are synced, and each folder's
/// exclude list is relative to that folder. Without (tests), the whole tree is one folder.
public struct PathFilter: @unchecked Sendable {  // the compiled patterns are never mutated
    /// Folders that are never synced, at any depth.
    static let excludedFolders: Set<String> = [".git", "node_modules", ".trash", ".Trashes", ".Spotlight-V100", ".fseventsd",
                                               ".TemporaryItems", ".DocumentRevisions-V100"]
    /// Files that are never synced, at any depth.
    static let excludedFiles: Set<String> = [".DS_Store", "Thumbs.db", "desktop.ini", "Icon\r"]
    /// The prefix of the client's temp files (atomic writes).
    public static let tempPrefix = ".syncryption-tmp-"

    private let patterns: [Regex<AnyRegexOutput>]
    /// The synced top-level folders and their exclude patterns, by name.
    private let folders: [PathKey: [Regex<AnyRegexOutput>]]?

    /// The whole tree as one folder, with one exclude list (see `parseExcludes`).
    public init(exclude: [String] = []) {
        patterns = Self.compileAll(exclude)
        folders = nil
    }

    /// Only the top-level folders in `folders` (name to its exclude list) are synced.
    public init(folders: [String: [String]]) {
        patterns = []
        self.folders = Dictionary(folders.map { (PathKey($0.key), Self.compileAll($0.value)) }, uniquingKeysWith: { a, _ in a })
    }

    /// The synced top-level folders, or nil for the whole tree.
    public var folderNames: [String]? { folders.map { $0.keys.map(\.path).sorted() } }

    private static func compileAll(_ exclude: [String]) -> [Regex<AnyRegexOutput>] {
        exclude.compactMap { try? Regex(Self.compile($0)) }
    }

    /// The top-level folder names a vault folder may have: one valid path segment that
    /// isn't one of the never-synced names.
    public static func isFolderName(_ name: String) -> Bool {
        KDF.isVaultPath(name) && !name.contains("/") && !excludedFolders.contains(name) && !excludedFiles.contains(name)
            && !name.hasPrefix("._") && !name.hasPrefix(tempPrefix)
    }

    /// The exclude list from the settings: one pattern per line, blank lines and `#` comments ignored.
    public static func parseExcludes(_ text: String) -> [String] {
        text.split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
    }

    /// A folder-relative pattern. `*` matches within one path segment and `**` across
    /// segments. It matches the path itself or anything inside it.
    static func compile(_ pattern: String) -> String {
        var clean = Substring(pattern)
        while clean.hasPrefix("/") { clean.removeFirst() }
        while clean.hasSuffix("/") { clean.removeLast() }
        var source = ""
        var i = clean.startIndex
        while i < clean.endIndex {
            let c = clean[i]
            let next = clean.index(after: i)
            if c == "*" && next < clean.endIndex && clean[next] == "*" {
                source += ".*"
                i = clean.index(after: next)
                continue
            }
            switch c {
            case "*": source += "[^/]*"
            case "?": source += "[^/]"
            default: source += NSRegularExpression.escapedPattern(for: String(c))
            }
            i = next
        }
        return "^\(source)(?:/.*)?$"
    }

    private func folderExcluded(_ segments: [Substring]) -> Bool {
        segments.contains { Self.excludedFolders.contains(String($0)) }
    }

    private static func matches(_ patterns: [Regex<AnyRegexOutput>], _ path: Substring) -> Bool {
        patterns.contains { path.wholeMatch(of: $0) != nil }
    }

    /// The exclude patterns for `path` and the part of it they apply to, or nil if `path`
    /// isn't inside a synced folder.
    private func scope(_ path: String) -> (patterns: [Regex<AnyRegexOutput>], rest: Substring)? {
        guard let folders else { return (patterns, Substring(path)) }
        guard let slash = path.firstIndex(of: "/"), let p = folders[PathKey(String(path[..<slash]))] else { return nil }
        return (p, path[path.index(after: slash)...])
    }

    /// True for files that are synced.
    public func includes(_ path: String) -> Bool {
        guard KDF.isVaultPath(path), let scope = scope(path) else { return false }
        var segments = path.split(separator: "/", omittingEmptySubsequences: false)
        let name = String(segments.removeLast())
        if folderExcluded(segments) || Self.excludedFiles.contains(name) { return false }
        if name.hasPrefix("._") || name.hasPrefix(Self.tempPrefix) { return false }
        return !Self.matches(scope.patterns, scope.rest)
    }

    /// True for folders whose whole content is excluded, so a scan can skip them.
    public func skipsFolder(_ folder: String) -> Bool {
        if folderExcluded(folder.split(separator: "/", omittingEmptySubsequences: false)) { return true }
        if let folders, !folder.contains("/") { return folders[PathKey(folder)] == nil }
        guard let scope = scope(folder) else { return true }
        return Self.matches(scope.patterns, scope.rest)
    }
}
