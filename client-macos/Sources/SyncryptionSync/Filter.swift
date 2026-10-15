import Foundation
import SyncryptionCrypto

/// Which paths a macOS folder syncs: generic rules, not Obsidian's (PLAN, macOS Client).
/// Dot files sync; OS clutter, version-control and package folders, the client's own temp
/// files and names no vault path may have don't.
public struct PathFilter: @unchecked Sendable {  // the compiled patterns are never mutated
    /// Folders that are never synced, at any depth.
    static let excludedFolders: Set<String> = [".git", "node_modules", ".trash", ".Trashes", ".Spotlight-V100", ".fseventsd",
                                               ".TemporaryItems", ".DocumentRevisions-V100"]
    /// Files that are never synced, at any depth.
    static let excludedFiles: Set<String> = [".DS_Store", "Thumbs.db", "desktop.ini", "Icon\r"]
    /// Per-device files of the Obsidian plugin, if the folder is also an Obsidian vault.
    static let workspaceFiles: Set<String> = ["workspace.json", "workspace-mobile.json", "workspaces.json"]
    /// The prefix of the client's temp files (atomic writes).
    public static let tempPrefix = ".syncryption-tmp-"

    private let patterns: [Regex<AnyRegexOutput>]

    /// `exclude`: the user's exclude list, one pattern per entry (see `parseExcludes`).
    public init(exclude: [String] = []) {
        patterns = exclude.compactMap { try? Regex(Self.compile($0)) }
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
        if segments.contains(where: { Self.excludedFolders.contains(String($0)) }) { return true }
        return segments.count >= 3 && segments[0] == ".obsidian" && segments[1] == "plugins" && segments[2] == "vault-syncryption"
    }

    private func userExcluded(_ path: String) -> Bool { patterns.contains { path.wholeMatch(of: $0) != nil } }

    /// True for files that are synced.
    public func includes(_ path: String) -> Bool {
        guard KDF.isVaultPath(path) else { return false }
        var segments = path.split(separator: "/", omittingEmptySubsequences: false)
        let name = String(segments.removeLast())
        if folderExcluded(segments) || Self.excludedFiles.contains(name) { return false }
        if name.hasPrefix("._") || name.hasPrefix(Self.tempPrefix) { return false }
        if segments.count == 1 && segments[0] == ".obsidian" && Self.workspaceFiles.contains(name) { return false }
        return !userExcluded(path)
    }

    /// True for folders whose whole content is excluded, so a scan can skip them.
    public func skipsFolder(_ folder: String) -> Bool {
        folderExcluded(folder.split(separator: "/", omittingEmptySubsequences: false)) || userExcluded(folder)
    }
}
