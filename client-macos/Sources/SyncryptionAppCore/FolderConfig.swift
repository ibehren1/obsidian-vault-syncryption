import Foundation
import SyncryptionAPI
import SystemConfiguration

/// One synced folder: the plugin's settings (endpoint, username, vault name, device name,
/// encryption key and the exclude list), plus where the folder is.
public struct FolderConfig: Codable, Identifiable, Equatable, Sendable {
    public var id: UUID
    /// The folder on disk.
    public var path: String
    /// The server's origin (`normalizeEndpoint`).
    public var endpoint: String
    public var username: String
    /// NFC, trimmed (`normalizeVaultName`).
    public var vaultName: String
    public var deviceName: String
    /// `ssh-ed25519 AAAA...` of this folder's key; the private key is in the Keychain.
    public var publicKey: String
    /// One pattern per line (`PathFilter.parseExcludes`).
    public var exclude: String
    public var paused: Bool
    /// Show the synced-folder icon on the folder in Finder.
    public var showsFolderIcon: Bool

    public init(id: UUID = UUID(), path: String, endpoint: String, username: String, vaultName: String, deviceName: String,
                publicKey: String = "", exclude: String = "", paused: Bool = false, showsFolderIcon: Bool = true)
    {
        self.showsFolderIcon = showsFolderIcon
        self.id = id
        self.path = path
        self.endpoint = endpoint
        self.username = username
        self.vaultName = vaultName
        self.deviceName = deviceName
        self.publicKey = publicKey
        self.exclude = exclude
        self.paused = paused
    }

    private enum CodingKeys: String, CodingKey {
        case id, path, endpoint, username, vaultName, deviceName, publicKey, exclude, paused, showsFolderIcon
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        path = try c.decode(String.self, forKey: .path)
        endpoint = try c.decode(String.self, forKey: .endpoint)
        username = try c.decode(String.self, forKey: .username)
        vaultName = try c.decode(String.self, forKey: .vaultName)
        deviceName = try c.decode(String.self, forKey: .deviceName)
        publicKey = try c.decodeIfPresent(String.self, forKey: .publicKey) ?? ""
        exclude = try c.decodeIfPresent(String.self, forKey: .exclude) ?? ""
        paused = try c.decodeIfPresent(Bool.self, forKey: .paused) ?? false
        // Folders added before the icon existed get it too.
        showsFolderIcon = try c.decodeIfPresent(Bool.self, forKey: .showsFolderIcon) ?? true
    }

    public var keySlot: String { KeyStore.slot(origin: endpoint, username: username, vaultName: vaultName) }

    public var url: URL { URL(filePath: path, directoryHint: .isDirectory) }

    /// The folder's name, for menus.
    public var title: String { (path as NSString).lastPathComponent }
}

/// `~/Library/Application Support/Vault Syncryption/`: folders.json, and a folder per synced
/// folder with its `state.db`.
public struct ConfigStore: Sendable {
    public let directory: URL

    public init(directory: URL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appending(path: "Vault Syncryption"))
    {
        self.directory = directory
    }

    private var file: URL { directory.appending(path: "folders.json") }

    public func load() throws -> [FolderConfig] {
        guard FileManager.default.fileExists(atPath: file.path) else { return [] }
        return try JSONDecoder().decode([FolderConfig].self, from: Data(contentsOf: file))
    }

    public func save(_ folders: [FolderConfig]) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try e.encode(folders).write(to: file, options: .atomic)
    }

    /// The sync state of one folder.
    public func stateURL(_ id: UUID) -> URL { directory.appending(path: id.uuidString).appending(path: "state.db") }

    public func removeState(_ id: UUID) {
        try? FileManager.default.removeItem(at: directory.appending(path: id.uuidString))
    }

    public struct Invalid: Error, CustomStringConvertible {
        public let description: String
    }

    /// Check a new folder against the others: not the same vault twice (that would be two
    /// devices with one key slot), and no folder inside another.
    public static func check(_ new: FolderConfig, against existing: [FolderConfig]) throws {
        for f in existing where f.id != new.id {
            if f.keySlot == new.keySlot { throw Invalid(description: "The folder \(f.title) already syncs this vault on this Mac.") }
            let a = f.url.standardizedFileURL.path + "/", b = new.url.standardizedFileURL.path + "/"
            if a.hasPrefix(b) || b.hasPrefix(a) { throw Invalid(description: "Synced folders can't be inside each other (\(f.title)).") }
        }
    }
}

/// The device name to suggest: the Mac's name (System Settings → General → About), up to 64
/// characters. Read from the system configuration, which answers at once: `Host.current()`
/// resolves the machine's network names first and can block for a long time.
public func defaultDeviceName() -> String {
    let computer = SCDynamicStoreCopyComputerName(nil, nil) as String?
    var name = (computer ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    if name.isEmpty {
        // The local host name ("Isaacs-MacBook"), without the ".local".
        name = (SCDynamicStoreCopyLocalHostName(nil) as String?) ?? ""
    }
    return String((name.isEmpty ? "Mac" : name).prefix(64))
}
