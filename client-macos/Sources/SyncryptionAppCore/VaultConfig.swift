import Foundation
import SyncryptionAPI
import SyncryptionSync
import SystemConfiguration

/// One top-level vault folder synced on this Mac, and where it is on disk.
public struct FolderMapping: Codable, Identifiable, Equatable, Sendable {
    public var id: String { name }
    /// The vault folder: one path segment, NFC.
    public var name: String
    /// The local folder it syncs with.
    public var path: String
    /// One pattern per line, relative to the folder (`PathFilter.parseExcludes`).
    public var exclude: String
    public var paused: Bool
    /// Show the synced-folder icon on the folder in Finder.
    public var showsFolderIcon: Bool

    public init(name: String, path: String, exclude: String = "", paused: Bool = false, showsFolderIcon: Bool = true) {
        self.name = name
        self.path = path
        self.exclude = exclude
        self.paused = paused
        self.showsFolderIcon = showsFolderIcon
    }

    public var url: URL { URL(filePath: path, directoryHint: .isDirectory) }
}

/// One vault linked on this Mac: how to reach it (endpoint, username, vault name, device
/// name and this Mac's encryption key) and the vault folders this Mac syncs.
public struct VaultConfig: Codable, Identifiable, Equatable, Sendable {
    public var id: UUID
    /// The server's origin (`normalizeEndpoint`).
    public var endpoint: String
    public var username: String
    /// NFC, trimmed (`normalizeVaultName`).
    public var vaultName: String
    public var deviceName: String
    /// `ssh-ed25519 AAAA...` of this vault's key on this Mac; the private key is in the Keychain.
    public var publicKey: String
    /// The whole vault is paused.
    public var paused: Bool
    public var folders: [FolderMapping]

    public init(id: UUID = UUID(), endpoint: String, username: String, vaultName: String, deviceName: String, publicKey: String = "",
                paused: Bool = false, folders: [FolderMapping] = [])
    {
        self.id = id
        self.endpoint = endpoint
        self.username = username
        self.vaultName = vaultName
        self.deviceName = deviceName
        self.publicKey = publicKey
        self.paused = paused
        self.folders = folders
    }

    public var keySlot: String { KeyStore.slot(origin: endpoint, username: username, vaultName: vaultName) }

    /// The vault's name, for menus.
    public var title: String { vaultName }

    public func folder(_ name: String) -> FolderMapping? { folders.first { $0.name.utf8.elementsEqual(name.utf8) } }
}

/// `~/Library/Application Support/Vault Syncryption/`: vaults.json, and a folder per vault
/// with its `state.db`.
public struct ConfigStore: Sendable {
    public let directory: URL

    public init(directory: URL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appending(path: "Vault Syncryption"))
    {
        self.directory = directory
    }

    /// The file the Finder extension reads too.
    public static let fileName = "vaults.json"

    private var file: URL { directory.appending(path: Self.fileName) }

    public func load() throws -> [VaultConfig] {
        guard FileManager.default.fileExists(atPath: file.path) else { return [] }
        return try JSONDecoder().decode([VaultConfig].self, from: Data(contentsOf: file))
    }

    public func save(_ vaults: [VaultConfig]) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try e.encode(vaults).write(to: file, options: .atomic)
    }

    /// The sync state of one vault.
    public func stateURL(_ id: UUID) -> URL { directory.appending(path: id.uuidString).appending(path: "state.db") }

    public func removeState(_ id: UUID) {
        try? FileManager.default.removeItem(at: directory.appending(path: id.uuidString))
    }

    public struct Invalid: Error, CustomStringConvertible {
        public let description: String
    }

    /// Check a new vault link against the others: not the same vault twice (that would be two
    /// devices with one key slot).
    public static func check(_ new: VaultConfig, against existing: [VaultConfig]) throws {
        for v in existing where v.id != new.id && v.keySlot == new.keySlot {
            throw Invalid(description: "This Mac already syncs the vault \(v.vaultName).")
        }
    }

    /// Two folder names the disk (and so the vault, on this Mac) would see as one.
    public static func sameName(_ a: String, _ b: String) -> Bool {
        a.precomposedStringWithCanonicalMapping.lowercased() == b.precomposedStringWithCanonicalMapping.lowercased()
    }

    /// Check a folder about to be synced: a usable name, not already a folder of the vault
    /// (`taken`: the vault's folder names), and not inside or around another synced folder.
    public static func checkFolder(name: String, path: String, taken: [String], vaults: [VaultConfig]) throws {
        guard PathFilter.isFolderName(name) else { throw Invalid(description: "A vault folder can't be named “\(name)”.") }
        if let other = taken.first(where: { sameName($0, name) }) {
            throw Invalid(description: "“\(other)” is already in this vault. Two folders can't have the same name: map the existing one instead.")
        }
        let b = URL(filePath: path).standardizedFileURL.path + "/"
        for v in vaults {
            for f in v.folders {
                let a = f.url.standardizedFileURL.path + "/"
                if a.hasPrefix(b) || b.hasPrefix(a) {
                    throw Invalid(description: "Synced folders can't be inside each other (\(f.name) in \(v.vaultName)).")
                }
            }
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
