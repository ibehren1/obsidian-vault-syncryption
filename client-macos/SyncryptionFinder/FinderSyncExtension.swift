import Cocoa
import FinderSync

/// The Finder Sync extension. It watches the synced folders that show the folder icon, so that
/// Finder shows the app's icon for them in the sidebar (Finder ignores custom folder icons
/// there). It reads the folders of every vault from the app's vaults.json (a read-only
/// sandbox exception) and reloads it when the app rewrites the file.
final class FinderSyncExtension: FIFinderSync {
    private let directory: URL
    private var source: DispatchSourceFileSystemObject?

    override init() {
        // The sandbox moves NSHomeDirectory() into the container; the folders are in the real home.
        let home = getpwuid(getuid()).map { String(cString: $0.pointee.pw_dir) } ?? NSHomeDirectory()
        directory = URL(filePath: home, directoryHint: .isDirectory)
            .appending(path: "Library/Application Support/Vault Syncryption", directoryHint: .isDirectory)
        super.init()
        reload()
        watch()
    }

    private func reload() {
        struct Folder: Decodable {
            let path: String
            let showsFolderIcon: Bool?
        }
        struct Vault: Decodable {
            let folders: [Folder]?
        }
        let data = try? Data(contentsOf: directory.appending(path: "vaults.json"))
        let folders = (data.flatMap { try? JSONDecoder().decode([Vault].self, from: $0) } ?? []).flatMap { $0.folders ?? [] }
        FIFinderSyncController.default().directoryURLs = Set(folders.filter { $0.showsFolderIcon ?? true }.map { URL(filePath: $0.path, directoryHint: .isDirectory) })
    }

    /// vaults.json is replaced atomically, which changes its directory.
    private func watch() {
        let fd = open(directory.path, O_EVTONLY)
        guard fd >= 0 else { return }
        let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: .write, queue: .main)
        source.setEventHandler { [weak self] in self?.reload() }
        source.setCancelHandler { close(fd) }
        source.resume()
        self.source = source
    }
}
