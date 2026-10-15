import FinderSync
import Foundation

/// The bundled Finder Sync extension, which puts the app's icon on synced folders in Finder's
/// sidebar. macOS installs extensions turned off; the app turns it on once, and after that it
/// is the user's choice in System Settings.
enum FinderExtension {
    static let identifier = "com.behrenshome.syncryption.mac.FinderSync"
    private static let turnedOnKey = "finderExtensionTurnedOn"

    static var isEnabled: Bool { FIFinderSyncController.isExtensionEnabled }

    /// Register the extension and turn it on, the first time the app runs.
    static func turnOnOnce() {
        guard !UserDefaults.standard.bool(forKey: turnedOnKey),
              let appex = Bundle.main.builtInPlugInsURL?.appending(path: "SyncryptionFinder.appex"),
              FileManager.default.fileExists(atPath: appex.path) else { return }
        UserDefaults.standard.set(true, forKey: turnedOnKey)
        Task.detached {
            pluginkit(["-a", appex.path])
            pluginkit(["-e", "use", "-i", identifier])
        }
    }

    /// System Settings' list of Finder extensions.
    static func showSettings() { FIFinderSyncController.showExtensionManagementInterface() }

    private static func pluginkit(_ arguments: [String]) {
        let p = Process()
        p.executableURL = URL(filePath: "/usr/bin/pluginkit")
        p.arguments = arguments
        try? p.run()
        p.waitUntilExit()
    }
}
