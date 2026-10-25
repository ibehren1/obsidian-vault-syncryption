import AppKit
import UserNotifications
import SwiftUI
import SyncryptionAPI
import SyncryptionAppCore

/// The menu bar app. It has no Dock icon (`LSUIElement`); its windows open from the menu.
@main
struct SyncryptionApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        MenuBarExtra {
            MenuView(model: delegate.model, updater: delegate.updater)
        } label: {
            MenuBarLabel(model: delegate.model)
        }
        .menuBarExtraStyle(.window)

        Window("Sync Status", id: "status") {
            StatusWindow(model: delegate.model)
        }
        .defaultSize(width: 920, height: 720)
        .defaultLaunchBehavior(.suppressed)

        Window("Welcome", id: "welcome") {
            WelcomeView(model: delegate.model)
        }
        .windowResizability(.contentSize)
        .defaultLaunchBehavior(delegate.model.vaults.isEmpty ? .presented : .suppressed)

        Window("Add Vault", id: "add") {
            AddVaultView(model: delegate.model)
        }
        .windowResizability(.contentSize)
        .defaultLaunchBehavior(.suppressed)

        Window("Vault Syncryption Client Settings", id: "settings") {
            SettingsView(model: delegate.model)
        }
        .defaultSize(width: 860, height: 620)
        .defaultLaunchBehavior(.suppressed)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    #if DEBUG
    let model = Snapshot.demoModel() ?? AppModel()
    #else
    let model = AppModel()
    #endif
    lazy var updater = Updater(isSyncing: { [model] in model.isSyncing }, stop: { [model] in await model.stopAllAndWait() })

    func applicationDidFinishLaunching(_ notification: Notification) {
        FolderIcon.logo = NSImage(named: "Logo")
        FinderExtension.turnOnOnce()
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        model.onPendingApproval = { vault, devices in
            let content = UNMutableNotificationContent()
            content.title = "Approve a device for \(vault.config.vaultName)?"
            content.body = devices.count == 1 ? "\(devices[0].name) is waiting. Compare its pairing code \(devices[0].code) before approving."
                : "\(devices.count) devices are waiting for approval."
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        }
        model.startAll()
        if let version = updater.updatedVersion() {
            let content = UNMutableNotificationContent()
            content.title = "Updated to \(version)"
            content.body = "Vault Syncryption Client updated itself. If macOS asks to allow access to the Keychain, choose Always Allow."
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        }
        #if !DEBUG
        updater.start()
        #endif
        // A menu bar app isn't active at launch: bring the welcome window forward.
        if model.vaults.isEmpty { activate() }
        #if DEBUG
        Snapshot.runIfAsked(model)
        #endif
    }

    func applicationWillTerminate(_ notification: Notification) {
        model.stopAll()
    }

    /// Opening the app again (from Finder, Launchpad or the Dock) while it runs shows its
    /// status window: the way in when the menu bar can't show the icon.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { WindowOpener.shared.open(model.vaults.isEmpty ? "welcome" : "status") }
        return true
    }

    func applicationWillFinishLaunching(_ notification: Notification) {
        DockIcon.apply()
    }
}

/// The menu bar icon. It also hands SwiftUI's window opener to the app delegate, which has no
/// SwiftUI environment of its own.
struct MenuBarLabel: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        icon.onAppear { WindowOpener.shared.openWindow = openWindow }
    }

    /// Green when every vault is synced, yellow while syncing, red when one needs attention.
    /// The menu bar draws SwiftUI images as templates, so a colored icon has to be an NSImage
    /// that isn't one.
    private var icon: Image {
        let name = model.hasProblem ? "exclamationmark.lock" : "lock.rotation"
        let color: NSColor? = switch model.menuBarKind {
        case .ok: .systemGreen
        case .busy: .systemYellow
        case .error, .warn: .systemRed
        case .off: nil
        }
        guard let color, let symbol = NSImage(systemSymbolName: name, accessibilityDescription: "Vault Syncryption Client")?
            .withSymbolConfiguration(.init(paletteColors: [color])) else { return Image(systemName: name) }
        symbol.isTemplate = false
        return Image(nsImage: symbol)
    }
}

/// Opens a window scene by id from outside a view.
@MainActor
final class WindowOpener {
    static let shared = WindowOpener()
    var openWindow: OpenWindowAction?

    func open(_ id: String) {
        openWindow?(id: id)
        activate()
    }
}

/// Whether the app shows in the Dock as well as the menu bar (for a menu bar too full to show
/// its icon). Off by default.
@MainActor
enum DockIcon {
    static let key = "showsDockIcon"

    static var isOn: Bool { UserDefaults.standard.bool(forKey: key) }

    static func set(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: key)
        apply()
    }

    static func apply() {
        NSApp.setActivationPolicy(isOn ? .regular : .accessory)
    }
}

/// Bring the app forward so a window it opens gets the focus (a menu bar app isn't active).
@MainActor
func activate() {
    NSApp.activate()
}
