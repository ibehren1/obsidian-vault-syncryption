#if DEBUG
import AppKit
import SwiftUI
import SyncryptionAPI
import SyncryptionAppCore
import SyncryptionCrypto

/// Debug builds only: `--snapshot <folder>` renders the windows to PNG files and quits, so
/// the layout can be checked without screen recording.
@MainActor
enum Snapshot {
    /// `--demo <endpoint> <shared secret>`: a throwaway model on a local server, with a
    /// sample folder, for snapshots of the populated windows.
    static func demoModel() -> AppModel? {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--demo"), i + 2 < args.count else { return nil }
        let dir = FileManager.default.temporaryDirectory.appending(path: "syncryption-demo-\(UUID().uuidString)")
        let folder = dir.appending(path: "Research Notes")
        try? FileManager.default.createDirectory(at: folder.appending(path: "Projects"), withIntermediateDirectories: true)
        for (name, text) in [("Inbox.md", "# Inbox\n"), ("Projects/Plan.md", "# Plan\n"), ("Projects/Budget.csv", "a,b\n"), ("Reading list.md", "- one\n")] {
            try? Data(text.utf8).write(to: folder.appending(path: name))
        }
        let model = AppModel(configs: ConfigStore(directory: dir.appending(path: "support")), keys: KeyStore(service: "Vault Syncryption demo"))
        let endpoint = args[i + 1], secret = args[i + 2]
        guard let c = try? model.addFolder(path: folder.path, endpoint: endpoint, username: "demo\(Int.random(in: 1000...9999))",
                                           vaultName: "Research", deviceName: "Studio Mac") else { return model }
        Task { @MainActor in
            while c.status != .needsSecret { try? await Task.sleep(for: .milliseconds(50)) }
            c.provideSecret(secret)
            // A second device asks to join, so the keys and approvals show.
            while c.session == nil { try? await Task.sleep(for: .milliseconds(50)) }
            let seed = Primitives.random(32)
            if let api = try? ApiClient(endpoint: endpoint, username: c.config.username, vaultName: "Research", seed: seed, deviceName: "iPhone") {
                _ = try? await api.login()
            }
            try? Data("draft\n".utf8).write(to: folder.appending(path: "Draft.md"))
            c.syncNow()
        }
        return model
    }

    static func runIfAsked(_ model: AppModel) {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--snapshot"), i + 1 < args.count else { return }
        let dir = URL(filePath: args[i + 1])
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(args.contains("--demo") ? 9 : 6))
            await render(MenuView(model: model), size: nil, to: dir.appending(path: "menu.png"))
            await render(StatusWindow(model: model), size: CGSize(width: 920, height: 900), to: dir.appending(path: "status.png"))
            for (tab, name) in [(SettingsTab.general, "settings"), (.key, "settings-key"), (.devices, "settings-devices"),
                                (.recovery, "settings-recovery"), (.history, "settings-history")]
            {
                if let f = model.folders.first { SettingsSelection.shared.select(f.id, tab: tab) }
                await render(SettingsView(model: model), size: CGSize(width: 900, height: 640), to: dir.appending(path: "\(name).png"))
            }
            await render(AddFolderView(model: model), size: nil, to: dir.appending(path: "add.png"))
            await render(WelcomeView(model: model), size: nil, to: dir.appending(path: "welcome.png"))
            let windows = NSApp.windows.filter { $0.isVisible }.map { $0.title }
            try? windows.joined(separator: "\n").write(to: dir.appending(path: "launch-windows.txt"), atomically: true, encoding: .utf8)
            if let icon = FolderIcon.image(), let tiff = icon.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff) {
                try? rep.representation(using: .png, properties: [:])?.write(to: dir.appending(path: "folder-icon.png"))
            }
            let test = dir.appending(path: "Icon test")
            try? FileManager.default.createDirectory(at: test, withIntermediateDirectories: true)
            FolderIcon.apply(to: test)
            NSApp.terminate(nil)
        }
    }

    /// Render after the view had a moment to load what it shows.
    static func render<V: View>(_ view: V, size: CGSize?, to url: URL) async {
        let host = NSHostingView(rootView: view.environment(\.colorScheme, .light))
        let fitting = host.fittingSize
        let s = size ?? CGSize(width: max(fitting.width, 300), height: max(fitting.height, 200))
        let window = NSWindow(contentRect: NSRect(origin: .zero, size: s), styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = host
        window.orderBack(nil)
        try? await Task.sleep(for: .seconds(1.5))
        window.layoutIfNeeded()
        host.layoutSubtreeIfNeeded()
        if let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) {
            host.cacheDisplay(in: host.bounds, to: rep)
            try? rep.representation(using: .png, properties: [:])?.write(to: url)
        }
        window.orderOut(nil)
    }
}
#endif
