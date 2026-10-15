import AppKit
import SwiftUI
import SyncryptionAppCore

/// Shown at launch while no folder is set up: says where the app lives (the menu bar, as it
/// has no Dock icon or main window) and starts adding a folder.
struct WelcomeView: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismiss) private var dismiss
    @State private var dock = DockIcon.isOn

    var body: some View {
        VStack(spacing: 16) {
            Logo(size: 80)
            Text("Welcome to Vault Syncryption").font(.title.weight(.semibold))
            Text("Sync folders on this Mac, end-to-end encrypted, with a vault on your Vault Syncryption server.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "lock.rotation").font(.title2).frame(width: 28)
                Text("Vault Syncryption lives in the menu bar, at the top right of the screen: it has no Dock icon. If you don't see its icon there, the menu bar may be full or hiding it: check System Settings → Menu Bar.")
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(12)
            .background(CardBackground())
            Toggle("Also show Vault Syncryption in the Dock", isOn: Binding(get: { dock }, set: { dock = $0; DockIcon.set($0) }))
            Text("Opening the app again from Finder or Launchpad always shows its status window.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Later") { dismiss() }
                Button("Add Folder…") {
                    dismiss()
                    openWindow(id: "add")
                    activate()
                }
                .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
            }
            .controlSize(.large)
        }
        .padding(28)
        .frame(width: 480)
        .onAppear { WindowOpener.shared.openWindow = openWindow }
    }
}
