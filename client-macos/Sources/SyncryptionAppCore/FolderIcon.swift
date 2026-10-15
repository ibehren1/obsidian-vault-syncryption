import AppKit
import Foundation

/// The Finder icon of a synced folder: the system folder icon with the app's logo on it.
/// macOS keeps a custom folder icon inside the folder (the hidden `Icon\r` file, which the
/// sync filter excludes) plus a Finder flag, so it stays on this Mac.
@MainActor
public enum FolderIcon {
    /// The logo to put on folders; the app sets it from its asset catalog at launch.
    public static var logo: NSImage?

    public static func image() -> NSImage? {
        guard let logo else { return nil }
        let size = NSSize(width: 512, height: 512)
        let folder = NSWorkspace.shared.icon(for: .folder)
        return NSImage(size: size, flipped: false) { rect in
            folder.draw(in: rect)
            // On the folder's front, a little below the middle, as system folder glyphs sit.
            let side = rect.width * 0.38
            let badge = NSRect(x: rect.midX - side / 2, y: rect.height * 0.2, width: side, height: side)
            NSGraphicsContext.current?.saveGraphicsState()
            let shadow = NSShadow()
            shadow.shadowColor = NSColor.black.withAlphaComponent(0.25)
            shadow.shadowOffset = NSSize(width: 0, height: -3)
            shadow.shadowBlurRadius = 6
            shadow.set()
            logo.draw(in: badge)
            NSGraphicsContext.current?.restoreGraphicsState()
            return true
        }
    }

    /// Give `folder` the synced-folder icon. Returns whether Finder accepted it.
    @discardableResult
    public static func apply(to folder: URL) -> Bool {
        guard let image = image() else { return false }
        return NSWorkspace.shared.setIcon(image, forFile: folder.path, options: [])
    }

    /// Give `folder` back its normal icon.
    public static func remove(from folder: URL) {
        NSWorkspace.shared.setIcon(nil, forFile: folder.path, options: [])
    }

    /// Whether `folder` has a custom icon (the `Icon\r` file).
    public static func isApplied(to folder: URL) -> Bool {
        FileManager.default.fileExists(atPath: folder.path + "/Icon\r")
    }
}
