import Foundation

extension FolderController {
    /// One line for the menu.
    public var statusText: String {
        switch status {
        case .idle: "Not started"
        case .connecting: "Connecting…"
        case .needsSecret: "Needs the server's shared secret to create the vault"
        case .pairing(let code, _): "Waiting for approval · code \(code)"
        case .syncing(let what): what
        case .synced(let at):
            "Synced \(at.formatted(date: .omitted, time: .shortened)) · \(fileCount) \(fileCount == 1 ? "file" : "files") · \(sizeText)"
                + (pendingCount > 0 ? " · \(pendingCount) waiting" : "")
        case .offline(let why): why
        case .paused: "Paused"
        case .error(let why): why
        case .refused: "This key is remote-only. The macOS client syncs full devices only: make it a full device from another device, or remove it."
        case .revoked: "This Mac's key was removed from the vault. Create a new key to pair this Mac again, or remove the folder."
        case .keyProblem(let why): why
        }
    }

    /// The size of the files in sync, as Finder writes it ("1.2 MB").
    public var sizeText: String { totalSize.formatted(.byteCount(style: .file)) }

    /// An SF Symbol for the status.
    public var statusSymbol: String {
        switch status {
        case .synced: "checkmark.circle"
        case .syncing, .connecting: "arrow.triangle.2.circlepath"
        case .offline: "wifi.slash"
        case .paused, .idle: "pause.circle"
        case .needsSecret, .pairing: "person.badge.key"
        case .error, .refused, .revoked, .keyProblem: "exclamationmark.triangle"
        }
    }
}

extension FolderController {
    /// How much attention a status needs, for its colour.
    public enum Kind: Sendable { case ok, busy, warn, error, off }

    /// The short state name for the status pill.
    public var statusName: String {
        switch status {
        case .idle: "Not connected"
        case .connecting: "Connecting"
        case .needsSecret: "Needs secret"
        case .pairing: "Awaiting approval"
        case .syncing: "Syncing"
        case .synced: "Synced"
        case .offline(let why): why.hasPrefix("The server is in maintenance") ? "Maintenance" : "Offline"
        case .paused: "Paused"
        case .error: "Error"
        case .refused: "Remote-only"
        case .revoked: "Removed"
        case .keyProblem: "Key problem"
        }
    }

    public var statusKind: Kind {
        switch status {
        case .synced: .ok
        case .syncing, .connecting: .busy
        case .offline, .paused, .needsSecret, .pairing: .warn
        case .error, .refused, .revoked, .keyProblem: .error
        case .idle: .off
        }
    }

    /// The status line beyond the state name: shown when it says more than "Synced".
    public var statusDetail: String? {
        switch status {
        case .synced, .idle: nil
        case .paused: "Sync is paused on this Mac. Changes are noted and sent when it resumes."
        default: statusText
        }
    }
}
