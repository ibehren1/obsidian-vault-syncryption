import AppKit
import Foundation
import Observation
import SyncryptionAPI
import SyncryptionCrypto

/// Updates the app from the public repo's client releases (`client-macos-v<x.y.z>`). A release
/// is installed only if its DMG carries an sshsig by the update key built in here: the app
/// is signed ad hoc, so its code signature can't say who built it.
@MainActor @Observable
public final class Updater {
    public enum State: Equatable {
        case idle
        case checking
        case downloading(String)
        /// Verified and staged, waiting until no vault syncs.
        case waiting(String)
        /// Verified and staged; installs when the user chooses (automatic install is off).
        case available(String)
        case installing(String)
        case failed(String)
        /// Verified, but this copy of the app can't replace itself: the DMG to install by hand.
        case cantInstall(String, dmg: URL)
    }

    /// The signers' namespace (`ssh-keygen -Y sign -n`).
    public nonisolated static let namespace = "syncryption-update@v1"
    /// The update key's public half. Empty: this build doesn't update itself.
    nonisolated static let publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK8w1LoxqVzoJNje8xRUlTCrDIKKorvl/ObudKkL+lp9 syncryption-update"
    nonisolated static let defaultRepo = "ibehren1/obsidian-vault-syncryption"
    nonisolated static let bundleId = "com.behrenshome.syncryption.mac"
    nonisolated static let appName = "VaultSyncryptionClient.app"
    static let firstCheck: Duration = .seconds(60)
    static let interval: Duration = .seconds(6 * 3600)

    public private(set) var state: State = .idle
    public private(set) var lastCheck: Date?
    public var installsAutomatically: Bool {
        didSet { defaults.set(!installsAutomatically, forKey: "updatesManual") }
    }

    /// Whether this build can update itself at all.
    public var isEnabled: Bool { trusted != nil }

    private let current: URL
    private let isSyncing: @MainActor () -> Bool
    private let stop: @MainActor () async -> Void
    private let defaults: UserDefaults
    private let trusted: Bytes?
    private var timer: Task<Void, Never>?
    private var staged: (version: String, app: URL)?

    public init(current: URL = Bundle.main.bundleURL, defaults: UserDefaults = .standard, isSyncing: @escaping @MainActor () -> Bool,
                stop: @escaping @MainActor () async -> Void)
    {
        self.current = current
        self.defaults = defaults
        self.isSyncing = isSyncing
        self.stop = stop
        trusted = Self.publicKey.isEmpty ? nil : try? OpenSSH.parsePublicKeyText(Self.publicKey)
        installsAutomatically = !defaults.bool(forKey: "updatesManual")
    }

    /// The repo whose releases to follow; `defaults write … UpdateRepo <owner/name>` for tests.
    private var repo: String { defaults.string(forKey: "UpdateRepo") ?? Self.defaultRepo }

    /// Versions whose signature failed: never tried again.
    private var rejected: Set<String> {
        get { Set(defaults.stringArray(forKey: "rejectedUpdates") ?? []) }
        set { defaults.set(Array(newValue).sorted(), forKey: "rejectedUpdates") }
    }

    /// Check a minute after launch, then every 6 hours.
    public func start() {
        guard isEnabled, timer == nil else { return }
        timer = Task { [weak self] in
            try? await Task.sleep(for: Self.firstCheck)
            while !Task.isCancelled {
                await self?.checkNow()
                try? await Task.sleep(for: Self.interval)
            }
        }
    }

    /// The version this app runs, if it differs from the last launch's (it was updated).
    public func updatedVersion() -> String? {
        let last = defaults.string(forKey: "lastVersion")
        defaults.set(clientVersion, forKey: "lastVersion")
        return last != nil && last != clientVersion ? clientVersion : nil
    }

    public func checkNow() async {
        guard let trusted else {
            state = .failed("This build doesn't update itself.")
            return
        }
        switch state {
        case .checking, .downloading, .waiting, .installing: return
        default: break
        }
        state = .checking
        do {
            var request = URLRequest(url: URL(string: "https://api.github.com/repos/\(repo)/releases?per_page=50")!)
            request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw UpdateError("GitHub refused the check.") }
            let releases = try JSONDecoder().decode([Release].self, from: data)
            lastCheck = Date()
            guard let c = Self.pick(releases, current: clientVersion), !rejected.contains(c.version) else {
                state = .idle
                return
            }
            if let s = staged, s.version == c.version {
                state = installsAutomatically ? .waiting(c.version) : .available(c.version)
                if installsAutomatically { await install() }
                return
            }
            state = .downloading(c.version)
            let dmg = try await download(c)
            let sig = try await URLSession.shared.data(from: c.sig).0
            guard Self.verify(dmg: Bytes(try Data(contentsOf: dmg)), signature: String(decoding: sig, as: UTF8.self), trusted: trusted) else {
                try? FileManager.default.removeItem(at: dmg)
                rejected.insert(c.version)
                state = .failed("The update to \(c.version) failed its signature check, so it wasn't installed.")
                return
            }
            if let reason = Self.cantInstallReason(current) {
                state = .cantInstall(reason, dmg: dmg)
                return
            }
            let current = current, version = c.version
            let app = try await Task.detached { try Self.stage(dmg: dmg, nextTo: current, version: version) }.value
            try? FileManager.default.removeItem(at: dmg)
            staged = (c.version, app)
            state = installsAutomatically ? .waiting(c.version) : .available(c.version)
            if installsAutomatically { await install() }
        } catch {
            state = .failed("Couldn't update: \(error)")
        }
    }

    /// Install the staged update once no vault syncs: stop the vaults, let a helper swap the
    /// app bundle once this process has quit, and quit. The helper opens the new app.
    public func install() async {
        guard let staged else { return }
        state = .waiting(staged.version)
        while isSyncing() {
            try? await Task.sleep(for: .seconds(60))
            if Task.isCancelled { return }
        }
        state = .installing(staged.version)
        await stop()
        do {
            let script = FileManager.default.temporaryDirectory.appending(path: "syncryption-update-\(UUID().uuidString).sh")
            try Self.helperScript(pid: getpid(), current: current, staged: staged.app).write(to: script, atomically: true, encoding: .utf8)
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/sh")
            p.arguments = [script.path]
            try p.run()
        } catch {
            state = .failed("Couldn't start the update: \(error)")
            return
        }
        NSApp.terminate(nil)
    }

    private func download(_ c: Candidate) async throws -> URL {
        let (temp, response) = try await URLSession.shared.download(from: c.dmg)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw UpdateError("The download failed.") }
        let dir = FileManager.default.temporaryDirectory.appending(path: "syncryption-updates")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let dest = dir.appending(path: "VaultSyncryptionClient-\(c.version).dmg")
        try? FileManager.default.removeItem(at: dest)
        try FileManager.default.moveItem(at: temp, to: dest)
        return dest
    }

    // MARK: Parts

    struct UpdateError: Error, CustomStringConvertible {
        let description: String
        init(_ d: String) { description = d }
    }

    /// A GitHub release, as the releases API lists it.
    public struct Release: Decodable, Sendable {
        public struct Asset: Decodable, Sendable {
            public let name: String
            public let url: URL
            enum CodingKeys: String, CodingKey {
                case name
                case url = "browser_download_url"
            }
        }

        public let tag: String
        public let draft: Bool
        public let prerelease: Bool
        public let assets: [Asset]
        enum CodingKeys: String, CodingKey {
            case tag = "tag_name", draft, prerelease, assets
        }
    }

    public struct Candidate: Equatable, Sendable {
        public let version: String
        public let dmg: URL
        public let sig: URL
    }

    /// The newest client release above `current` with a DMG and its signature.
    nonisolated static func pick(_ releases: [Release], current: String) -> Candidate? {
        var best: Candidate?
        for r in releases where !r.draft && !r.prerelease && r.tag.hasPrefix("client-macos-v") {
            let version = String(r.tag.dropFirst("client-macos-v".count))
            guard parts(version) != nil, newer(version, current), best.map({ newer(version, $0.version) }) ?? true else { continue }
            let name = "VaultSyncryptionClient-\(version).dmg"
            guard let dmg = r.assets.first(where: { $0.name == name }), let sig = r.assets.first(where: { $0.name == name + ".sig" })
            else { continue }
            best = Candidate(version: version, dmg: dmg.url, sig: sig.url)
        }
        return best
    }

    nonisolated private static func parts(_ v: String) -> [Int]? {
        let p = v.split(separator: ".", omittingEmptySubsequences: false).map { Int($0) }
        guard p.count == 3, p.allSatisfy({ $0 != nil && $0! >= 0 }) else { return nil }
        return p.map { $0! }
    }

    /// Whether version `a` is above `b`, by number (`0.1.10` is above `0.1.9`).
    nonisolated static func newer(_ a: String, _ b: String) -> Bool {
        guard let x = parts(a), let y = parts(b) else { return false }
        return y.lexicographicallyPrecedes(x)
    }

    /// Whether `signature` is an update sshsig over `dmg` by the key `trusted`.
    nonisolated static func verify(dmg: Bytes, signature: String, trusted: Bytes) -> Bool {
        (try? SshSig.verify(signature, namespace: namespace, message: dmg)) == trusted
    }

    /// Why the app at `current` can't replace itself, or nil.
    nonisolated static func cantInstallReason(_ current: URL) -> String? {
        let path = current.path
        if path.contains("/AppTranslocation/") || path.hasPrefix("/Volumes/") {
            return "Move the app to the Applications folder to get updates."
        }
        let dir = current.deletingLastPathComponent().path
        if !FileManager.default.isWritableFile(atPath: dir) {
            return "This user can't write to \(dir), so the update can't install itself. Install it from the download."
        }
        return nil
    }

    /// Copy the app out of `dmg` next to `current` (hidden, until the helper swaps it in) and
    /// check it: this app's id, the expected version, and a valid code signature.
    nonisolated static func stage(dmg: URL, nextTo current: URL, version: String, bundleId: String = bundleId) throws -> URL {
        let fm = FileManager.default
        let mount = fm.temporaryDirectory.appending(path: "syncryption-mount-\(UUID().uuidString)")
        try fm.createDirectory(at: mount, withIntermediateDirectories: true)
        try run("/usr/bin/hdiutil", ["attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", mount.path, dmg.path])
        defer {
            _ = try? run("/usr/bin/hdiutil", ["detach", mount.path, "-force"])
            try? fm.removeItem(at: mount)
        }
        let staged = current.deletingLastPathComponent().appending(path: ".VaultSyncryptionClient-\(version).app")
        try? fm.removeItem(at: staged)
        do {
            try run("/usr/bin/ditto", [mount.appending(path: appName).path, staged.path])
            let info = NSDictionary(contentsOf: staged.appending(path: "Contents/Info.plist"))
            guard info?["CFBundleIdentifier"] as? String == bundleId else { throw UpdateError("The update isn't this app.") }
            guard info?["CFBundleShortVersionString"] as? String == version else {
                throw UpdateError("The update's version isn't \(version).")
            }
            try run("/usr/bin/codesign", ["--verify", "--strict", staged.path])
            _ = try? run("/usr/bin/xattr", ["-dr", "com.apple.quarantine", staged.path])
            return staged
        } catch {
            try? fm.removeItem(at: staged)
            throw error
        }
    }

    /// A shell script that waits for `pid` to exit, puts `staged` in the place of `current`
    /// and opens it. If the swap fails, it puts the old app back and opens that.
    nonisolated static func helperScript(pid: Int32, current: URL, staged: URL, open: String = "/usr/bin/open") -> String {
        func q(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let cur = q(current.path), new = q(staged.path)
        let old = q(current.deletingLastPathComponent().appending(path: ".VaultSyncryptionClient-old.app").path)
        return """
            #!/bin/sh
            while kill -0 \(pid) 2>/dev/null; do sleep 0.2; done
            rm -rf \(old)
            if mv \(cur) \(old); then
              if mv \(new) \(cur); then
                \(open) \(cur)
                rm -rf \(old)
              else
                mv \(old) \(cur)
                \(open) \(cur)
              fi
            fi
            rm -f "$0"

            """
    }

    @discardableResult
    nonisolated static func run(_ tool: String, _ args: [String]) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        let output = out.fileHandleForReading.readDataToEndOfFile()
        let error = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else {
            let detail = String(decoding: error, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            throw UpdateError("\((tool as NSString).lastPathComponent) failed: \(detail)")
        }
        return String(decoding: output, as: UTF8.self)
    }
}
