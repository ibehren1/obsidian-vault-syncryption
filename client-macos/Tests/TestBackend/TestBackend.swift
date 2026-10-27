import Foundation
import SyncryptionAPI

/// Starts the real backend (`uv run uvicorn ...`) once per test process, on a free port, so
/// the API and sync tests run against the server itself. Without uv those tests are skipped,
/// unless REQUIRE_BACKEND=1 (as in CI), which makes a missing backend an error.
public enum TestBackend {
    public static let sharedSecret = "test-shared-secret"

    public struct Unavailable: Error, CustomStringConvertible {
        public let description: String
    }

    /// The backend's URL, or nil when uv isn't installed and REQUIRE_BACKEND isn't set.
    public static func url() throws -> String? {
        try started.get()
    }

    public static var available: Bool { (try? url()) != nil }

    private static let started: Result<String?, Unavailable> = Result { try start() }.mapError {
        $0 as? Unavailable ?? Unavailable(description: "\($0)")
    }

    private static func start() throws -> String? {
        let required = ProcessInfo.processInfo.environment["REQUIRE_BACKEND"] == "1"
        guard let uv = which("uv") else {
            if required { throw Unavailable(description: "REQUIRE_BACKEND=1 but uv is not installed") }
            return nil
        }
        let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let dataDir = FileManager.default.temporaryDirectory.appending(path: "syncryption-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)
        let p = Process()
        p.executableURL = uv
        p.arguments = ["run", "--project", root.appending(path: "backend").path, "--quiet", "uvicorn", "--factory",
                       "syncryption_server.app:create_app", "--host", "127.0.0.1", "--port", "0", "--no-proxy-headers",
                       "--timeout-keep-alive", "75"]
        var env = ProcessInfo.processInfo.environment
        env["SHARED_SECRET"] = sharedSecret
        env["ADMIN_TOKEN"] = "test-admin-token-0123456789abcdef"
        env["BEHIND_PROXY"] = "TRUE"
        env["SYNCRYPTION_DATA_DIR"] = dataDir.path
        p.environment = env
        let stderr = Pipe()
        p.standardError = stderr
        p.standardOutput = FileHandle.nullDevice
        try p.run()
        process = p
        dataDirectory = dataDir
        atexit {
            TestBackend.process?.terminate()
            TestBackend.process?.waitUntilExit()
            if let d = TestBackend.dataDirectory { try? FileManager.default.removeItem(at: d) }
        }

        let found = Mutex<String?>(nil)
        let log = Mutex("")
        let ready = DispatchSemaphore(value: 0)
        stderr.fileHandleForReading.readabilityHandler = { h in
            let chunk = String(decoding: h.availableData, as: UTF8.self)
            let text = log.withLock { $0 += chunk; return $0 }
            if found.withLock({ $0 }) == nil, let m = text.firstMatch(of: /Uvicorn running on (http:\/\/127\.0\.0\.1:\d+)/) {
                found.withLock { $0 = String(m.1) }
                ready.signal()
            }
        }
        if ready.wait(timeout: .now() + 60) == .timedOut || !p.isRunning {
            throw Unavailable(description: "backend didn't start:\n\(log.withLock { $0 })")
        }
        return found.withLock { $0 }
    }

    nonisolated(unsafe) private static var process: Process?
    /// The server's data folder, to check that it holds no plaintext.
    nonisolated(unsafe) public private(set) static var dataDirectory: URL?

    private static func which(_ tool: String) -> URL? {
        let home = FileManager.default.homeDirectoryForCurrentUser.appending(path: ".local/bin").path
        let paths = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":").map(String.init)
            + ["/opt/homebrew/bin", "/usr/local/bin", home]
        return paths.map { URL(filePath: $0).appending(path: tool) }.first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    /// A transport whose every request looks like it comes from a new address (the server
    /// trusts the last X-Forwarded-For entry), so the per-IP auth rate limit never stops a
    /// test: a device that pairs, replaces its key and is removed logs in often in a minute.
    public static func transport() -> HookTransport {
        HookTransport(inner: ForwardedTransport())
    }

    /// A name no other test uses.
    public static func uniqueName(_ prefix: String) -> String {
        "\(prefix)\(UUID().uuidString.prefix(8).lowercased())"
    }
}

/// A small lock, since the backend's log arrives on another thread.
final class Mutex<T>: @unchecked Sendable {
    private var value: T
    private let lock = NSLock()
    init(_ v: T) { value = v }
    func withLock<R>(_ f: (inout T) -> R) -> R {
        lock.lock()
        defer { lock.unlock() }
        return f(&value)
    }
}

struct ForwardedTransport: Transport {
    let inner = URLSessionTransport()

    func send(_ request: HttpRequest, timeout: TimeInterval) async throws -> HttpResponse {
        var r = request
        r.headers["X-Forwarded-For"] = "10.\((1...3).map { _ in String(Int.random(in: 1...254)) }.joined(separator: "."))"
        return try await inner.send(r, timeout: timeout)
    }
}

/// A transport whose requests and responses a test can intercept: fail a download, tamper
/// with a blob, and so on.
public final class HookTransport: Transport, @unchecked Sendable {
    let inner: any Transport
    private let lock = NSLock()
    private var _before: (@Sendable (HttpRequest) throws -> HttpResponse?)?
    private var _after: (@Sendable (HttpRequest, HttpResponse) -> HttpResponse)?

    init(inner: any Transport) { self.inner = inner }

    /// Answer a request without the server (return nil to send it), or throw for "no response".
    public var before: (@Sendable (HttpRequest) throws -> HttpResponse?)? {
        get { lock.withLock { _before } }
        set { lock.withLock { _before = newValue } }
    }

    /// Change a response from the server.
    public var after: (@Sendable (HttpRequest, HttpResponse) -> HttpResponse)? {
        get { lock.withLock { _after } }
        set { lock.withLock { _after = newValue } }
    }

    public func send(_ request: HttpRequest, timeout: TimeInterval) async throws -> HttpResponse {
        if let r = try before?(request) { return r }
        let response = try await inner.send(request, timeout: timeout)
        return after?(request, response) ?? response
    }
}
