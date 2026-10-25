import Foundation
import SyncryptionCrypto

/// Typed client for the server API (docs/protocol.md), over a `Transport`. A port of
/// client-obsidian-plugin/src/api/client.ts.

public let versionHeader = "x-syncryption-version"
public let protocolHeader = "x-syncryption-protocol"

/// The server's form of a vault name: NFC, trimmed. The keyring and the login use it too.
public func normalizeVaultName(_ name: String) -> String {
    name.precomposedStringWithCanonicalMapping.trimmingCharacters(in: .whitespacesAndNewlines)
}

/// Hosts reached without leaving the machine: the only ones `http://` is accepted for.
private func isLoopback(_ host: String) -> Bool {
    if host == "localhost" || host == "::1" { return true }
    let parts = host.split(separator: ".", omittingEmptySubsequences: false)
    return parts.count == 4 && parts[0] == "127" && parts.allSatisfy { !$0.isEmpty && $0.count <= 3 && $0.allSatisfy(\.isNumber) }
}

public struct EndpointError: Error, Equatable, CustomStringConvertible {
    public let description: String
}

/// `https://Notes.Example.com/` -> `https://notes.example.com`. The endpoint must be an
/// origin: the server signs challenges for its origin, and the client compares the two.
/// `http://` is accepted only for this machine.
public func normalizeEndpoint(_ endpoint: String) throws(EndpointError) -> String {
    guard let c = URLComponents(string: endpoint.trimmingCharacters(in: .whitespacesAndNewlines)),
          let scheme = c.scheme?.lowercased(), let rawHost = c.host?.lowercased(), !rawHost.isEmpty
    else { throw EndpointError(description: "The endpoint must be a URL like https://notes.example.com") }
    let host = rawHost.hasPrefix("[") && rawHost.hasSuffix("]") ? String(rawHost.dropFirst().dropLast()) : rawHost
    guard scheme == "https" || (scheme == "http" && isLoopback(host)) else {
        throw EndpointError(description: "The endpoint must start with https:// (http:// only for localhost)")
    }
    guard c.path.isEmpty || c.path == "/", c.query == nil, c.fragment == nil, c.user == nil, c.password == nil else {
        throw EndpointError(description: "The endpoint must be just the server address, without a path")
    }
    let defaultPort = scheme == "https" ? 443 : 80
    let hostText = host.contains(":") ? "[\(host)]" : host
    let port = c.port.flatMap { $0 == defaultPort ? nil : ":\($0)" } ?? ""
    return "\(scheme)://\(hostText)\(port)"
}

/// Check a login challenge before signing it (protocol.md 5.1), so a malicious server can't
/// get a signature it could replay against another server.
public func checkChallenge(_ message: String, origin: String, username: String, vaultName: String, publicKey: Bytes) throws(ApiError) {
    let lines = message.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    func matches(_ s: String, prefix: String, _ ok: (Substring) -> Bool) -> Bool {
        s.hasPrefix(prefix) && ok(s.dropFirst(prefix.count))
    }
    let b64u = { (c: Character) in c.isASCII && (c.isLetter || c.isNumber || c == "_" || c == "-") }
    let ok = lines.count == 8
        && lines[0] == SshSig.namespaceAuth
        && lines[1] == "origin: \(origin)"
        && lines[2] == "username: \(username)"
        && lines[3].unicodeScalars.elementsEqual("vault: \(normalizeVaultName(vaultName))".unicodeScalars)
        && lines[4] == "key: \(OpenSSH.fingerprint(publicKey))"
        && matches(lines[5], prefix: "nonce: ") { $0.count == 43 && $0.allSatisfy(b64u) }
        && matches(lines[6], prefix: "expires: ") { $0.wholeMatch(of: /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ/) != nil }
        && lines[7].isEmpty
    guard ok else { throw ApiError(status: 0, code: "bad_challenge", message: "The server sent an unexpected login challenge.") }
}

public struct LastLogin: Sendable {
    public let at: Date
    public let remoteOnly: Bool
    public let graceSeconds: Int
}

public actor ApiClient {
    public nonisolated let origin: String
    public nonisolated let publicKey: Bytes
    public nonisolated let username: String
    /// The vault named at login (protocol.md 5), NFC and trimmed.
    public nonisolated let vaultName: String
    private let seed: Bytes
    private let deviceName: String
    private let transport: any Transport
    private let timeout: TimeInterval
    private var token: String?

    /// Set after login.
    public private(set) var deviceId: String?
    public private(set) var deviceStatus: String?
    public private(set) var lastLogin: LastLogin?

    /// `timeout`: give up on a request after this long (default 60 s, above the 25 s long-poll).
    public init(endpoint: String, username: String, vaultName: String, seed: Bytes, deviceName: String,
                transport: any Transport = URLSessionTransport(), timeout: TimeInterval = 60) throws(EndpointError)
    {
        origin = try normalizeEndpoint(endpoint)
        self.username = username
        self.vaultName = normalizeVaultName(vaultName)
        self.seed = seed
        self.deviceName = deviceName
        self.transport = transport
        self.timeout = timeout
        publicKey = Primitives.ed25519PublicKey(seed: seed)
    }

    /// Log in to `vaultName` (protocol.md 5). A new key of an existing vault joins it as
    /// pending, without the shared secret. A new key for a vault that doesn't exist yet gets
    /// `403 join_required` until `sharedSecret` is sent; it is then active and creates the
    /// vault. `409 vault_being_created`: another key is creating that vault.
    @discardableResult
    public func login(sharedSecret: String? = nil) async throws -> VerifyResponse {
        let challenge: ChallengeResponse = try await send(
            "POST", "/api/v1/auth/challenge",
            json: ChallengeRequest(publicKey: OpenSSH.publicKeyText(publicKey), username: username, vaultName: vaultName),
            token: nil)
        try checkChallenge(challenge.message, origin: origin, username: username, vaultName: vaultName, publicKey: publicKey)
        let signature = SshSig.sign(seed: seed, namespace: SshSig.namespaceAuth, message: Bytes(utf8: challenge.message))
        let result: VerifyResponse = try await send(
            "POST", "/api/v1/auth/verify",
            json: VerifyRequest(challengeId: challenge.challengeId, deviceName: deviceName, sharedSecret: sharedSecret,
                                signature: signature),
            token: nil)
        // An active key's device id never changes: a server that names another one isn't
        // followed. A pending key may get a new id: the server replaces stale pending keys.
        if deviceStatus == "active" && result.deviceId != deviceId {
            throw DeviceMismatchError(description: "The server returned another device's id for this key.")
        }
        token = result.token
        deviceId = result.deviceId
        deviceStatus = result.status
        lastLogin = LastLogin(at: Date(), remoteOnly: result.remoteOnly ?? false, graceSeconds: result.graceSeconds ?? 0)
        return result
    }

    /// Forget the session token, as if it expired (tests only).
    func dropToken(replacingWith t: String?) { token = t }

    // MARK: Devices (protocol.md 6)

    public func selfDevice() async throws -> SelfDevice { try await call("GET", "/api/v1/devices/self") }

    /// Every key of the vault, revoked ones included.
    public func devices(_ vaultId: String) async throws -> [Device] {
        let list: DeviceList = try await call("GET", "\(vaultPath(vaultId))/devices")
        return list.devices
    }

    /// `remoteOnly`: approve it as remote-only, matching its keyring policy.
    public func approveDevice(_ vaultId: String, _ deviceId: String, remoteOnly: Bool = false) async throws -> Device {
        try await call("POST", "\(vaultPath(vaultId))/devices/\(enc(deviceId))/approve", json: ApproveRequest(remoteOnly: remoteOnly))
    }

    /// Change another active key's policy. The keyring is updated first.
    public func setDevicePolicy(_ vaultId: String, _ deviceId: String, remoteOnly: Bool) async throws -> Device {
        try await call("PUT", "\(vaultPath(vaultId))/devices/\(enc(deviceId))/policy", json: PolicyRequest(remoteOnly: remoteOnly))
    }

    /// Lock or unlock another remote-only key: a locked one can't log in.
    public func setDeviceLocked(_ vaultId: String, _ deviceId: String, locked: Bool) async throws -> Device {
        try await call("PUT", "\(vaultPath(vaultId))/devices/\(enc(deviceId))/lock", json: LockRequest(locked: locked))
    }

    /// Set or clear this device's metadata, already encrypted (crypto.md 8.5).
    public func setDeviceMeta(_ vaultId: String, _ meta: Bytes?) async throws -> Device {
        try await call("PUT", "\(vaultPath(vaultId))/devices/self/meta", json: MetaUpload(meta: meta?.b64u))
    }

    /// Revoke a key of the vault (it may be this one) and end its sessions. 409 for the last active key.
    public func removeDevice(_ vaultId: String, _ deviceId: String) async throws {
        _ = try await raw("DELETE", "\(vaultPath(vaultId))/devices/\(enc(deviceId))")
    }

    // MARK: Vaults and keyrings (protocol.md 7)

    public func openVault(_ name: String) async throws -> OpenResponse {
        try await call("POST", "/api/v1/vaults/open", json: OpenRequest(name: name))
    }

    public func createVault(id: String, name: String, keyring: KeyringUpload) async throws -> Vault {
        try await call("POST", "/api/v1/vaults", json: CreateRequest(id: id, keyring: keyring, name: name))
    }

    public func keyring(_ vaultId: String, version: Int? = nil) async throws -> Keyring {
        try await call("GET", "\(vaultPath(vaultId))/keyring" + (version.map { "?version=\($0)" } ?? ""))
    }

    public func putKeyring(_ vaultId: String, _ upload: KeyringUpload) async throws -> Keyring {
        try await call("PUT", "\(vaultPath(vaultId))/keyring", json: upload)
    }

    /// The current keyring, for recovery (protocol.md 7.4). Pending tokens are allowed.
    public func recoveryKeyring(_ vaultId: String) async throws -> Keyring {
        try await call("GET", "\(vaultPath(vaultId))/recovery")
    }

    /// Upload the next keyring signed by the recovery key, activating this device's membership.
    public func recover(_ vaultId: String, _ upload: KeyringUpload) async throws -> Keyring {
        try await call("POST", "\(vaultPath(vaultId))/recover", json: upload)
    }

    // MARK: Blobs (protocol.md 8)

    public func putBlob(_ vaultId: String, _ blobId: String, _ bytes: Data) async throws {
        _ = try await raw("PUT", "\(vaultPath(vaultId))/blobs/\(enc(blobId))", body: bytes, contentType: "application/octet-stream")
    }

    public func getBlob(_ vaultId: String, _ blobId: String) async throws -> Data {
        try await raw("GET", "\(vaultPath(vaultId))/blobs/\(enc(blobId))").body
    }

    public func missingBlobs(_ vaultId: String, _ ids: [String]) async throws -> [String] {
        var missing: [String] = []
        for start in stride(from: 0, to: ids.count, by: 1000) {
            let r: MissingResponse = try await call("POST", "\(vaultPath(vaultId))/blobs/missing",
                                                    json: MissingRequest(ids: Array(ids[start..<min(start + 1000, ids.count)])))
            missing += r.missing
        }
        return missing
    }

    // MARK: Files and the change feed (protocol.md 9, 10)

    public func commit(_ vaultId: String, _ fileId: String, _ body: CommitRequest) async throws -> Revision {
        try await call("PUT", "\(vaultPath(vaultId))/files/\(enc(fileId))", json: body)
    }

    public func head(_ vaultId: String, _ fileId: String) async throws -> Revision {
        try await call("GET", "\(vaultPath(vaultId))/files/\(enc(fileId))")
    }

    public func revision(_ vaultId: String, _ fileId: String, rev: Int) async throws -> Revision {
        try await call("GET", "\(vaultPath(vaultId))/files/\(enc(fileId))/revs/\(rev)")
    }

    /// Newest first. Pass the last `rev` of a page as `before` for the next one.
    public func revisions(_ vaultId: String, _ fileId: String, before: Int? = nil, limit: Int = 50) async throws -> History {
        try await call("GET", "\(vaultPath(vaultId))/files/\(enc(fileId))/revs?limit=\(limit)" + (before.map { "&before=\($0)" } ?? ""))
    }

    public func changes(_ vaultId: String, since: Int, limit: Int = 500) async throws -> Changes {
        try await call("GET", "\(vaultPath(vaultId))/changes?since=\(since)&limit=\(limit)")
    }

    // MARK: Locks (protocol.md 11)

    /// Take or renew a soft lease lock. Throws `423 locked` with the holder in `details.lock`.
    @discardableResult
    public func acquireLock(_ vaultId: String, _ fileId: String, clientId: String, ttl: Int = 120) async throws -> Lock {
        try await call("POST", "\(vaultPath(vaultId))/locks/\(enc(fileId))", json: AcquireRequest(clientId: clientId, ttl: ttl))
    }

    public func releaseLock(_ vaultId: String, _ fileId: String, clientId: String) async throws {
        _ = try await raw("DELETE", "\(vaultPath(vaultId))/locks/\(enc(fileId))?clientId=\(enc(clientId))")
    }

    /// Also returns when the keyring version passes `keyringSince`, if given.
    public func wait(_ vaultId: String, since: Int, locksSince: Int, timeout: Int = 25, keyringSince: Int? = nil) async throws -> WaitResponse {
        let keyring = keyringSince.map { "&keyringSince=\($0)" } ?? ""
        return try await call("GET", "\(vaultPath(vaultId))/wait?since=\(since)&locksSince=\(locksSince)&timeout=\(timeout)\(keyring)")
    }

    // MARK: Plumbing

    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.withoutEscapingSlashes]
        return e
    }()

    /// An authenticated call. Logs in first if needed, and again once if the token expired.
    private func call<T: Decodable>(_ method: String, _ path: String) async throws -> T {
        try decode(try await raw(method, path))
    }

    private func call<T: Decodable, B: Encodable>(_ method: String, _ path: String, json: B) async throws -> T {
        try decode(try await raw(method, path, body: try Self.encoder.encode(json), contentType: "application/json"))
    }

    private func raw(_ method: String, _ path: String, body: Data? = nil, contentType: String? = nil) async throws -> HttpResponse {
        if token == nil { try await login() }
        do {
            return try await request(method, path, body: body, contentType: contentType, token: token)
        } catch let e as ApiError where e.status == 401 {
            try await login()
            return try await request(method, path, body: body, contentType: contentType, token: token)
        }
    }

    private func send<T: Decodable, B: Encodable>(_ method: String, _ path: String, json: B, token: String?) async throws -> T {
        try decode(try await request(method, path, body: try Self.encoder.encode(json), contentType: "application/json", token: token))
    }

    private func decode<T: Decodable>(_ r: HttpResponse) throws -> T {
        do { return try JSONDecoder().decode(T.self, from: r.body) } catch {
            throw ConnectionError("The server sent a response this client doesn't understand.")
        }
    }

    private func request(_ method: String, _ path: String, body: Data?, contentType: String?, token: String?) async throws -> HttpResponse {
        var headers: [String: String] = [:]
        if let token { headers["Authorization"] = "Bearer \(token)" }
        if let contentType { headers["Content-Type"] = contentType }
        let req = HttpRequest(method: method, url: URL(string: origin + path)!, headers: headers, body: body)
        let response: HttpResponse
        do {
            response = try await withTimeout(timeout) { [transport, timeout] in try await transport.send(req, timeout: timeout) }
        } catch {
            // Cancelled by the caller (a sync that is stopped), not a server that can't be reached.
            if Task.isCancelled { throw CancellationError() }
            throw ConnectionError("Can't reach the server.")
        }
        try checkServerVersion(response)
        if (200..<300).contains(response.status) { return response }
        throw errorFrom(response)
    }
}

/// Run `body`, or throw `CancellationError` after `seconds`. The abandoned request may still
/// finish; its result is ignored.
func withTimeout<T: Sendable>(_ seconds: TimeInterval, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(for: .seconds(seconds))
            throw CancellationError()
        }
        defer { group.cancelAll() }
        return try await group.next()!
    }
}

private func enc(_ segment: String) -> String {
    segment.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? segment
}

private func vaultPath(_ vaultId: String) -> String { "/api/v1/vaults/\(enc(vaultId))" }

func checkServerVersion(_ r: HttpResponse) throws {
    guard let version = r.headers[versionHeader] else {
        throw ConnectionError("The endpoint didn't answer like a Vault Syncryption server.")
    }
    // Servers before 0.1.1 don't send the protocol header.
    let proto = Int(r.headers[protocolHeader] ?? "0") ?? 0
    if proto != protocolVersion {
        let update = proto < protocolVersion ? "the server" : "this app"
        throw ApiError(status: 0, code: "version_mismatch",
                       message: "The server runs Vault Syncryption \(version), which this app doesn't support. Update \(update).")
    }
}

func errorFrom(_ r: HttpResponse) -> ApiError {
    let parsed = try? JSONDecoder().decode([String: JSONValue].self, from: r.body)
    let code = parsed?["error"]?.string ?? "http_\(r.status)"
    let message = parsed?["message"]?.string ?? "Request failed (\(r.status))."
    var details: [String: JSONValue] = [:]
    if case .object(let d)? = parsed?["details"] { details = d }
    return ApiError(status: r.status, code: code, message: message, details: details,
                    retryAfter: r.headers["retry-after"].flatMap { Int($0) })
}
