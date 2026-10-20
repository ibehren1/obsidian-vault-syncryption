import Foundation
import SyncryptionCrypto
import TestBackend
import Testing

@testable import SyncryptionAPI

/// Answers every request with `handler`, recording what was sent.
final class FakeTransport: Transport, @unchecked Sendable {
    let handler: @Sendable (HttpRequest) async throws -> HttpResponse
    private(set) var requests: [HttpRequest] = []
    private let lock = NSLock()

    init(_ handler: @escaping @Sendable (HttpRequest) async throws -> HttpResponse) { self.handler = handler }

    func send(_ request: HttpRequest, timeout: TimeInterval) async throws -> HttpResponse {
        lock.withLock { requests.append(request) }
        return try await handler(request)
    }

    func bodies(endingWith suffix: String) -> [[String: Any]] {
        lock.withLock {
            requests.filter { $0.url.path.hasSuffix(suffix) }
                .map { try! JSONSerialization.jsonObject(with: $0.body!) as! [String: Any] }
        }
    }
}

let protocolHeaders = ["x-syncryption-version": "0.1.1", "x-syncryption-protocol": "1"]

func json(_ status: Int, _ body: Any, headers: [String: String] = protocolHeaders) -> HttpResponse {
    HttpResponse(status: status, headers: headers.merging(["content-type": "application/json"]) { a, _ in a },
                 body: try! JSONSerialization.data(withJSONObject: body))
}

func challenge(seed: Bytes, origin: String = "https://sync.example.com", vault: String = "Notes") -> String {
    ["syncryption-auth@v1", "origin: \(origin)", "username: alice", "vault: \(vault)",
     "key: \(OpenSSH.fingerprint(Primitives.ed25519PublicKey(seed: seed)))", "nonce: \(String(repeating: "A", count: 43))",
     "expires: 2026-10-02T12:00:00Z", ""].joined(separator: "\n")
}

func fake(seed: Bytes = Primitives.random(32), vaultName: String = "Notes", timeout: TimeInterval = 60,
          _ handler: @escaping @Sendable (HttpRequest) async throws -> HttpResponse) throws -> (ApiClient, FakeTransport)
{
    let t = FakeTransport(handler)
    let api = try ApiClient(endpoint: "https://sync.example.com", username: "alice", vaultName: vaultName, seed: seed,
                            deviceName: "Test", transport: t, timeout: timeout)
    return (api, t)
}

@Suite struct EndpointTests {
    @Test func keepsOnlyTheOrigin() throws {
        #expect(try normalizeEndpoint("https://sync.example.com/") == "https://sync.example.com")
        #expect(try normalizeEndpoint("https://Sync.Example.com:443") == "https://sync.example.com")
        #expect(try normalizeEndpoint("http://localhost:8080") == "http://localhost:8080")
    }

    @Test func rejectsPathsAndOtherSchemes() {
        for bad in ["https://example.com/sync", "ftp://example.com", "not a url", "https://example.com/?a=1", "https://u@example.com"] {
            #expect(throws: EndpointError.self, "\(bad)") { try normalizeEndpoint(bad) }
        }
    }

    @Test func acceptsHttpOnlyForThisMachine() throws {
        #expect(try normalizeEndpoint("http://127.0.0.1:8080") == "http://127.0.0.1:8080")
        #expect(try normalizeEndpoint("http://[::1]:8080") == "http://[::1]:8080")
        for bad in ["http://sync.example.com", "http://192.168.1.5:8080", "http://localhost.example.com"] {
            #expect(throws: EndpointError.self, "\(bad)") { try normalizeEndpoint(bad) }
        }
    }
}

@Suite struct ChallengeTests {
    let seed = Primitives.random(32)
    var key: Bytes { Primitives.ed25519PublicKey(seed: seed) }

    func message(_ field: String? = nil, _ value: String = "") -> String {
        var lines = challenge(seed: seed).split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let index = ["first": 0, "origin": 1, "username": 2, "vault": 3, "key": 4, "nonce": 5]
        if let field, let i = index[field] { lines[i] = i == 0 ? value : "\(field): \(value)" }
        return lines.joined(separator: "\n")
    }

    @Test func acceptsAChallengeForThisServerUserVaultAndKey() throws {
        try checkChallenge(message(), origin: "https://sync.example.com", username: "alice", vaultName: "Notes", publicKey: key)
        // The vault name as the server stores it: NFC, trimmed.
        try checkChallenge(message("vault", "Caf\u{e9}"), origin: "https://sync.example.com", username: "alice",
                           vaultName: " Cafe\u{301} ", publicKey: key)
    }

    @Test(arguments: [("first", "other-namespace"), ("origin", "https://evil.example.com"), ("username", "bob"),
                      ("vault", "Work"), ("key", "SHA256:AAAA"), ("nonce", "short")])
    func rejectsAWrongField(field: String, value: String) {
        #expect(throws: ApiError.self) {
            try checkChallenge(message(field, value), origin: "https://sync.example.com", username: "alice", vaultName: "Notes", publicKey: key)
        }
    }

    @Test func rejectsExtraOrMissingLines() {
        #expect(throws: ApiError.self) {
            try checkChallenge(message() + "sign: this too\n", origin: "https://sync.example.com", username: "alice", vaultName: "Notes", publicKey: key)
        }
        #expect(throws: ApiError.self) {
            try checkChallenge(message().replacingOccurrences(of: "vault: Notes\n", with: ""), origin: "https://sync.example.com",
                               username: "alice", vaultName: "Notes", publicKey: key)
        }
    }
}

@Suite struct ApiClientWithoutServerTests {
    @Test func doesntSignAChallengeForAnotherServer() async throws {
        let seed = Primitives.random(32)
        let (api, t) = try fake(seed: seed) { r in
            r.url.path.hasSuffix("/challenge")
                ? json(200, ["challengeId": "c", "message": challenge(seed: seed, origin: "https://evil.example.com"), "expiresAt": "x"])
                : json(500, [:])
        }
        await #expect { try await api.login() } throws: { ($0 as? ApiError)?.code == "bad_challenge" }
        #expect(t.bodies(endingWith: "/verify").isEmpty)
    }

    @Test func namesTheVaultAndSendsTheSharedSecretOnlyWhenGiven() async throws {
        let seed = Primitives.random(32)
        let (api, t) = try fake(seed: seed, vaultName: " Notes ") { r in
            if r.url.path.hasSuffix("/challenge") {
                return json(200, ["challengeId": "c", "message": challenge(seed: seed), "expiresAt": "x"])
            }
            return json(200, ["token": "t", "deviceId": "d", "vaultId": NSNull(), "status": "active", "created": true, "expiresAt": "x"])
        }
        try await api.login()
        try await api.login(sharedSecret: "secret")
        let challenges = t.bodies(endingWith: "/challenge")
        let verifies = t.bodies(endingWith: "/verify")
        #expect(challenges[0]["username"] as? String == "alice")
        #expect(challenges[0]["vaultName"] as? String == "Notes")
        #expect(verifies[0]["sharedSecret"] == nil)
        #expect(verifies[1]["sharedSecret"] as? String == "secret")
        #expect(verifies[1]["deviceName"] as? String == "Test")
        #expect(verifies[1]["vaultName"] == nil)
        // The signature covers the challenge in the auth namespace.
        let signature = verifies[0]["signature"] as! String
        #expect(try SshSig.verify(signature, namespace: SshSig.namespaceAuth, message: Bytes(utf8: challenge(seed: seed)))
            == Primitives.ed25519PublicKey(seed: seed))
    }

    @Test func checksTheProtocolVersionNotTheServerVersion() async throws {
        func login(_ headers: [String: String]) async throws -> any Error {
            let (api, _) = try fake { _ in json(200, [:], headers: headers) }
            do { try await api.login(); return CancellationError() } catch { return error }
        }
        #expect((try await login(["x-syncryption-version": "0.1.0"]) as? ApiError)?.message.contains("Update the server") == true)
        #expect((try await login(["x-syncryption-version": "0.2.0", "x-syncryption-protocol": "2"]) as? ApiError)?.message
            .contains("Update this app") == true)
        #expect((try await login(["x-syncryption-version": "7.3.1", "x-syncryption-protocol": "1"]) as? ApiError)?.code != "version_mismatch")
        #expect(try await login([:]) is ConnectionError)
    }

    @Test func turnsErrorBodiesAndRetryAfterIntoApiError() async throws {
        let (api, _) = try fake { _ in
            var r = json(429, ["error": "rate_limited", "message": "Slow down.", "details": ["a": 1]])
            r.headers["retry-after"] = "12"
            return r
        }
        await #expect { try await api.login() } throws: { e in
            guard let e = e as? ApiError else { return false }
            return e.status == 429 && e.code == "rate_limited" && e.message == "Slow down." && e.details == ["a": .number(1)]
                && e.retryAfter == 12
        }
    }

    @Test func maintenanceIsAnApiError() async throws {
        let (api, _) = try fake { _ in
            var r = json(503, ["error": "maintenance", "message": "The server is in maintenance, so sync is paused.",
                               "details": ["adminContact": "ops@example.com", "note": "Moving to a new disk."]])
            r.headers["retry-after"] = "60"
            return r
        }
        await #expect { try await api.login() } throws: { e in
            guard let e = e as? ApiError else { return false }
            return e.isMaintenance && e.retryAfter == 60
                && e.maintenanceText == "The server is in maintenance, so sync is paused. It resumes by itself. Moving to a new disk. For help, contact the server admin: ops@example.com."
        }
    }

    @Test func reportsAnUnreachableServer() async throws {
        let (api, _) = try fake { _ in throw URLError(.notConnectedToInternet) }
        await #expect(throws: ConnectionError.self) { try await api.login() }
    }

    @Test func givesUpOnARequestThatNeverAnswers() async throws {
        let (api, _) = try fake(timeout: 0.05) { _ in
            try await Task.sleep(for: .seconds(60))
            return json(200, [:])
        }
        await #expect(throws: ConnectionError.self) { try await api.login() }
    }

    @Test func aCancelledRequestIsCancelledNotUnreachable() async throws {
        let (api, _) = try fake(timeout: 30) { _ in
            try await Task.sleep(for: .seconds(60))
            return json(200, [:])
        }
        let t = Task { try await api.login() }
        try await Task.sleep(for: .milliseconds(50))
        t.cancel()
        await #expect(throws: CancellationError.self) { try await t.value }
    }

    @Test func errorTexts() {
        let base = "The server is in maintenance, so sync is paused. It resumes by itself."
        #expect(ApiError(status: 503, code: "maintenance", message: "x", details: ["note": "  ", "adminContact": .null]).maintenanceText
            == "\(base) For help or info, contact your server admin.")
        #expect(ApiError(status: 503, code: "maintenance", message: "x", details: ["adminContact": "Ann in #it."]).maintenanceText
            == "\(base) For help, contact the server admin: Ann in #it.")
        #expect(ApiError(status: 403, code: "user_disabled", message: "This user is disabled.").disabledText == "This user is disabled.")
        #expect(ApiError(status: 403, code: "vault_disabled", message: "This vault is disabled", details: ["adminContact": "ops@example.com"])
            .disabledText == "This vault is disabled. Contact the server admin: ops@example.com.")
        #expect(ApiError(status: 403, code: "device_revoked", message: "x").isRevoked)
        #expect(!ApiError(status: 403, code: "device_pending", message: "x").isDisabled)
    }
}

extension JSONValue: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral {
    public init(stringLiteral s: String) { self = .string(s) }
    public init(integerLiteral n: Int) { self = .number(Double(n)) }
}

func client(_ username: String, _ vaultName: String, _ seed: Bytes, deviceName: String = "Test device") throws -> ApiClient {
    try ApiClient(endpoint: TestBackend.url()!, username: username, vaultName: vaultName, seed: seed, deviceName: deviceName,
                  transport: TestBackend.transport())
}

@Suite(.enabled(if: TestBackend.available, "needs uv to start the backend"))
struct ApiClientBackendTests {
    @Test func needsTheSharedSecretForANewVaultThenLogsInWithoutIt() async throws {
        let username = TestBackend.uniqueName("join")
        let vaultName = TestBackend.uniqueName("Vault ")
        let seed = Primitives.random(32)
        let api = try client(username, vaultName, seed)
        await #expect { try await api.login() } throws: { ($0 as? ApiError)?.code == "join_required" }
        await #expect(throws: ApiError.self) { try await api.login(sharedSecret: "wrong") }
        let joined = try await api.login(sharedSecret: TestBackend.sharedSecret)
        #expect(joined.status == "active")
        #expect(joined.vaultId == nil)
        let me = try await api.selfDevice()
        #expect(me.id == joined.deviceId && me.username == username && me.vaultName == vaultName)
        #expect(try await client(username, vaultName, seed).login().deviceId == joined.deviceId)
    }

    @Test func refusesAKnownKeyForAnotherVaultOrUser() async throws {
        let username = TestBackend.uniqueName("onekey")
        let vaultName = TestBackend.uniqueName("Vault ")
        let seed = Primitives.random(32)
        try await client(username, vaultName, seed).login(sharedSecret: TestBackend.sharedSecret)
        await #expect(throws: ApiError.self) {
            try await client(username, TestBackend.uniqueName("Other "), seed).login(sharedSecret: TestBackend.sharedSecret)
        }
        await #expect(throws: ApiError.self) {
            try await client(TestBackend.uniqueName("other"), vaultName, seed).login(sharedSecret: TestBackend.sharedSecret)
        }
    }

    @Test func tellsASecondNewKeyThatTheVaultIsBeingCreated() async throws {
        let username = TestBackend.uniqueName("creating")
        let vaultName = TestBackend.uniqueName("Vault ")
        try await client(username, vaultName, Primitives.random(32)).login(sharedSecret: TestBackend.sharedSecret)
        await #expect { try await client(username, vaultName, Primitives.random(32)).login(sharedSecret: TestBackend.sharedSecret) }
            throws: { ($0 as? ApiError)?.code == "vault_being_created" }
    }

    @Test func logsInAgainWhenTheTokenIsRejected() async throws {
        let api = try client(TestBackend.uniqueName("relogin"), TestBackend.uniqueName("Vault "), Primitives.random(32))
        try await api.login(sharedSecret: TestBackend.sharedSecret)
        await api.dropToken(replacingWith: "not-a-token")
        #expect(try await api.selfDevice().id == api.deviceId)
    }

    @Test func createsAVaultPairsADeviceAndSyncsAFile() async throws {
        let username = TestBackend.uniqueName("flow")
        let vaultName = TestBackend.uniqueName("Vault ")
        let aSeed = Primitives.random(32)
        let a = try client(username, vaultName, aSeed, deviceName: "Mac A")
        let joined = try await a.login(sharedSecret: TestBackend.sharedSecret)
        await #expect { try await a.openVault(vaultName) } throws: { ($0 as? ApiError)?.status == 404 }

        // Create the vault with the genesis keyring.
        let vaultId = UUID().uuidString.lowercased()
        let me = KeyringDevice(id: joined.deviceId, name: "Mac A", publicKey: OpenSSH.publicKeyText(a.publicKey))
        let k1 = Keyrings.create(vaultId: vaultId, name: vaultName, device: me)
        let b1 = try Keyrings.seal(k1, seed: aSeed)
        let vault = try await a.createVault(id: vaultId, name: vaultName, keyring: upload(b1, signer: joined.deviceId))
        #expect(vault.id == vaultId && vault.keyringVersion == 1)
        let trusted = try Keyrings.open(try blob(try await a.keyring(vaultId)), KeyringContext(seed: aSeed, vaultId: vaultId, name: vaultName))

        // A second key joins as pending; A approves it after adding it to the keyring.
        let bSeed = Primitives.random(32)
        let b = try client(username, vaultName, bSeed, deviceName: "Mac B")
        let bJoined = try await b.login()
        #expect(bJoined.status == "pending")
        let pending = try await a.devices(vaultId).first { $0.id == bJoined.deviceId }
        #expect(pending?.pairingCode == OpenSSH.pairingCode(b.publicKey))
        let k2 = try Keyrings.addDevice(trusted.keyring, KeyringDevice(id: bJoined.deviceId, name: "Mac B",
                                                                      publicKey: OpenSSH.publicKeyText(b.publicKey)), updatedBy: joined.deviceId)
        _ = try await a.putKeyring(vaultId, upload(try Keyrings.seal(k2, seed: aSeed), signer: joined.deviceId))
        #expect(try await a.approveDevice(vaultId, bJoined.deviceId).status == "active")
        try await b.login()
        let bView = try Keyrings.open(try blob(try await b.keyring(vaultId)), KeyringContext(seed: bSeed, vaultId: vaultId, name: vaultName))
        #expect(bView.keyring.devices.count == 2)

        // A commits a file; B reads it from the change feed.
        let path = "Notes/Hello.md"
        let content = Bytes(utf8: "# Hello\n")
        let fileId = try KDF.fileId(indexKey: k1.indexKeyBytes, path: path)
        let fileKey = KDF.fileKey(vdk: try k1.epochKey(), fileId: fileId)
        let chunks = Objects.sealChunks(fileKey: fileKey, epoch: 1, fileId: fileId, content)
        #expect(try await a.missingBlobs(vaultId, chunks.map(\.id)) == chunks.map(\.id))
        for c in chunks { try await a.putBlob(vaultId, c.id, Data(c.object)) }
        let meta = FileMeta(path: path, deleted: false, size: content.count, mtime: 1_790_000_000_000, ctime: 1_790_000_000_000,
                            sha256: Primitives.sha256(content).hex, chunks: chunks.map { ChunkRef(id: $0.id, size: $0.size) },
                            device: joined.deviceId)
        let metaObject = try Objects.sealMeta(fileKey: fileKey, epoch: 1, fileId: fileId, meta)
        let rev = try await a.commit(vaultId, KDF.fileIdString(fileId),
                                     CommitRequest(blobs: chunks.map(\.id), deleted: false, meta: metaObject.b64u, parentRev: nil))
        await #expect {
            try await a.commit(vaultId, KDF.fileIdString(fileId), CommitRequest(blobs: chunks.map(\.id), deleted: false,
                                                                                  meta: metaObject.b64u, parentRev: nil))
        } throws: { ($0 as? ApiError)?.code == "stale_parent" }

        let feed = try await b.changes(vaultId, since: 0)
        let got = try #require(feed.changes.first { $0.fileId == KDF.fileIdString(fileId) })
        #expect(got.rev == rev.rev)
        let opened = try Objects.openMeta(fileKey: fileKey, indexKey: bView.keyring.indexKeyBytes, fileId: fileId, Bytes(b64u: got.meta)!)
        var objects: [Bytes] = []
        for id in got.blobs { objects.append(Bytes(try await b.getBlob(vaultId, id))) }
        #expect(try Objects.openChunks(fileKey: fileKey, fileId: fileId, meta: opened, objects) == content)

        let waited = try await b.wait(vaultId, since: feed.cursor, locksSince: 0, timeout: 1)
        #expect(waited.seq == feed.cursor)
    }

    func upload(_ b: KeyringBlob, signer: String) -> KeyringUpload {
        KeyringUpload(keyring: b.keyring.b64u, signature: b.signature, signer: signer, version: b.version)
    }

    func blob(_ k: SyncryptionAPI.Keyring) throws -> KeyringBlob {
        KeyringBlob(version: k.version, keyring: try #require(Bytes(b64u: k.keyring)), signature: k.signature)
    }
}
