import Foundation
import Testing

@testable import SyncryptionCrypto

private func code(_ body: () throws -> Any) -> String {
    do {
        _ = try body()
        return "ok"
    } catch let e as KeyringError {
        return e.code.rawValue
    } catch {
        return "\(error)"
    }
}

@Suite struct KeyringVectorTests {
    let v: [String: Any]

    init() throws { v = try vectors("keyring.json") }

    func blob(_ name: String) -> KeyringBlob {
        let b = v.dict("blobs").dict(name)
        return KeyringBlob(version: b["version"] as! Int, keyring: b.hex("keyring"), signature: b.str("signature"))
    }

    func plaintext(_ name: String) throws -> Keyring {
        try JSONDecoder().decode(Keyring.self, from: JSONSerialization.data(withJSONObject: v.dict("blobs").dict(name)["plaintext"]!))
    }

    func ctx(_ who: String) -> KeyringContext {
        KeyringContext(seed: v.dict("devices").dict(who).hex("seed"), vaultId: v.dict("vault").str("id"), name: v.dict("vault").str("name"))
    }

    @Test func cases() throws {
        for c in v.list("cases") {
            let ctx = ctx(c.str("as"))
            var trusted: TrustedKeyring?
            for name in c["trustedChain"] as! [String] { trusted = try Keyrings.open(blob(name), ctx, trusted: trusted) }
            let got = code { try Keyrings.open(blob(c.str("open")), ctx, trusted: trusted) }
            #expect(got == c.str("expect"), "\(c.str("name"))")
            if c.str("expect") == "ok" {
                #expect(try Keyrings.open(blob(c.str("open")), ctx, trusted: trusted).keyring == plaintext(c.str("open")), "\(c.str("name"))")
            }
        }
    }

    @Test func walksTheChain() throws {
        let ctx = ctx("bob")
        let trusted = try Keyrings.open(blob("v2"), ctx)
        #expect(try Keyrings.openChain([blob("v4"), blob("v3")], ctx, trusted: trusted).pin.version == 4)
    }

    @Test func recoveryIdentity() throws {
        let r = v.dict("recovery")
        guard let id = Age.Identity.x25519(text: r.str("identity")) else { Issue.record(); return }
        let plain = try Age.decrypt(blob("v2").keyring, with: [id])
        #expect(try JSONDecoder().decode(Keyring.self, from: Data(plain)).version == 2)
        #expect(try Keyrings.recoverySigningSeed(r.str("identity")) == r.hex("signerSeed"))
        #expect(try Keyrings.recoverySigner(r.str("identity").lowercased()) == r.str("signerPublicKeyText"))
        #expect(throws: (any Error).self) { try Keyrings.recoverySigner("AGE-SECRET-KEY-1QQQQ") }
        #expect(throws: (any Error).self) { try Keyrings.recoverySigner(r.str("recipient")) }
        let recipientPk = Primitives.x25519Base(r.hex("secret"))
        #expect(Age.recipientText(publicKey: recipientPk) == r.str("recipient"))
        #expect(Age.identityText(secret: r.hex("secret")) == r.str("identity"))
    }

    @Test func opensTheCurrentKeyringWithTheRecoveryIdentity() throws {
        let r = v.dict("recovery")
        let vault = v.dict("vault")
        let open = { (b: String, name: String) in
            code { try Keyrings.openWithRecovery(self.blob(b), vaultId: vault.str("id"), name: name, identity: r.str("identity")) }
        }
        #expect(try Keyrings.openWithRecovery(blob("v4"), vaultId: vault.str("id"), name: vault.str("name"),
                                              identity: r.str("identity")).keyring == plaintext("v4"))
        #expect(open("v1", vault.str("name")) == "not-a-recipient")
        #expect(open("v3-recovery-replaced", vault.str("name")) == "not-a-recipient")
        #expect(open("v4", "Work") == "wrong-vault")
    }
}

@Suite struct KeyringRoundTripTests {
    struct Dev {
        let seed: Bytes
        let device: KeyringDevice
    }

    let a: Dev, b: Dev, c: Dev

    init() {
        let devs = (0..<3).map { i -> Dev in
            let seed = Primitives.random(32)
            return Dev(seed: seed, device: KeyringDevice(id: "d_\(i)", name: "device \(i)",
                                                         publicKey: OpenSSH.publicKeyText(Primitives.ed25519PublicKey(seed: seed))))
        }
        (a, b, c) = (devs[0], devs[1], devs[2])
    }

    func ctx(_ seed: Bytes) -> KeyringContext { KeyringContext(seed: seed, vaultId: "vault-1", name: "Work") }

    @Test func createsPairsRotatesAndRecovers() throws {
        let recovery = Keyrings.generateRecoveryKey()
        let k1 = Keyrings.create(vaultId: "vault-1", name: "Work", device: a.device, recovery: recovery)
        let t1 = try Keyrings.open(try Keyrings.seal(k1, seed: a.seed), ctx(a.seed))

        let k2 = try Keyrings.addDevice(t1.keyring, b.device, updatedBy: a.device.id)
        let b2 = try Keyrings.seal(k2, seed: a.seed)
        let t2 = try Keyrings.open(b2, ctx(a.seed), trusted: t1)
        let bobView = try Keyrings.open(b2, ctx(b.seed))
        #expect(bobView.keyring == t2.keyring)

        let k3 = try Keyrings.addDevice(t2.keyring, c.device, updatedBy: b.device.id)
        let b3 = try Keyrings.seal(k3, seed: b.seed)
        let k4 = try Keyrings.removeDevicesAndRotate(k3, [a.device.id], updatedBy: c.device.id)
        let b4 = try Keyrings.seal(k4, seed: c.seed)
        let t4 = try Keyrings.openChain([b3, b4], ctx(b.seed), trusted: bobView)
        #expect(t4.keyring.currentEpoch == 2)
        #expect(try t4.keyring.epochKey(1) == t1.keyring.epochKey(1))
        #expect(try t4.keyring.epochKey() != t1.keyring.epochKey())
        #expect(code { try Keyrings.open(b4, ctx(a.seed), trusted: t2) } == "chain-gap")
        #expect(code { try Keyrings.open(b4, ctx(a.seed)) } == "not-a-recipient")

        let id = Age.Identity.x25519(text: recovery.identity)!
        #expect(try JSONDecoder().decode(Keyring.self, from: Data(Age.decrypt(b3.keyring, with: [id]))).version == 3)
        // a set the recovery key, so removing a removes it too.
        #expect(throws: Age.Failure.noIdentityMatched) { try Age.decrypt(b4.keyring, with: [id]) }
    }

    @Test func addsADeviceWithTheRecoveryKey() throws {
        let recovery = Keyrings.generateRecoveryKey()
        var k1 = Keyrings.setRecovery(Keyrings.create(vaultId: "vault-1", name: "Work", device: a.device), recovery, updatedBy: "d_0")
        k1.version = 1
        let k1Blob = try Keyrings.seal(k1, seed: a.seed)
        let t1 = try Keyrings.open(k1Blob, ctx(a.seed))
        #expect(t1.keyring.recoverySetBy == "d_0")

        let opened = try Keyrings.openWithRecovery(k1Blob, vaultId: "vault-1", name: "Work", identity: recovery.identity)
        let k2 = try Keyrings.addDevice(opened.keyring, c.device, updatedBy: c.device.id)
        let b2 = try Keyrings.seal(k2, seed: try Keyrings.recoverySigningSeed(recovery.identity))
        #expect(try Keyrings.open(b2, ctx(c.seed)).keyring.devices.map(\.id) == ["d_0", "d_2"])
        #expect(try Keyrings.open(b2, ctx(a.seed), trusted: t1).pin.version == 2)

        // The recovery key can't replace itself.
        let other = Keyrings.generateRecoveryKey()
        let k3 = Keyrings.setRecovery(k2, other, updatedBy: c.device.id)
        #expect(k3.currentEpoch == 2)
        var forged = k3
        forged.recoverySigner = recovery.signer
        let b3 = try Keyrings.seal(forged, seed: try Keyrings.recoverySigningSeed(recovery.identity))
        let t2 = try Keyrings.open(b2, ctx(c.seed))
        #expect(code { try Keyrings.open(b3, ctx(c.seed), trusted: t2) } == "inconsistent")
        // A device can, in its own name.
        #expect(try Keyrings.open(try Keyrings.seal(k3, seed: c.seed), ctx(c.seed), trusted: t2).keyring.recoverySetBy == "d_2")
    }

    @Test func revokingTheDeviceThatSetTheRecoveryKeyRemovesIt() throws {
        let recovery = Keyrings.generateRecoveryKey()
        let k1 = Keyrings.create(vaultId: "vault-1", name: "Work", device: a.device, recovery: recovery)
        let k2 = try Keyrings.addDevice(k1, b.device, updatedBy: a.device.id)
        let k3 = try Keyrings.removeDevicesAndRotate(k2, [a.device.id], updatedBy: b.device.id)
        #expect(k3.recovery == nil && k3.recoverySigner == nil && k3.recoverySetBy == nil)
        let t2 = try Keyrings.open(try Keyrings.seal(k2, seed: a.seed), ctx(b.seed))
        #expect(try Keyrings.open(try Keyrings.seal(k3, seed: b.seed), ctx(b.seed), trusted: t2).keyring.recovery == nil)
        let k4 = try Keyrings.addDevice(k3, c.device, updatedBy: b.device.id)
        let k5 = Keyrings.setRecovery(k4, recovery, updatedBy: b.device.id)
        #expect(try Keyrings.removeDevicesAndRotate(k5, [c.device.id], updatedBy: b.device.id).recovery == recovery.recipient)
    }

    @Test func addsARemoteOnlyDeviceAndChangesItsPolicy() throws {
        let k1 = Keyrings.create(vaultId: "vault-1", name: "Work", device: a.device)
        let t1 = try Keyrings.open(try Keyrings.seal(k1, seed: a.seed), ctx(a.seed))
        var remote = b.device
        remote.policy = Keyring.remoteOnly
        let k2 = try Keyrings.addDevice(t1.keyring, remote, updatedBy: a.device.id)
        let t2 = try Keyrings.open(try Keyrings.seal(k2, seed: a.seed), ctx(b.seed))
        #expect(t2.keyring.devices[1].policy == Keyring.remoteOnly)
        let byRemote = try Keyrings.seal(try Keyrings.addDevice(k2, c.device, updatedBy: b.device.id), seed: b.seed)
        #expect(code { try Keyrings.open(byRemote, ctx(a.seed), trusted: t2) } == "untrusted-signer")
        let k3 = try Keyrings.setPolicy(k2, deviceId: b.device.id, policy: nil, updatedBy: a.device.id)
        #expect(try Keyrings.open(try Keyrings.seal(k3, seed: a.seed), ctx(b.seed), trusted: t2).keyring.devices[1].policy == nil)
    }

    @Test func refusesToSignWithADeviceOutsideTheKeyring() {
        let k1 = Keyrings.create(vaultId: "vault-1", name: "Work", device: a.device)
        #expect(throws: (any Error).self) { try Keyrings.seal(k1, seed: b.seed) }
    }
}
