import Foundation
import Testing

@testable import SyncryptionCrypto

@Suite struct OpenSSHTests {
    @Test func parsesTheUnencryptedKeyAndRefusesEncryptedOnes() throws {
        for v in try vectors("openssh-keys.json").list("valid") {
            if v.str("passphrase").isEmpty {
                let key = try OpenSSH.parsePrivateKey(v.str("pem"))
                #expect(key.seed == v.hex("seed"))
                #expect(key.publicKey == v.hex("publicKey"))
                #expect(key.comment == v.str("comment"))
                #expect(OpenSSH.publicKeyText(key.publicKey, comment: key.comment) == v.str("publicKeyText"))
                #expect(OpenSSH.fingerprint(key.publicKey) == v.str("fingerprint"))
                #expect(try OpenSSH.parsePublicKeyText(v.str("publicKeyText")) == key.publicKey)
                let written = OpenSSH.writePrivateKey(seed: key.seed, comment: key.comment,
                                                      checkint: UInt32(v["checkint"] as! Int))
                #expect(written == v.str("pem"))
            } else {
                #expect(throws: SshKeyError.passphraseRequired) { try OpenSSH.parsePrivateKey(v.str("pem")) }
            }
        }
    }

    @Test func rejectsInvalidKeys() throws {
        for v in try vectors("openssh-keys.json").list("invalid") {
            // Passphrase-protected keys are refused before any passphrase check.
            let expected = v.str("error") == "wrong-passphrase" ? "passphrase-required" : v.str("error")
            do {
                _ = try OpenSSH.parsePrivateKey(v.str("pem"))
                Issue.record("\(v.str("name")) parsed")
            } catch {
                #expect(error.code == expected, "\(v.str("name"))")
            }
        }
    }

    @Test func generatedKeysRoundTrip() throws {
        let key = OpenSSH.generate(comment: "syncryption me@Mac")
        let parsed = try OpenSSH.parsePrivateKey(OpenSSH.writePrivateKey(seed: key.seed, comment: key.comment))
        #expect(parsed.seed == key.seed)
        #expect(parsed.publicKey == key.publicKey)
        #expect(parsed.comment == key.comment)
    }

    @Test func pairingCodes() throws {
        for v in try vectors("kdf.json").list("pairingCodes") {
            #expect(OpenSSH.pairingCode(v.hex("publicKey")) == v.str("code"))
            #expect(OpenSSH.publicKeyText(v.hex("publicKey")) == v.str("publicKeyText"))
        }
    }

    @Test func ed25519ToX25519() throws {
        for v in try vectors("ed25519-to-x25519.json").list("cases") {
            #expect(Primitives.ed25519PublicKey(seed: v.hex("seed")) == v.hex("edPublicKey"))
            #expect(Primitives.ed25519PublicToX25519(v.hex("edPublicKey")) == v.hex("xPublicKey"))
            #expect(Primitives.ed25519SeedToX25519(v.hex("seed")) == v.hex("xSecretKey"))
        }
    }
}

@Suite struct SshSigTests {
    @Test func signsByteIdenticallyAndVerifies() throws {
        let v = try vectors("sshsig.json")
        let seed = v.hex("seed")
        for c in v.list("valid") {
            let message = Bytes(hex: c.str("message"))!
            #expect(SshSig.sign(seed: seed, namespace: c.str("namespace"), message: message) == c.str("signature"))
            #expect(try SshSig.verify(c.str("signature"), namespace: c.str("namespace"), message: message) == v.hex("publicKey"))
        }
    }

    @Test func rejectsInvalidSignatures() throws {
        for c in try vectors("sshsig.json").list("invalid") {
            #expect(throws: SshSig.Failure.self, "\(c.str("name"))") {
                try SshSig.verify(c.str("signature"), namespace: c.str("namespace"), message: Bytes(hex: c.str("message"))!)
            }
        }
    }
}

@Suite struct KDFTests {
    @Test func derivations() throws {
        let v = try vectors("kdf.json")
        let indexKey = KDF.indexKey(vdk1: v.hex("vdk1"))
        #expect(indexKey == v.hex("indexKey"))
        for f in v.list("files") {
            #expect(try KDF.normPath(f.str("path")).unicodeScalars.elementsEqual(f.str("normPath").unicodeScalars))
            let id = try KDF.fileId(indexKey: indexKey, path: f.str("path"))
            #expect(id == f.hex("fileId"), "\(f.str("name"))")
            #expect(KDF.fileIdString(id) == f.str("fileIdString"))
            #expect(KDF.fileKey(vdk: v.hex("vdk1"), fileId: id) == f.hex("fileKeyEpoch1"))
            #expect(KDF.fileKey(vdk: v.hex("vdk2"), fileId: id) == f.hex("fileKeyEpoch2"))
        }
        for p in v["invalidPaths"] as! [String] {
            #expect(!KDF.isVaultPath(p), "\(p.debugDescription)")
        }
    }

    @Test func base64Strictness() {
        #expect(Bytes(b64u: "AQ") == [1])
        #expect(Bytes(b64u: "AQ==") == nil)
        #expect(Bytes(b64u: "AR") == nil)  // non-canonical
        #expect(Bytes(base64NoPad: "A Q") == nil)
    }
}

extension Error {
    var code: String { (self as? SshKeyError)?.code ?? "\(self)" }
}
