import Foundation
import Testing

@testable import SyncryptionCrypto

@Suite struct AgeTests {
    let v: [String: Any]
    let alice: Age.Identity

    init() throws {
        v = try vectors("age-ssh-ed25519.json")
        alice = .sshEd25519(seed: v.dict("alice").hex("seed"))
    }

    @Test func deterministicWraps() throws {
        for w in v.list("wrap") {
            let s = try Age.wrapSshEd25519(publicKey: w.hex("publicKey"), fileKey: w.hex("fileKey"), ephemeral: w.hex("ephemeral"))
            #expect(s.args == w["args"] as! [String])
            #expect(s.body == w.hex("body"))
            #expect(try Age.unwrap(s, with: .sshEd25519(seed: w.hex("seed"))) == w.hex("fileKey"))
        }
    }

    @Test func stanzas() throws {
        for c in v.list("stanzas") {
            let s = Age.Stanza(args: c["args"] as! [String], body: c.hex("body"))
            if c["error"] as? Bool == true {
                #expect(throws: Age.Failure.invalidStanza, "\(c.str("name"))") { try Age.unwrap(s, with: alice) }
            } else {
                let expected = (c["result"] as? String).flatMap { Bytes(hex: $0) }
                #expect(try Age.unwrap(s, with: alice) == expected, "\(c.str("name"))")
            }
        }
    }

    @Test func decryptsRageAndGoAgeFiles() throws {
        for f in v.list("files") {
            let file = f.hex("file")
            if let plain = f["plaintext"] as? String {
                #expect(try Age.decrypt(file, with: [alice]) == Bytes(hex: plain)!, "\(f.str("name"))")
            } else {
                #expect(throws: Age.Failure.noIdentityMatched, "\(f.str("name"))") { try Age.decrypt(file, with: [alice]) }
            }
        }
    }

    @Test func roundTripsToSeveralRecipients() throws {
        let other = OpenSSH.generate()
        let xSecret = Primitives.random(32)
        let message = Bytes(utf8: "vault key")
        let file = try Age.encrypt(message, to: [
            .sshEd25519(other.publicKey), .sshEd25519(v.dict("alice").hex("publicKey")), .x25519(Primitives.x25519Base(xSecret)),
        ])
        #expect(try Age.decrypt(file, with: [alice]) == message)
        #expect(try Age.decrypt(file, with: [.sshEd25519(seed: other.seed)]) == message)
        #expect(try Age.decrypt(file, with: [.x25519(secret: xSecret)]) == message)
        #expect(throws: Age.Failure.noIdentityMatched) { try Age.decrypt(file, with: [.sshEd25519(seed: OpenSSH.generate().seed)]) }
    }

    @Test(arguments: [0, 1, 65535, 65536, 65537, 200_000])
    func payloadSizes(size: Int) throws {
        let message = Primitives.random(size)
        let file = try Age.encrypt(message, to: [.sshEd25519(v.dict("alice").hex("publicKey"))])
        #expect(try Age.decrypt(file, with: [alice]) == message)
        var tampered = file
        tampered[tampered.count - 1] ^= 1
        #expect(throws: Age.Failure.malformed) { try Age.decrypt(tampered, with: [alice]) }
        #expect(throws: Age.Failure.malformed) { try Age.decrypt(Array(file.dropLast(17)), with: [alice]) }
    }

    @Test func bech32RoundTrip() throws {
        let secret = Primitives.random(32)
        let text = Age.identityText(secret: secret)
        #expect(text.hasPrefix("AGE-SECRET-KEY-1"))
        guard case .x25519(let back)? = Age.Identity.x25519(text: text.lowercased()) else { Issue.record(); return }
        #expect(back == secret)
        let r = Age.recipientText(publicKey: Primitives.x25519Base(secret))
        guard case .x25519(let pk)? = Age.Recipient.x25519(text: r) else { Issue.record(); return }
        #expect(pk == Primitives.x25519Base(secret))
        #expect(Age.Identity.x25519(text: "AGE-SECRET-KEY-1QQQQ") == nil)
    }
}
