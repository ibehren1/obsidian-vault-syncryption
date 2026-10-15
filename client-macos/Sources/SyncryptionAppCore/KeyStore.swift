import CryptoKit
import Foundation
import Security
import SyncryptionAPI
import SyncryptionCrypto

/// The device keys, one per server, user and vault (docs/crypto.md 3.3), in the login Keychain
/// as `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` items: never synced to iCloud, and
/// readable without a prompt once the Mac was unlocked after boot, so background sync works.
public struct KeyStore: @unchecked Sendable {
    public let service: String
    /// A keychain to use instead of the default (login) one: the tests' own, so they never
    /// touch the user's keys and run as a user without a login keychain (a CI runner).
    private let keychain: SecKeychain?

    public init(service: String = "Vault Syncryption", keychain: SecKeychain? = nil) {
        self.service = service
        self.keychain = keychain
    }

    public struct Failure: Error, CustomStringConvertible {
        public let status: OSStatus
        public var description: String {
            (SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error \(status)"
        }
    }

    /// `syncryption-key-` + the first 8 bytes of SHA-256(origin + "\n" + username + "\n" +
    /// vault name), in hex: the plugin's id for the same key slot.
    public static func slot(origin: String, username: String, vaultName: String) -> String {
        let input = "\(origin)\n\(username)\n\(normalizeVaultName(vaultName))"
        return "syncryption-key-" + Array(SHA256.hash(data: Data(input.utf8)).prefix(8)).hex
    }

    private func query(_ slot: String) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: slot]
        if let keychain { q[kSecMatchSearchList as String] = [keychain] }
        return q
    }

    /// The OpenSSH private key in `slot`, or nil.
    public func load(_ slot: String) throws -> OpenSshKey? {
        var q = query(slot)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = out as? Data else { throw Failure(status: status) }
        return try OpenSSH.parsePrivateKey(String(decoding: data, as: UTF8.self))
    }

    /// Store (or replace) the key in `slot`.
    public func save(_ key: OpenSshKey, slot: String) throws {
        let pem = Data(OpenSSH.writePrivateKey(seed: key.seed, comment: key.comment).utf8)
        SecItemDelete(query(slot) as CFDictionary)
        var q = query(slot)
        q[kSecValueData as String] = pem
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        q[kSecAttrSynchronizable as String] = false
        q[kSecAttrLabel as String] = "Vault Syncryption encryption key"
        if let keychain {
            q[kSecMatchSearchList as String] = nil
            q[kSecUseKeychain as String] = keychain
        }
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw Failure(status: status) }
    }

    public func delete(_ slot: String) throws {
        let status = SecItemDelete(query(slot) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw Failure(status: status) }
    }
}
