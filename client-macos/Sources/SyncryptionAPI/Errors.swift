import Foundation

/// A non-2xx response (docs/protocol.md 1). `code` is the server's stable `error` code.
public struct ApiError: Error, Equatable, CustomStringConvertible {
    public let status: Int
    public let code: String
    public let message: String
    public let details: [String: JSONValue]
    /// Seconds, from `Retry-After` (on `429` and the maintenance `503`).
    public let retryAfter: Int?

    public init(status: Int, code: String, message: String, details: [String: JSONValue] = [:], retryAfter: Int? = nil) {
        self.status = status
        self.code = code
        self.message = message
        self.details = details
        self.retryAfter = retryAfter
    }

    public var description: String { message }

    /// The server administrator disabled this user or vault (protocol.md 14): retrying won't help.
    public var isDisabled: Bool { code == "user_disabled" || code == "vault_disabled" }

    /// This device's key was removed from the vault (protocol.md 6): it can never log in again.
    public var isRevoked: Bool { code == "device_revoked" }

    /// The administrator put the server in maintenance: a pause, not an error. Keep the
    /// session and retry.
    public var isMaintenance: Bool { code == "maintenance" }

    /// The admin's free-text contact, if the server sent one (maintenance and disabled errors).
    public var adminContact: String? { trimmed(details["adminContact"]) }

    /// The user-facing text for maintenance, from `details` (`note`, `adminContact`).
    public var maintenanceText: String {
        var parts = ["The server is in maintenance, so sync is paused. It resumes by itself."]
        if let note = trimmed(details["note"]) { parts.append(sentence(note)) }
        if let contact = adminContact {
            parts.append("For help, contact the server admin: \(sentence(contact))")
        } else {
            parts.append("For help or info, contact your server admin.")
        }
        return parts.joined(separator: " ")
    }

    /// A disabled user's or vault's message, with the admin's contact when the server sent one.
    public var disabledText: String {
        if let contact = adminContact { return "\(sentence(message)) Contact the server admin: \(sentence(contact))" }
        return message
    }

    public static let revokedText =
        "This device's encryption key was removed from the vault. Remove the folder and add it again to pair this Mac with a new key."
}

private func trimmed(_ v: JSONValue?) -> String? {
    guard let s = v?.string?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty else { return nil }
    return s
}

/// End with a full stop unless the text already ends with punctuation.
private func sentence(_ s: String) -> String {
    guard let last = s.last, !".!?".contains(last) else { return s }
    return s + "."
}

/// The server couldn't be reached, or the response wasn't one we understand.
public struct ConnectionError: Error, Equatable, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

/// The server named this key with another device's id. The keyring entry found by this
/// device's public key decides the device's policy, so sync stops instead.
public struct DeviceMismatchError: Error, CustomStringConvertible {
    public let description: String
    public init(description: String) { self.description = description }
}
