import Foundation

@testable import SyncryptionCrypto

/// Loads `testvectors/<name>` (shared with the plugin and the backend) as JSON.
func vectors(_ name: String) throws -> [String: Any] {
    let url = URL(filePath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().appending(path: "testvectors").appending(path: name)
    return try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
}

extension Dictionary where Key == String, Value == Any {
    func str(_ k: String) -> String { self[k] as! String }
    func hex(_ k: String) -> Bytes { Bytes(hex: str(k))! }
    func dict(_ k: String) -> [String: Any] { self[k] as! [String: Any] }
    func list(_ k: String) -> [[String: Any]] { self[k] as! [[String: Any]] }
}
