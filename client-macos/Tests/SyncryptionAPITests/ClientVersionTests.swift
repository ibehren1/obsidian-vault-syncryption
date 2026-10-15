import Foundation
import Testing

@testable import SyncryptionAPI

@Test func versionMatchesProjectYml() throws {
    let project = URL(filePath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appending(path: "project.yml")
    let text = try String(contentsOf: project, encoding: .utf8)
    let line = text.split(separator: "\n").first { $0.contains("MARKETING_VERSION:") }
    let value = line?.split(separator: ":").last?.trimmingCharacters(in: .whitespaces)
    #expect(value?.trimmingCharacters(in: CharacterSet(charactersIn: "\"")) == clientVersion)
}
