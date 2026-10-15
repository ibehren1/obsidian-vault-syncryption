// swift-tools-version: 6.2
// The client's libraries and their tests. The app is built from project.yml (XcodeGen) on
// top of these libraries.
import PackageDescription

let package = Package(
    name: "SyncryptionClient",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "SyncryptionCrypto", targets: ["SyncryptionCrypto"]),
        .library(name: "SyncryptionAPI", targets: ["SyncryptionAPI"]),
        .library(name: "SyncryptionStore", targets: ["SyncryptionStore"]),
        .library(name: "SyncryptionSync", targets: ["SyncryptionSync"]),
        .library(name: "SyncryptionAppCore", targets: ["SyncryptionAppCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.9.1"),
    ],
    targets: [
        .target(name: "SyncryptionCrypto", dependencies: [.product(name: "Clibsodium", package: "swift-sodium")]),
        .target(name: "SyncryptionAPI", dependencies: ["SyncryptionCrypto"]),
        .target(name: "SyncryptionStore"),
        .target(name: "SyncryptionSync", dependencies: ["SyncryptionCrypto", "SyncryptionAPI", "SyncryptionStore"]),
        .target(name: "SyncryptionAppCore", dependencies: ["SyncryptionCrypto", "SyncryptionAPI", "SyncryptionStore", "SyncryptionSync"]),
        .target(name: "TestBackend", dependencies: ["SyncryptionAPI"], path: "Tests/TestBackend"),
        .testTarget(name: "SyncryptionCryptoTests", dependencies: ["SyncryptionCrypto"]),
        .testTarget(name: "SyncryptionAPITests", dependencies: ["SyncryptionAPI", "TestBackend"]),
        .testTarget(name: "SyncryptionStoreTests", dependencies: ["SyncryptionStore"]),
        .testTarget(name: "SyncryptionSyncTests", dependencies: ["SyncryptionSync", "TestBackend"]),
        .testTarget(name: "SyncryptionAppCoreTests", dependencies: ["SyncryptionAppCore", "TestBackend"]),
    ]
)
