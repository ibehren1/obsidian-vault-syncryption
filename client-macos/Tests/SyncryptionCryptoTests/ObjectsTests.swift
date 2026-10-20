import Foundation
import Testing

@testable import SyncryptionCrypto

@Suite struct ObjectsTests {
    let v: [String: Any]
    let indexKey: Bytes
    let fileId: Bytes

    init() throws {
        v = try vectors("objects.json")
        indexKey = v.hex("indexKey")
        fileId = v.hex("fileId")
    }

    func key(_ epoch: Int, _ id: Bytes? = nil) -> Bytes {
        KDF.fileKey(vdk: Bytes(hex: v.dict("vdk").str(String(epoch)))!, fileId: id ?? fileId)
    }

    @Test func derivesTheFileId() throws {
        #expect(try KDF.fileId(indexKey: indexKey, path: v.str("path")) == fileId)
    }

    @Test func sealsAChunkLikeTheReference() throws {
        let c = v.dict("chunk")
        let epoch = c["epoch"] as! Int
        let object = Objects.seal(fileKey: key(epoch), epoch: epoch, domain: Objects.chunkDomain(fileId, c["index"] as! Int),
                                  v.hex("content"), nonce: c.hex("nonce"))
        #expect(object == c.hex("object"))
        #expect(Objects.blobId(object) == c.str("blobId"))
        #expect(try Objects.epoch(of: object) == 2)
    }

    @Test(arguments: ["meta", "tombstone"])
    func sealsAndOpensMetadata(kind: String) throws {
        let m = v.dict(kind)
        let epoch = m["epoch"] as! Int
        let object = Objects.seal(fileKey: key(epoch), epoch: epoch, domain: Objects.metaDomain(fileId), m.hex("plaintext"),
                                  nonce: m.hex("nonce"))
        #expect(object == m.hex("object"))
        let meta = try Objects.openMeta(fileKey: key(try Objects.epoch(of: object)), indexKey: indexKey, fileId: fileId, object)
        let expected = try JSONDecoder().decode(FileMeta.self, from: JSONSerialization.data(withJSONObject: m["value"]!))
        #expect(meta == expected)
    }

    @Test func sealsAndOpensDeviceMetadata() throws {
        let m = v.dict("deviceMeta")
        let vdk = Bytes(hex: v.dict("vdk").str("2"))!
        let device = m.str("deviceId")
        #expect(KDF.deviceKey(vdk: vdk, deviceId: device) == m.hex("key"))
        let object = Objects.seal(fileKey: m.hex("key"), epoch: 2, domain: Objects.deviceDomain(device), m.hex("plaintext"),
                                  nonce: m.hex("nonce"))
        #expect(object == m.hex("object"))
        let meta = try Objects.openDeviceMeta(vdk: vdk, deviceId: device, object)
        #expect(meta == DeviceMeta(folders: [.init(name: "Notes", path: "/Users/me/Notes")]))
        // Bound to the device: the same object read as another device's fails.
        #expect(throws: Objects.Failure.self) { _ = try Objects.openDeviceMeta(vdk: vdk, deviceId: m.str("otherDeviceId"), object) }
        let again = try Objects.sealDeviceMeta(vdk: vdk, epoch: 2, deviceId: device, meta)
        #expect(try Objects.openDeviceMeta(vdk: vdk, deviceId: device, again) == meta)
    }

    @Test func opensTheReferenceFile() throws {
        let meta = try Objects.openMeta(fileKey: key(2), indexKey: indexKey, fileId: fileId, v.dict("meta").hex("object"))
        let data = try Objects.openChunks(fileKey: key(2), fileId: fileId, meta: meta, [v.dict("chunk").hex("object")])
        #expect(data == v.hex("content"))
    }

    @Test func rejectsInvalidObjects() throws {
        for bad in v.list("invalid") {
            let object = bad.hex("object")
            #expect(throws: Objects.Failure.self, "\(bad.str("name"))") {
                switch bad.str("kind") {
                case "chunk": _ = try Objects.open(fileKey: key(2), domain: Objects.chunkDomain(fileId, bad["index"] as! Int), object)
                case "meta-moved":
                    let id = bad.hex("fileId")
                    _ = try Objects.openMeta(fileKey: key(2, id), indexKey: indexKey, fileId: id, object)
                default: _ = try Objects.openMeta(fileKey: key(2), indexKey: indexKey, fileId: fileId, object)
                }
            }
        }
    }

    @Test func roundTripsAMultiChunkFile() throws {
        let data = (0..<(Objects.chunkSize * 2 + 10)).map { UInt8($0 % 251) }
        let k = key(1)
        let chunks = Objects.sealChunks(fileKey: k, epoch: 1, fileId: fileId, data)
        #expect(chunks.map(\.size) == [Objects.chunkSize, Objects.chunkSize, 10])
        let meta = FileMeta(path: v.str("path"), deleted: false, size: data.count, mtime: 1, ctime: 1,
                            sha256: Primitives.sha256(data).hex, chunks: chunks.map { ChunkRef(id: $0.id, size: $0.size) },
                            device: "d_x")
        let object = try Objects.sealMeta(fileKey: k, epoch: 1, fileId: fileId, meta)
        let opened = try Objects.openMeta(fileKey: k, indexKey: indexKey, fileId: fileId, object)
        #expect(opened == meta)
        #expect(try Objects.openChunks(fileKey: k, fileId: fileId, meta: opened, chunks.map(\.object)) == data)
        #expect(throws: Objects.Failure.self) {
            try Objects.openChunks(fileKey: k, fileId: fileId, meta: opened, [chunks[1].object, chunks[0].object, chunks[2].object])
        }
    }
}
