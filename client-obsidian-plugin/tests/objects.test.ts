import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import { equal, fromHex, fromUtf8, hex } from "../src/crypto/bytes";
import { deriveFileId, deriveFileKey } from "../src/crypto/kdf";
import {
	CHUNK_SIZE,
	chunkDomain,
	metaDomain,
	objectEpoch,
	openChunks,
	openMeta,
	openObject,
	sealChunks,
	sealMeta,
	sealObject,
	type FileMeta,
} from "../src/crypto/objects";
import { loadVectors } from "./vectors";

const v = loadVectors<{
	vdk: Record<string, string>;
	indexKey: string;
	path: string;
	fileId: string;
	content: string;
	chunk: { epoch: number; index: number; nonce: string; object: string; blobId: string };
	meta: { epoch: number; nonce: string; plaintext: string; object: string; value: FileMeta };
	tombstone: { epoch: number; nonce: string; plaintext: string; object: string; value: FileMeta };
	invalid: { name: string; kind: string; index: number; object: string; fileId?: string }[];
}>("objects.json");

const indexKey = fromHex(v.indexKey);
const fileId = fromHex(v.fileId);
const keyFor = (epoch: number, id = fileId) => deriveFileKey(fromHex(v.vdk[String(epoch)]!), id);

describe("encrypted objects", () => {
	it("derives the fileId from the path", () => {
		expect(hex(deriveFileId(indexKey, v.path))).toBe(v.fileId);
	});

	it("seals a chunk like the reference", () => {
		const c = v.chunk;
		const object = sealObject(keyFor(c.epoch), c.epoch, chunkDomain(fileId, c.index), fromHex(v.content), fromHex(c.nonce));
		expect(hex(object)).toBe(c.object);
		expect(objectEpoch(object)).toBe(2);
	});

	it.each([
		["meta", v.meta],
		["tombstone", v.tombstone],
	] as const)("seals and opens %s like the reference", (_, m) => {
		const object = sealObject(keyFor(m.epoch), m.epoch, metaDomain(fileId), fromHex(m.plaintext), fromHex(m.nonce));
		expect(hex(object)).toBe(m.object);
		const meta = openMeta(keyFor(objectEpoch(object)), indexKey, fileId, object);
		expect(meta).toEqual(m.value);
	});

	it("opens the reference file", () => {
		const meta = openMeta(keyFor(2), indexKey, fileId, fromHex(v.meta.object));
		const data = openChunks(keyFor(2), fileId, meta, [fromHex(v.chunk.object)]);
		expect(hex(data)).toBe(v.content);
	});

	it.each(v.invalid)("rejects $name", (bad) => {
		const object = fromHex(bad.object);
		const open = () => {
			if (bad.kind === "chunk") return openObject(keyFor(2), chunkDomain(fileId, bad.index), object);
			if (bad.kind === "meta-moved") return openMeta(keyFor(2, fromHex(bad.fileId!)), indexKey, fromHex(bad.fileId!), object);
			return openMeta(keyFor(2), indexKey, fileId, object);
		};
		expect(open).toThrow();
	});

	// Compare with equal(), not toEqual(): vitest's deep equality on 8 MiB arrays uses
	// gigabytes of memory, enough for CI runners to kill the worker.
	it("round-trips a multi-chunk file", { timeout: 60_000 }, () => {
		const data = new Uint8Array(CHUNK_SIZE * 2 + 10);
		for (let i = 0; i < data.length; i++) data[i] = i % 251;
		const key = keyFor(1);
		const chunks = sealChunks(key, 1, fileId, data);
		expect(chunks.map((c) => c.size)).toEqual([CHUNK_SIZE, CHUNK_SIZE, 10]);
		const objects = chunks.map((c) => c.object);
		const meta: FileMeta = {
			...v.meta.value,
			size: data.length,
			sha256: hex(sha256(data)),
			chunks: chunks.map(({ id, size }) => ({ id, size })),
		};
		const opened = openMeta(key, indexKey, fileId, sealMeta(key, 1, fileId, meta));
		expect(equal(openChunks(key, fileId, opened, objects), data)).toBe(true);

		const swapped = [objects[1]!, objects[0]!, objects[2]!];
		expect(() => openChunks(key, fileId, opened, swapped)).toThrow();

		const wrongHash = openMeta(key, indexKey, fileId, sealMeta(key, 1, fileId, { ...meta, sha256: v.meta.value.sha256 }));
		expect(() => openChunks(key, fileId, wrongHash, objects)).toThrow();
	});

	it("rejects metadata whose chunk sizes don't add up", () => {
		const meta: FileMeta = { ...v.meta.value, size: v.meta.value.size + 1 };
		const object = sealMeta(keyFor(2), 2, fileId, meta);
		expect(() => openMeta(keyFor(2), indexKey, fileId, object)).toThrow("size");
	});

	it("encodes metadata as plain JSON", () => {
		expect(JSON.parse(fromUtf8(fromHex(v.meta.plaintext)))).toEqual(v.meta.value);
	});
});
