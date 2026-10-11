import { describe, expect, it } from "vitest";

import { fromHex, hex } from "../src/crypto/bytes";
import { deriveFileId, deriveFileKey, deriveIndexKey, deriveLocalKey, fileIdString, normPath } from "../src/crypto/kdf";
import { openHash, openLocal, sealHash, sealLocal } from "../src/crypto/local";
import { pairingCode } from "../src/crypto/openssh";
import { loadVectors } from "./vectors";

const v = loadVectors<{
	vdk1: string;
	vdk2: string;
	indexKey: string;
	files: {
		name: string;
		path: string;
		normPath: string;
		fileId: string;
		fileIdString: string;
		fileKeyEpoch1: string;
		fileKeyEpoch2: string;
	}[];
	invalidPaths: string[];
	pairingCodes: { publicKey: string; code: string }[];
	local: {
		localKey: string;
		path: string;
		content: { plaintext: string; nonce: string; ciphertext: string };
		hash: { sha256: string; nonce: string; sealed: string };
	};
}>("kdf.json");

describe("kdf", () => {
	const indexKey = deriveIndexKey(fromHex(v.vdk1));

	it("derives indexKey from VDK[1]", () => {
		expect(hex(indexKey)).toBe(v.indexKey);
	});

	it.each(v.files)("derives fileId and fileKey: $name", (f) => {
		expect(normPath(f.path)).toBe(f.normPath);
		const fileId = deriveFileId(indexKey, f.path);
		expect(hex(fileId)).toBe(f.fileId);
		expect(fileIdString(fileId)).toBe(f.fileIdString);
		expect(fileIdString(fileId)).toHaveLength(43);
		expect(hex(deriveFileKey(fromHex(v.vdk1), fileId))).toBe(f.fileKeyEpoch1);
		expect(hex(deriveFileKey(fromHex(v.vdk2), fileId))).toBe(f.fileKeyEpoch2);
	});

	it.each(v.invalidPaths)("rejects path %j", (p) => {
		expect(() => normPath(p)).toThrow();
	});

	it.each(v.pairingCodes)("computes pairing code $code", (p) => {
		expect(pairingCode(fromHex(p.publicKey))).toBe(p.code);
	});

	describe("local key", () => {
		const key = deriveLocalKey(indexKey);
		const { path, content, hash } = v.local;

		it("derives localKey from indexKey", () => {
			expect(hex(key)).toBe(v.local.localKey);
		});

		it("seals local content with the path in the AD", () => {
			const sealed = sealLocal(key, "local-content", path, fromHex(content.plaintext), fromHex(content.nonce));
			expect(hex(sealed.data)).toBe(content.ciphertext);
			const nonce = fromHex(content.nonce);
			expect(hex(openLocal(key, "local-content", path, nonce, sealed.data))).toBe(content.plaintext);
			expect(() => openLocal(key, "local-content", "other.md", nonce, sealed.data)).toThrow();
			expect(() => openLocal(key, "local-hash", path, nonce, sealed.data)).toThrow();
		});

		it("seals hashes", () => {
			expect(sealHash(key, path, hash.sha256, fromHex(hash.nonce))).toBe(hash.sealed);
			expect(openHash(key, path, hash.sealed)).toBe(hash.sha256);
			expect(() => openHash(key, "other.md", hash.sealed)).toThrow();
			expect(sealHash(key, path, hash.sha256)).not.toBe(hash.sealed);
		});
	});
});
