import { describe, expect, it } from "vitest";

import { fromHex, hex } from "../src/crypto/bytes";
import { deriveFileId, deriveFileKey, deriveIndexKey, fileIdString, normPath } from "../src/crypto/kdf";
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
});
