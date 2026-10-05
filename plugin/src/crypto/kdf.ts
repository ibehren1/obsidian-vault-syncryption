/** Vault key derivations (docs/crypto.md 5). */
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { concat, toB64u, utf8 } from "./bytes";

const EMPTY = new Uint8Array(0);
const INDEX_INFO = utf8("syncryption/v1/index");
const FILE_INFO = utf8("syncryption/v1/file");

/**
 * `normPath` (crypto.md 5.2): relative, `/`-separated, no empty, `.` or `..` segments,
 * Unicode NFC. Case is preserved. Throws on paths that can't be normalised safely.
 */
export function normPath(path: string): string {
	const nfc = path.normalize("NFC");
	const segments = nfc.split("/");
	if (nfc === "" || segments.some((s) => s === "" || s === "." || s === "..")) {
		throw new Error("invalid vault path");
	}
	return nfc;
}

/** `indexKey = HKDF(VDK[1], "", "syncryption/v1/index")`. Derived once at vault creation. */
export function deriveIndexKey(vdk1: Uint8Array): Uint8Array {
	return hkdf(sha256, vdk1, EMPTY, INDEX_INFO, 32);
}

/** `fileId = HMAC(indexKey, utf8(normPath))`, 32 bytes. */
export function deriveFileId(indexKey: Uint8Array, path: string): Uint8Array {
	return hmac(sha256, indexKey, utf8(normPath(path)));
}

/** The 43-character form of a fileId used in the API. */
export function fileIdString(fileId: Uint8Array): string {
	return toB64u(fileId);
}

/** `fileKey[e] = HKDF(VDK[e], "", "syncryption/v1/file" || fileId)`. */
export function deriveFileKey(vdk: Uint8Array, fileId: Uint8Array): Uint8Array {
	return hkdf(sha256, vdk, EMPTY, concat(FILE_INFO, fileId), 32);
}
