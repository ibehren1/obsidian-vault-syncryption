/**
 * Sealing a remote-only device's local copy under its local key (docs/crypto.md 11):
 * XChaCha20-Poly1305 with a random nonce, and the domain and the path in the AD. Content is
 * sealed in chunks, each bound to its entry, its position and the chunk count.
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";

import { concat, fromB64u, fromHex, hex, toB64u, utf8 } from "./bytes";

export type LocalDomain = "local-content" | "local-hash";

function ad(domain: LocalDomain, path: string): Uint8Array {
	return concat(utf8(`syncryption/v1/${domain}`), new Uint8Array([0]), utf8(path));
}

export function sealLocal(
	key: Uint8Array,
	domain: LocalDomain,
	path: string,
	plaintext: Uint8Array,
	nonce: Uint8Array = randomBytes(24),
): { nonce: Uint8Array; data: Uint8Array } {
	return { nonce, data: xchacha20poly1305(key, nonce, ad(domain, path)).encrypt(plaintext) };
}

/** Throws if the data was sealed under another key, domain or path. */
export function openLocal(
	key: Uint8Array,
	domain: LocalDomain,
	path: string,
	nonce: Uint8Array,
	data: Uint8Array,
): Uint8Array {
	return xchacha20poly1305(key, nonce, ad(domain, path)).decrypt(data);
}

/** A chunk's AD: domain, index and count (u32 big-endian), the 16-byte entry id, the path. */
function chunkAd(path: string, entryId: Uint8Array, index: number, count: number): Uint8Array {
	const position = new Uint8Array(8);
	const view = new DataView(position.buffer);
	view.setUint32(0, index);
	view.setUint32(4, count);
	return concat(utf8("syncryption/v1/local-chunk"), new Uint8Array([0]), position, entryId, utf8(path));
}

export const ENTRY_ID_SIZE = 16;

export function sealLocalChunk(
	key: Uint8Array,
	path: string,
	entryId: Uint8Array,
	index: number,
	count: number,
	plaintext: Uint8Array,
	nonce: Uint8Array = randomBytes(24),
): { nonce: Uint8Array; data: Uint8Array } {
	const ad = chunkAd(path, entryId, index, count);
	return { nonce, data: xchacha20poly1305(key, nonce, ad).encrypt(plaintext) };
}

/** Throws if the chunk belongs to another key, path, entry, position or count. */
export function openLocalChunk(
	key: Uint8Array,
	path: string,
	entryId: Uint8Array,
	index: number,
	count: number,
	nonce: Uint8Array,
	data: Uint8Array,
): Uint8Array {
	return xchacha20poly1305(key, nonce, chunkAd(path, entryId, index, count)).decrypt(data);
}

const HASH_PREFIX = "s1:";

/** A sealed hex SHA-256: `"s1:" || b64u(nonce || ciphertext)`. */
export function sealHash(key: Uint8Array, path: string, sha256: string, nonce?: Uint8Array): string {
	const sealed = sealLocal(key, "local-hash", path, fromHex(sha256), nonce);
	return HASH_PREFIX + toB64u(concat(sealed.nonce, sealed.data));
}

export function isSealedHash(value: string): boolean {
	return value.startsWith(HASH_PREFIX);
}

export function openHash(key: Uint8Array, path: string, sealed: string): string {
	const raw = fromB64u(sealed.slice(HASH_PREFIX.length));
	return hex(openLocal(key, "local-hash", path, raw.subarray(0, 24), raw.subarray(24)));
}
