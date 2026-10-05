/** Encrypted metadata and chunk objects (docs/crypto.md 8). */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { concat, equal, fromUtf8, hex, u32be, utf8 } from "./bytes";
import { deriveFileId } from "./kdf";

export const FORMAT_VERSION = 1;
export const HEADER_SIZE = 5;
export const NONCE_SIZE = 24;
export const OVERHEAD = HEADER_SIZE + NONCE_SIZE + 16;
export const CHUNK_SIZE = 4 * 1024 * 1024;
export const MAX_META_SIZE = 64 * 1024;

export class ObjectError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ObjectError";
	}
}

export function metaDomain(fileId: Uint8Array): Uint8Array {
	return concat(utf8("syncryption/v1/meta"), fileId);
}

export function chunkDomain(fileId: Uint8Array, index: number): Uint8Array {
	return concat(utf8("syncryption/v1/chunk"), fileId, u32be(index));
}

function header(epoch: number): Uint8Array {
	if (!Number.isInteger(epoch) || epoch < 1 || epoch > 0xffffffff) throw new Error("invalid epoch");
	return concat(Uint8Array.of(FORMAT_VERSION), u32be(epoch));
}

/** `header || nonce || AEAD(fileKey, nonce, plaintext, header || domain)`. */
export function sealObject(
	fileKey: Uint8Array,
	epoch: number,
	domain: Uint8Array,
	plaintext: Uint8Array,
	nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(NONCE_SIZE)),
): Uint8Array {
	if (nonce.length !== NONCE_SIZE) throw new Error("invalid nonce");
	const h = header(epoch);
	const ct = xchacha20poly1305(fileKey, nonce, concat(h, domain)).encrypt(plaintext);
	return concat(h, nonce, ct);
}

/** The epoch in an object's header, so the reader can pick the right VDK. */
export function objectEpoch(object: Uint8Array): number {
	if (object.length < OVERHEAD || object[0] !== FORMAT_VERSION) {
		throw new ObjectError("unsupported or truncated object");
	}
	return new DataView(object.buffer, object.byteOffset + 1, 4).getUint32(0);
}

export function openObject(fileKey: Uint8Array, domain: Uint8Array, object: Uint8Array): Uint8Array {
	objectEpoch(object);
	const h = object.subarray(0, HEADER_SIZE);
	const nonce = object.subarray(HEADER_SIZE, HEADER_SIZE + NONCE_SIZE);
	try {
		return xchacha20poly1305(fileKey, nonce, concat(h, domain)).decrypt(
			object.subarray(HEADER_SIZE + NONCE_SIZE),
		);
	} catch {
		throw new ObjectError("object failed to decrypt");
	}
}

/** Blob id: `hex(SHA-256(object))`. */
export function blobId(object: Uint8Array): string {
	return hex(sha256(object));
}

export interface ChunkRef {
	id: string;
	size: number;
}

export interface FileMeta {
	v: 1;
	path: string;
	deleted: boolean;
	size: number;
	mtime: number;
	ctime: number;
	sha256: string;
	chunks: ChunkRef[];
	device: string;
}

export function sealMeta(
	fileKey: Uint8Array,
	epoch: number,
	fileId: Uint8Array,
	meta: FileMeta,
	nonce?: Uint8Array,
): Uint8Array {
	const object = sealObject(fileKey, epoch, metaDomain(fileId), utf8(JSON.stringify(meta)), nonce);
	if (object.length > MAX_META_SIZE) throw new ObjectError("metadata too large");
	return object;
}

/**
 * Decrypt and check metadata (crypto.md 8.3): its path must hash to `fileId`, and the
 * chunk list must match `size`.
 */
export function openMeta(
	fileKey: Uint8Array,
	indexKey: Uint8Array,
	fileId: Uint8Array,
	object: Uint8Array,
): FileMeta {
	if (object.length > MAX_META_SIZE) throw new ObjectError("metadata too large");
	let meta: FileMeta;
	try {
		meta = JSON.parse(fromUtf8(openObject(fileKey, metaDomain(fileId), object))) as FileMeta;
	} catch (e) {
		if (e instanceof ObjectError) throw e;
		throw new ObjectError("metadata is not valid JSON");
	}
	if (!isFileMeta(meta)) throw new ObjectError("metadata has the wrong shape");
	let pathId: Uint8Array;
	try {
		pathId = deriveFileId(indexKey, meta.path);
	} catch {
		throw new ObjectError("metadata path is invalid");
	}
	if (!equal(pathId, fileId)) throw new ObjectError("metadata path does not match fileId");
	const total = meta.chunks.reduce((n, c) => n + c.size, 0);
	if (total !== meta.size) throw new ObjectError("chunk sizes do not add up to size");
	if (meta.deleted && meta.chunks.length !== 0) throw new ObjectError("deleted file has chunks");
	const last = meta.chunks.length - 1;
	if (meta.chunks.some((c, i) => c.size > CHUNK_SIZE || (i < last && c.size !== CHUNK_SIZE))) {
		throw new ObjectError("chunks must be 4 MiB, except the last");
	}
	return meta;
}

function isFileMeta(m: unknown): m is FileMeta {
	if (typeof m !== "object" || m === null) return false;
	const o = m as Record<string, unknown>;
	const isCount = (x: unknown) => typeof x === "number" && Number.isSafeInteger(x) && x >= 0;
	return (
		o.v === 1 &&
		typeof o.path === "string" &&
		typeof o.deleted === "boolean" &&
		isCount(o.size) &&
		isCount(o.mtime) &&
		isCount(o.ctime) &&
		typeof o.sha256 === "string" &&
		/^[0-9a-f]{64}$/.test(o.sha256) &&
		typeof o.device === "string" &&
		Array.isArray(o.chunks) &&
		o.chunks.every(
			(c: unknown) =>
				typeof c === "object" &&
				c !== null &&
				typeof (c as ChunkRef).id === "string" &&
				/^[0-9a-f]{64}$/.test((c as ChunkRef).id) &&
				isCount((c as ChunkRef).size) &&
				(c as ChunkRef).size > 0,
		)
	);
}

export interface SealedChunk {
	id: string;
	size: number;
	object: Uint8Array;
}

/** Split into 4 MiB chunks and seal each one. An empty file has no chunks. */
export function sealChunks(
	fileKey: Uint8Array,
	epoch: number,
	fileId: Uint8Array,
	data: Uint8Array,
): SealedChunk[] {
	const chunks: SealedChunk[] = [];
	for (let i = 0, off = 0; off < data.length; i++, off += CHUNK_SIZE) {
		const plain = data.subarray(off, off + CHUNK_SIZE);
		const object = sealObject(fileKey, epoch, chunkDomain(fileId, i), plain);
		chunks.push({ id: blobId(object), size: plain.length, object });
	}
	return chunks;
}

/**
 * Decrypt chunks in metadata order and check the reassembled file against `meta.sha256`.
 * `objects[i]` must be the blob for `meta.chunks[i]`.
 */
export function openChunks(
	fileKey: Uint8Array,
	fileId: Uint8Array,
	meta: FileMeta,
	objects: Uint8Array[],
): Uint8Array {
	if (objects.length !== meta.chunks.length) throw new ObjectError("wrong number of chunks");
	const parts = objects.map((object, i) => {
		const ref = meta.chunks[i]!;
		if (blobId(object) !== ref.id) throw new ObjectError("chunk does not match its id");
		const plain = openObject(fileKey, chunkDomain(fileId, i), object);
		if (plain.length !== ref.size) throw new ObjectError("chunk has the wrong size");
		return plain;
	});
	const data = concat(...parts);
	if (hex(sha256(data)) !== meta.sha256) throw new ObjectError("file hash does not match");
	return data;
}
