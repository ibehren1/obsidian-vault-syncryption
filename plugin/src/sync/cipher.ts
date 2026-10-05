/** File encryption for one vault, on top of the keyring (docs/crypto.md 5 and 8). */
import { sha256 } from "@noble/hashes/sha2.js";

import { fromB64u, hex, toB64u } from "../crypto/bytes";
import { deriveFileId, deriveFileKey, fileIdString } from "../crypto/kdf";
import { epochKey, indexKey, type Keyring } from "../crypto/keyring";
import {
	objectEpoch,
	openChunks,
	openMeta,
	sealChunks,
	sealMeta,
	type FileMeta,
	type SealedChunk,
} from "../crypto/objects";

export const EMPTY_SHA256 = hex(sha256(new Uint8Array(0)));

export function sha256Hex(data: Uint8Array): string {
	return hex(sha256(data));
}

export interface SealedFile {
	/** b64u, for the commit body. */
	meta: string;
	chunks: SealedChunk[];
}

export class VaultCipher {
	constructor(private readonly keyring: () => Keyring) {}

	currentEpoch(): number {
		return this.keyring().currentEpoch;
	}

	/** The epoch a revision's metadata (b64u) was encrypted under. */
	epoch(meta: string): number {
		return objectEpoch(fromB64u(meta));
	}

	fileId(path: string): string {
		return fileIdString(deriveFileId(indexKey(this.keyring()), path));
	}

	private fileKey(fileId: Uint8Array, epoch: number): Uint8Array {
		return deriveFileKey(epochKey(this.keyring(), epoch), fileId);
	}

	/** Decrypt and check a revision's metadata. Throws `ObjectError` if it was tampered with. */
	openMeta(fileId: string, meta: string): FileMeta {
		const id = fromB64u(fileId);
		const object = fromB64u(meta);
		return openMeta(this.fileKey(id, objectEpoch(object)), indexKey(this.keyring()), id, object);
	}

	/** Decrypt the chunks of a revision. `objects[i]` is the blob for `meta.chunks[i]`. */
	openContent(fileId: string, meta: FileMeta, objects: Uint8Array[]): Uint8Array {
		const id = fromB64u(fileId);
		const epoch = objects.length ? objectEpoch(objects[0]!) : this.keyring().currentEpoch;
		if (objects.some((o) => objectEpoch(o) !== epoch)) throw new Error("chunks from different epochs");
		return openChunks(this.fileKey(id, epoch), id, meta, objects);
	}

	/** Encrypt a file, or a deletion when `data` is null, under the current epoch. */
	seal(
		path: string,
		data: Uint8Array | null,
		times: { mtime: number; ctime: number },
		device: string,
	): SealedFile & { sha256: string } {
		const keyring = this.keyring();
		const id = deriveFileId(indexKey(keyring), path);
		const epoch = keyring.currentEpoch;
		const key = this.fileKey(id, epoch);
		const chunks = data === null ? [] : sealChunks(key, epoch, id, data);
		const digest = data === null ? EMPTY_SHA256 : sha256Hex(data);
		const meta: FileMeta = {
			v: 1,
			path,
			deleted: data === null,
			size: data?.length ?? 0,
			mtime: times.mtime,
			ctime: times.ctime,
			sha256: digest,
			chunks: chunks.map((c) => ({ id: c.id, size: c.size })),
			device,
		};
		return { meta: toB64u(sealMeta(key, epoch, id, meta)), chunks, sha256: digest };
	}
}
