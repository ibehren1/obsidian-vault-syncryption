/**
 * Sync state for a remote-only device (docs/remote-only.md 7): `SyncedFile.sha256` is a
 * plaintext hash, which would let anyone confirm a guess of a file's content, so it is
 * stored sealed under the local key (crypto.md 11). Values without the `s1:` prefix are
 * plaintext hashes from before the device was remote-only.
 */
import { isSealedHash, openHash, sealHash } from "../crypto/local";
import type { OutboxEntry, SyncedFile, SyncStore } from "./state";

/**
 * - `"plain"`: a full device. Hashes are stored as they are.
 * - a key: a remote-only device, unlocked.
 * - `"locked"`: a remote-only device without the key. Sealed hashes are returned sealed
 *   (they match nothing), and storing a file fails.
 */
export type HashMode = "plain" | "locked" | Uint8Array;

export class SealedHashStore implements SyncStore {
	constructor(
		readonly inner: SyncStore,
		private readonly mode: () => HashMode,
	) {}

	private open(path: string, file: SyncedFile): SyncedFile {
		const mode = this.mode();
		if (!isSealedHash(file.sha256) || typeof mode === "string") return file;
		return { ...file, sha256: openHash(mode, path, file.sha256) };
	}

	private seal(path: string, file: SyncedFile): SyncedFile {
		const mode = this.mode();
		if (mode === "plain" || file.sha256 === "") return file;
		if (mode === "locked") throw new Error("The remote-only files are locked.");
		return { ...file, sha256: sealHash(mode, path, file.sha256) };
	}

	/** Seal every plaintext hash under `key` (becoming remote-only). Returns how many. */
	sealAll(key: Uint8Array): Promise<number> {
		return this.rewrite(true, (path, sha256) => sealHash(key, path, sha256));
	}

	/** Open every sealed hash (becoming a full device). Returns how many. */
	openAll(key: Uint8Array): Promise<number> {
		return this.rewrite(false, (path, sha256) => openHash(key, path, sha256));
	}

	private async rewrite(sealedAfter: boolean, change: (path: string, sha256: string) => string): Promise<number> {
		let n = 0;
		for (const [path, file] of await this.inner.files()) {
			if (file.sha256 === "" || isSealedHash(file.sha256) === sealedAfter) continue;
			await this.inner.putFile(path, { ...file, sha256: change(path, file.sha256) });
			n++;
		}
		return n;
	}

	/** How many hashes are stored in plaintext. */
	async plainHashes(): Promise<number> {
		let n = 0;
		for (const file of (await this.inner.files()).values()) if (file.sha256 !== "" && !isSealedHash(file.sha256)) n++;
		return n;
	}

	getMeta<T>(key: string): Promise<T | undefined> {
		return this.inner.getMeta<T>(key);
	}
	setMeta(key: string, value: unknown): Promise<void> {
		return this.inner.setMeta(key, value);
	}
	async getFile(path: string): Promise<SyncedFile | undefined> {
		const file = await this.inner.getFile(path);
		return file && this.open(path, file);
	}
	async putFile(path: string, file: SyncedFile): Promise<void> {
		await this.inner.putFile(path, this.seal(path, file));
	}
	removeFile(path: string): Promise<void> {
		return this.inner.removeFile(path);
	}
	async files(): Promise<Map<string, SyncedFile>> {
		const files = await this.inner.files();
		for (const [path, file] of files) files.set(path, this.open(path, file));
		return files;
	}
	enqueue(path: string): Promise<void> {
		return this.inner.enqueue(path);
	}
	outbox(): Promise<OutboxEntry[]> {
		return this.inner.outbox();
	}
	dequeue(entry: OutboxEntry): Promise<void> {
		return this.inner.dequeue(entry);
	}
	clear(): Promise<void> {
		return this.inner.clear();
	}
	close(): void {
		this.inner.close();
	}
}
