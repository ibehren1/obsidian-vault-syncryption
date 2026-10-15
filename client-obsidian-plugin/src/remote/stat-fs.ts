import { sha256Hex } from "../sync/cipher";
import { hashFile, writeChunked, type FileStat, type ListedFile, type VaultFs } from "../sync/fs";
import type { StubAdapter } from "./stub-adapter";

const EMPTY = new Uint8Array(0);

/**
 * `VaultFs` that reports the real size and times of remote-only files: `TFile.stat` has the
 * stub's (size 0), and the sync scan would hash those files again on every sync. It hashes
 * and writes remote-only files one chunk at a time, so a large one is never whole in memory.
 */
export class RemoteStatFs implements VaultFs {
	constructor(
		private readonly inner: VaultFs,
		private readonly stub: () => StubAdapter | null,
	) {}

	private real<T extends FileStat>(path: string, stat: T): T {
		const info = this.stub()?.info(path);
		return info ? { ...stat, ...info } : stat;
	}

	async list(): Promise<ListedFile[]> {
		return (await this.inner.list()).map((f) => this.real(f.path, f));
	}
	async stat(path: string): Promise<FileStat | null> {
		const stat = await this.inner.stat(path);
		return stat && this.real(path, stat);
	}
	read(path: string): Promise<Uint8Array> {
		return this.inner.read(path);
	}
	write(path: string, data: Uint8Array, times: { mtime: number; ctime?: number }): Promise<void> {
		return this.inner.write(path, data, times);
	}
	remove(path: string): Promise<void> {
		return this.inner.remove(path);
	}
	hash(path: string): Promise<string> {
		const stub = this.stub();
		if (stub && !stub.locked && stub.isRemote(path)) return stub.hash(path);
		return hashFile(this.inner, path, sha256Hex);
	}
	/**
	 * A remote-only file: the chunks go into the store first, then an empty write through the
	 * Vault API commits them, so Obsidian sees the change as for any other write.
	 */
	async writeChunks(path: string, size: number, count: number, chunks: AsyncIterable<Uint8Array>, times: { mtime: number; ctime?: number }): Promise<void> {
		const stub = this.stub();
		if (!stub || stub.locked || !stub.isRemote(path)) return writeChunked(this.inner, path, size, count, chunks, times);
		await stub.stage(path, count, chunks);
		try {
			await this.inner.write(path, EMPTY, times);
			// The Vault didn't pass the write on to the adapter: commit it directly.
			await stub.commitStaged(path, times);
		} finally {
			await stub.unstage(path);
		}
	}
}
