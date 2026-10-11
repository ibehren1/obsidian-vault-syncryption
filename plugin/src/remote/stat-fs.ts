import type { FileStat, ListedFile, VaultFs } from "../sync/fs";
import type { StubAdapter } from "./stub-adapter";

/**
 * `VaultFs` that reports the real size and times of remote-only files: `TFile.stat` has the
 * stub's (size 0), and the sync scan would hash those files again on every sync.
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
}
