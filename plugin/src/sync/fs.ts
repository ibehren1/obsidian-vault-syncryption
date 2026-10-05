/** The files the engine syncs, behind an interface so tests can use memory. */

export interface FileStat {
	mtime: number;
	ctime: number;
	size: number;
}

export interface ListedFile extends FileStat {
	/** Vault-relative, `/`-separated. */
	path: string;
}

export interface VaultFs {
	/** Every file in the vault (no folders). The engine filters out excluded paths. */
	list(): Promise<ListedFile[]>;
	stat(path: string): Promise<FileStat | null>;
	read(path: string): Promise<Uint8Array>;
	/** Create or replace, creating parent folders as needed. */
	write(path: string, data: Uint8Array, times: { mtime: number; ctime?: number }): Promise<void>;
	/** Delete a file because it was deleted on another device. */
	remove(path: string): Promise<void>;
}

export class MemoryFs implements VaultFs {
	readonly files = new Map<string, { data: Uint8Array } & FileStat>();
	private clock = 1_790_000_000_000;

	/** Simulates an edit by the user. */
	set(path: string, content: string | Uint8Array): void {
		const data = typeof content === "string" ? new TextEncoder().encode(content) : content;
		const mtime = this.tick();
		const ctime = this.files.get(path)?.ctime ?? mtime;
		this.files.set(path, { data, mtime, ctime, size: data.length });
	}
	text(path: string): string | undefined {
		const f = this.files.get(path);
		return f && new TextDecoder().decode(f.data);
	}
	delete(path: string): void {
		this.files.delete(path);
	}
	private tick(): number {
		return (this.clock += 1000);
	}

	async list(): Promise<ListedFile[]> {
		return [...this.files].map(([path, f]) => ({ path, mtime: f.mtime, ctime: f.ctime, size: f.size }));
	}
	async stat(path: string): Promise<FileStat | null> {
		const f = this.files.get(path);
		return f ? { mtime: f.mtime, ctime: f.ctime, size: f.size } : null;
	}
	async read(path: string): Promise<Uint8Array> {
		const f = this.files.get(path);
		if (!f) throw new Error(`no such file: ${path}`);
		return f.data.slice();
	}
	async write(path: string, data: Uint8Array, times: { mtime: number; ctime?: number }): Promise<void> {
		const ctime = times.ctime ?? this.files.get(path)?.ctime ?? times.mtime;
		// Like a real clock, later edits get later times than anything written before.
		this.clock = Math.max(this.clock, times.mtime);
		this.files.set(path, { data: data.slice(), mtime: times.mtime, ctime, size: data.length });
	}
	async remove(path: string): Promise<void> {
		this.files.delete(path);
	}
}
