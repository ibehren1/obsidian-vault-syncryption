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

/**
 * A file whose content isn't on this device: a remote-only stub without its sealed content
 * (docs/remote-only.md 7). The engine downloads it again instead of committing the stub.
 */
export class MissingContentError extends Error {
	constructor() {
		super("This file's content isn't on this device.");
		this.name = "MissingContentError";
	}
}

/** By name: the error may come back through Obsidian's `Vault`, not as the same class. */
export function isMissingContent(e: unknown): boolean {
	return e instanceof Error && e.name === "MissingContentError";
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
	/** The hex SHA-256 of a file, where it can be had without reading the file whole. */
	hash?(path: string): Promise<string>;
	/**
	 * Write a file of `size` bytes that arrives in `count` chunks, where that can be done
	 * without holding it whole. If `chunks` throws, nothing is written.
	 */
	writeChunks?(path: string, size: number, count: number, chunks: AsyncIterable<Uint8Array>, times: { mtime: number; ctime?: number }): Promise<void>;
}

/** Collect chunks into one buffer of `size` bytes. Throws if they don't add up to it. */
export async function collect(size: number, chunks: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
	const out = new Uint8Array(size);
	let offset = 0;
	for await (const chunk of chunks) {
		if (offset + chunk.length > size) throw new Error("The chunks are larger than the file.");
		out.set(chunk, offset);
		offset += chunk.length;
	}
	if (offset !== size) throw new Error("The chunks are smaller than the file.");
	return out;
}

/** `fs.hash`, or a whole read where the file system has none. */
export async function hashFile(fs: VaultFs, path: string, sha256Hex: (data: Uint8Array) => string): Promise<string> {
	return fs.hash ? fs.hash(path) : sha256Hex(await fs.read(path));
}

/** `fs.writeChunks`, or the chunks collected and written whole. */
export async function writeChunked(
	fs: VaultFs,
	path: string,
	size: number,
	count: number,
	chunks: AsyncIterable<Uint8Array>,
	times: { mtime: number; ctime?: number },
): Promise<void> {
	if (fs.writeChunks) return fs.writeChunks(path, size, count, chunks, times);
	await fs.write(path, await collect(size, chunks), times);
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
