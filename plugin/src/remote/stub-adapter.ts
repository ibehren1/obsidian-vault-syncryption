/**
 * Remote-only files (docs/remote-only.md 6): zero-byte stubs on disk, with the content sealed
 * under the local key (crypto.md 11) in a local store and served through a wrapped
 * `app.vault.adapter`. Sync goes through the Vault API, so it goes through the wrapper too.
 */
import { concat, fromUtf8, utf8 } from "../crypto/bytes";
import { openLocal, sealLocal } from "../crypto/local";
import { MissingContentError } from "../sync/fs";

/** The size and times of a remote-only file, kept next to its sealed content. */
export interface EntryInfo {
	size: number;
	mtime: number;
	ctime: number;
}

/** One remote-only file in the local store, keyed by its path. */
export interface SealedEntry extends EntryInfo {
	nonce: Uint8Array;
	data: Uint8Array;
}

export interface EntryStore {
	get(path: string): Promise<SealedEntry | undefined>;
	put(path: string, entry: SealedEntry): Promise<void>;
	delete(path: string): Promise<void>;
	/** Every entry's size and times, without the content. */
	infos(): Promise<Map<string, EntryInfo>>;
}

export class MemoryEntryStore implements EntryStore {
	readonly entries = new Map<string, SealedEntry>();
	async get(path: string) {
		return this.entries.get(path);
	}
	async put(path: string, entry: SealedEntry) {
		this.entries.set(path, entry);
	}
	async delete(path: string) {
		this.entries.delete(path);
	}
	async infos() {
		return new Map([...this.entries].map(([p, { size, mtime, ctime }]) => [p, { size, mtime, ctime }]));
	}
}

interface WriteOptions {
	mtime?: number;
	ctime?: number;
}

/** The `DataAdapter` methods the wrapper replaces. */
export interface WrappedAdapter {
	read(path: string): Promise<string>;
	readBinary(path: string): Promise<ArrayBuffer>;
	write(path: string, data: string, options?: WriteOptions): Promise<void>;
	writeBinary(path: string, data: ArrayBuffer, options?: WriteOptions): Promise<void>;
	append(path: string, data: string, options?: WriteOptions): Promise<void>;
	appendBinary(path: string, data: ArrayBuffer, options?: WriteOptions): Promise<void>;
	process(path: string, fn: (data: string) => string, options?: WriteOptions): Promise<string>;
	stat(path: string): Promise<{ type: "file" | "folder"; mtime: number; ctime: number; size: number } | null>;
	copy(from: string, to: string): Promise<void>;
	rename(from: string, to: string): Promise<void>;
	remove(path: string): Promise<void>;
	rmdir(path: string, recursive: boolean): Promise<void>;
	trashSystem(path: string): Promise<boolean>;
	trashLocal(path: string): Promise<void>;
	getResourcePath(path: string): string;
}

const METHODS = [
	"read",
	"readBinary",
	"write",
	"writeBinary",
	"append",
	"appendBinary",
	"process",
	"stat",
	"copy",
	"rename",
	"remove",
	"rmdir",
	"trashSystem",
	"trashLocal",
	"getResourcePath",
] as const;

const MIME: Record<string, string> = {
	png: "image/png",
	jpg: "image/jpeg",
	jpeg: "image/jpeg",
	gif: "image/gif",
	webp: "image/webp",
	svg: "image/svg+xml",
	bmp: "image/bmp",
	avif: "image/avif",
	pdf: "application/pdf",
	mp3: "audio/mpeg",
	wav: "audio/wav",
	m4a: "audio/mp4",
	ogg: "audio/ogg",
	flac: "audio/flac",
	mp4: "video/mp4",
	webm: "video/webm",
	mov: "video/quicktime",
};

export class LockedError extends Error {
	constructor() {
		super("The remote-only files are locked.");
	}
}

function buffer(data: Uint8Array): ArrayBuffer {
	return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

const EMPTY = new ArrayBuffer(0);

export interface StubAdapterOptions {
	/** Whether a vault path is remote-only: not for `configDir` and other hidden paths. */
	isRemote(path: string): boolean;
	store: EntryStore;
	/** Called when a resource URL becomes available, so the view can render it again. */
	onResource?: (path: string) => void;
	/** `URL.createObjectURL` and `revokeObjectURL`, replaceable in tests. */
	urls?: { create(blob: Blob): string; revoke(url: string): void };
}

export class StubAdapter {
	private key: Uint8Array | null = null;
	private orig: WrappedAdapter | null = null;
	private readonly queues = new Map<string, Promise<unknown>>();
	private readonly resources = new Map<string, string>();
	private readonly warming = new Set<string>();
	/** The store's entries without their content, loaded by `load`. */
	private readonly index = new Map<string, EntryInfo>();
	private readonly urls: { create(blob: Blob): string; revoke(url: string): void };
	/** Set by `restoreAll`: the files go back on disk for good. */
	private restoring = false;

	constructor(private readonly opts: StubAdapterOptions) {
		this.urls = opts.urls ?? { create: (b) => URL.createObjectURL(b), revoke: (u) => URL.revokeObjectURL(u) };
	}

	get locked(): boolean {
		return this.key === null;
	}

	unlock(key: Uint8Array): void {
		this.key = key;
	}

	/** Drops the key and every decrypted resource. */
	lock(): void {
		this.key = null;
		for (const url of this.resources.values()) this.urls.revoke(url);
		this.resources.clear();
	}

	isRemote(path: string): boolean {
		return this.opts.isRemote(path.replace(/^\/+/, ""));
	}

	/** Read the store's index. Call once, before Obsidian reads through the wrapper. */
	async load(): Promise<void> {
		this.index.clear();
		for (const [path, info] of await this.opts.store.infos()) this.index.set(path, info);
	}

	/** The paths in the store. */
	paths(): string[] {
		return [...this.index.keys()];
	}

	/** The real size and times of a file in the store. */
	info(path: string): EntryInfo | undefined {
		return this.index.get(path);
	}

	/** Replaces the adapter's methods on the instance. Returns the function that puts them back. */
	install(adapter: WrappedAdapter): () => void {
		const target = adapter as unknown as Record<string, unknown>;
		const saved = new Map<string, unknown>();
		const orig: Record<string, unknown> = {};
		for (const name of METHODS) {
			const own = Object.prototype.hasOwnProperty.call(target, name);
			saved.set(name, own ? target[name] : undefined);
			orig[name] = (adapter[name] as (...args: unknown[]) => unknown).bind(adapter);
		}
		this.orig = orig as unknown as WrappedAdapter;
		const self = this as unknown as Record<string, (...args: unknown[]) => unknown>;
		for (const name of METHODS) target[name] = self[name]!.bind(this);
		return () => {
			for (const [name, fn] of saved) {
				if (fn === undefined) delete target[name];
				else target[name] = fn;
			}
			this.lock();
			this.orig = null;
		};
	}

	/** The adapter's own methods, which read and write the disk as it is. */
	get raw(): WrappedAdapter {
		if (!this.orig) throw new Error("The stub adapter isn't installed.");
		return this.orig;
	}

	/** Runs operations on one path one at a time, like Obsidian's own adapter queue. */
	private serial<T>(path: string, fn: () => Promise<T>): Promise<T> {
		const prev = this.queues.get(path) ?? Promise.resolve();
		const next = prev.then(fn, fn);
		const tail = next.catch(() => {});
		this.queues.set(path, tail);
		void tail.then(() => {
			if (this.queues.get(path) === tail) this.queues.delete(path);
		});
		return next;
	}

	private requireKey(): Uint8Array {
		if (!this.key) throw new LockedError();
		return this.key;
	}

	private seal(path: string, plain: Uint8Array, mtime: number, ctime: number): SealedEntry {
		const { nonce, data } = sealLocal(this.requireKey(), "local-content", path, plain);
		return { nonce, data, size: plain.length, mtime, ctime };
	}

	private open(path: string, entry: SealedEntry): Uint8Array {
		return openLocal(this.requireKey(), "local-content", path, entry.nonce, entry.data);
	}

	private async store(path: string, entry: SealedEntry): Promise<void> {
		await this.opts.store.put(path, entry);
		this.index.set(path, { size: entry.size, mtime: entry.mtime, ctime: entry.ctime });
	}

	private async drop(path: string): Promise<void> {
		await this.opts.store.delete(path);
		this.index.delete(path);
		this.dropResource(path);
	}

	/**
	 * The plaintext of a remote-only file. A file not yet in the store is read from disk, but
	 * an empty one there is a stub whose content is missing, never empty content: reading it
	 * as content would let a sync commit it over the file.
	 */
	private async content(path: string): Promise<Uint8Array> {
		this.requireKey();
		const entry = await this.opts.store.get(path);
		if (entry) return this.open(path, entry);
		const plain = new Uint8Array(await this.raw.readBinary(path));
		if (plain.length === 0) throw new MissingContentError();
		return plain;
	}

	/** Stores the content and leaves an empty stub with the file's times, so Obsidian sees a change. */
	private async put(path: string, plain: Uint8Array, options?: WriteOptions): Promise<void> {
		const prev = this.index.get(path);
		const mtime = options?.mtime ?? Date.now();
		const ctime = prev?.ctime ?? options?.ctime ?? mtime;
		await this.store(path, this.seal(path, plain, mtime, ctime));
		this.dropResource(path);
		await this.raw.writeBinary(path, EMPTY, { ...options, mtime, ctime });
	}

	/** The size of the file on disk, which is 0 for a stub. */
	async diskSize(path: string): Promise<number | null> {
		const s = await this.raw.stat(path);
		return s?.type === "file" ? s.size : null;
	}

	/**
	 * Moves a file that is on disk in plaintext into the store. An empty file is taken as
	 * content only with `empty` (the files of a full device): otherwise it is a stub.
	 */
	async convert(path: string, empty = false): Promise<boolean> {
		return this.serial(path, async () => {
			if (this.restoring) return false;
			const stat = await this.raw.stat(path);
			if (stat?.type !== "file") return false;
			const plain = new Uint8Array(await this.raw.readBinary(path));
			if (plain.length === 0 && (!empty || this.index.has(path))) return false;
			await this.put(path, plain, { mtime: stat.mtime, ctime: stat.ctime });
			return true;
		});
	}

	/** Writes a remote-only file back to disk in plaintext and drops it from the store. */
	async restore(path: string): Promise<boolean> {
		return this.serial(path, async () => {
			const entry = await this.opts.store.get(path);
			if (!entry) {
				this.index.delete(path);
				return false;
			}
			await this.raw.writeBinary(path, buffer(this.open(path, entry)), { mtime: entry.mtime, ctime: entry.ctime });
			await this.drop(path);
			return true;
		});
	}

	/**
	 * Writes every file back to disk in plaintext (becoming a full device). From here on
	 * `convert` does nothing: Obsidian's `modify` events for the restored files would move
	 * them back into the store, which is then deleted. Returns the paths still in the store.
	 */
	async restoreAll(): Promise<string[]> {
		this.restoring = true;
		try {
			for (const path of this.paths()) await this.restore(path);
		} catch (e) {
			this.restoring = false;
			throw e;
		}
		const left = this.paths();
		if (left.length) this.restoring = false;
		return left;
	}

	// The wrapped `DataAdapter` methods.

	async read(path: string): Promise<string> {
		if (!this.isRemote(path)) return this.raw.read(path);
		return this.serial(path, async () => fromUtf8(await this.content(path)));
	}

	async readBinary(path: string): Promise<ArrayBuffer> {
		if (!this.isRemote(path)) return this.raw.readBinary(path);
		return this.serial(path, async () => buffer(await this.content(path)));
	}

	async write(path: string, data: string, options?: WriteOptions): Promise<void> {
		if (!this.isRemote(path)) return this.raw.write(path, data, options);
		return this.serial(path, () => this.put(path, utf8(data), options));
	}

	async writeBinary(path: string, data: ArrayBuffer, options?: WriteOptions): Promise<void> {
		if (!this.isRemote(path)) return this.raw.writeBinary(path, data, options);
		return this.serial(path, () => this.put(path, new Uint8Array(data), options));
	}

	async append(path: string, data: string, options?: WriteOptions): Promise<void> {
		if (!this.isRemote(path)) return this.raw.append(path, data, options);
		return this.serial(path, async () => this.put(path, concat(await this.content(path), utf8(data)), options));
	}

	async appendBinary(path: string, data: ArrayBuffer, options?: WriteOptions): Promise<void> {
		if (!this.isRemote(path)) return this.raw.appendBinary(path, data, options);
		return this.serial(path, async () =>
			this.put(path, concat(await this.content(path), new Uint8Array(data)), options),
		);
	}

	async process(path: string, fn: (data: string) => string, options?: WriteOptions): Promise<string> {
		if (!this.isRemote(path)) return this.raw.process(path, fn, options);
		return this.serial(path, async () => {
			const out = fn(fromUtf8(await this.content(path)));
			await this.put(path, utf8(out), options);
			return out;
		});
	}

	async stat(path: string) {
		const s = await this.raw.stat(path);
		if (!s || s.type !== "file" || !this.isRemote(path)) return s;
		const info = this.index.get(path);
		return info ? { ...s, ...info } : s;
	}

	async copy(from: string, to: string): Promise<void> {
		if (!this.isRemote(from) && !this.isRemote(to)) return this.raw.copy(from, to);
		const plain = await this.serial(from, () => this.content(from));
		await this.raw.copy(from, to);
		await this.serial(to, async () => {
			if (this.isRemote(to)) await this.put(to, plain);
			else await this.raw.writeBinary(to, buffer(plain));
		});
	}

	async rename(from: string, to: string): Promise<void> {
		if (!this.isRemote(from) && !this.isRemote(to)) return this.raw.rename(from, to);
		const stat = await this.raw.stat(from);
		// A folder: move each file of the store under it. Files only on disk move with the folder.
		const moves: [string, string][] =
			stat?.type === "folder"
				? this.paths()
						.filter((p) => p.startsWith(`${from}/`))
						.map((p) => [p, to + p.slice(from.length)])
				: [[from, to]];
		const contents = new Map<string, Uint8Array>();
		for (const [src] of moves) {
			if (this.index.has(src)) contents.set(src, await this.content(src));
		}
		await this.raw.rename(from, to);
		for (const [src, dst] of moves) {
			const plain = contents.get(src);
			const entry = this.index.get(src);
			if (plain === undefined) {
				// A plaintext file moved to a remote-only path.
				if (this.isRemote(dst)) await this.convert(dst);
				continue;
			}
			await this.drop(src);
			await this.serial(dst, async () => {
				const times = { mtime: entry?.mtime ?? Date.now(), ctime: entry?.ctime ?? Date.now() };
				if (this.isRemote(dst)) await this.put(dst, plain, times);
				else await this.raw.writeBinary(dst, buffer(plain), times);
			});
		}
	}

	async remove(path: string): Promise<void> {
		await this.raw.remove(path);
		if (this.isRemote(path)) await this.forget(path, false);
	}

	async rmdir(path: string, recursive: boolean): Promise<void> {
		await this.raw.rmdir(path, recursive);
		await this.forget(path, true);
	}

	/** The trash gets only the empty stub: the content is dropped (sync history would keep it). */
	async trashSystem(path: string): Promise<boolean> {
		const done = await this.raw.trashSystem(path);
		if (done) await this.forget(path, true);
		return done;
	}

	async trashLocal(path: string): Promise<void> {
		await this.raw.trashLocal(path);
		await this.forget(path, true);
	}

	private async forget(path: string, folder: boolean): Promise<void> {
		const paths = folder ? this.paths().filter((p) => p === path || p.startsWith(`${path}/`)) : [path];
		for (const p of paths) if (this.index.has(p)) await this.drop(p);
	}

	/**
	 * Synchronous in Obsidian, so a resource that isn't decrypted yet gets the stub's URL (empty)
	 * while it is decrypted in the background; `onResource` then asks the view to render again.
	 */
	getResourcePath(path: string): string {
		if (!this.isRemote(path)) return this.raw.getResourcePath(path);
		const url = this.resources.get(path);
		if (url) return url;
		void this.warm(path).then((ready) => {
			if (ready) this.opts.onResource?.(path);
		});
		return this.raw.getResourcePath(path);
	}

	/** Decrypts a resource into a `blob:` URL ahead of `getResourcePath`. */
	async warm(path: string): Promise<boolean> {
		if (this.locked || this.resources.has(path) || this.warming.has(path)) return false;
		this.warming.add(path);
		try {
			const plain = await this.serial(path, () => this.content(path));
			if (this.locked) return false;
			const ext = path.slice(path.lastIndexOf(".") + 1).toLowerCase();
			const type = MIME[ext] ?? "application/octet-stream";
			this.resources.set(path, this.urls.create(new Blob([buffer(plain)], { type })));
			return true;
		} catch {
			return false;
		} finally {
			this.warming.delete(path);
		}
	}

	private dropResource(path: string): void {
		const url = this.resources.get(path);
		if (url) this.urls.revoke(url);
		this.resources.delete(path);
	}
}
