/**
 * Remote-only files (docs/remote-only.md 6): zero-byte stubs on disk, with the content sealed
 * under the local key (crypto.md 11) in a local store and served through a wrapped
 * `app.vault.adapter`. Sync goes through the Vault API, so it goes through the wrapper too.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/ciphers/utils.js";

import { concat, fromHex, fromUtf8, hex, utf8 } from "../crypto/bytes";
import { ENTRY_ID_SIZE, openLocal, openLocalChunk, sealLocalChunk } from "../crypto/local";
import { CHUNK_SIZE } from "../crypto/objects";
import { MissingContentError } from "../sync/fs";

/** The size and times of a remote-only file, kept next to its sealed content. */
export interface EntryInfo {
	size: number;
	mtime: number;
	ctime: number;
}

/** An entry's info as stored: a chunked entry also names its id (hex). */
export interface StoredInfo extends EntryInfo {
	id?: string;
}

/** A remote-only file from before chunking: the whole content sealed at once. */
export interface SealedEntry extends EntryInfo {
	nonce: Uint8Array;
	data: Uint8Array;
}

/** A remote-only file whose content is `count` chunks sealed under its random `id`. */
export interface ChunkedEntry extends EntryInfo {
	id: Uint8Array;
	count: number;
}

export type StoredEntry = SealedEntry | ChunkedEntry;

/** One sealed chunk of a `ChunkedEntry`. */
export interface SealedPiece {
	nonce: Uint8Array;
	data: Uint8Array;
}

export interface EntryStore {
	get(path: string): Promise<StoredEntry | undefined>;
	/** Replace the entry; the previous entry's chunks go in the same step. */
	put(path: string, entry: StoredEntry): Promise<void>;
	/** Delete the entry and its chunks. */
	delete(path: string): Promise<void>;
	getChunk(id: Uint8Array, index: number): Promise<SealedPiece | undefined>;
	putChunk(id: Uint8Array, index: number, piece: SealedPiece): Promise<void>;
	deleteChunks(id: Uint8Array): Promise<void>;
	/** The ids (hex) that have chunks, to find those of writes that never finished. */
	chunkIds(): Promise<Set<string>>;
	/** Every entry's size and times, without the content. */
	infos(): Promise<Map<string, StoredInfo>>;
}

function storedInfo(entry: StoredEntry): StoredInfo {
	const times: EntryInfo = { size: entry.size, mtime: entry.mtime, ctime: entry.ctime };
	return "id" in entry ? { ...times, id: hex(entry.id) } : times;
}

export class MemoryEntryStore implements EntryStore {
	readonly entries = new Map<string, StoredEntry>();
	readonly chunks = new Map<string, SealedPiece>();
	private key(id: Uint8Array | string, index: number): string {
		return `${typeof id === "string" ? id : hex(id)}/${index}`;
	}
	private dropChunks(id: string): void {
		for (const k of [...this.chunks.keys()]) if (k.startsWith(`${id}/`)) this.chunks.delete(k);
	}
	async get(path: string) {
		return this.entries.get(path);
	}
	async put(path: string, entry: StoredEntry) {
		const old = this.entries.get(path);
		const id = storedInfo(entry).id;
		if (old && "id" in old && hex(old.id) !== id) this.dropChunks(hex(old.id));
		this.entries.set(path, entry);
	}
	async delete(path: string) {
		const old = this.entries.get(path);
		if (old && "id" in old) this.dropChunks(hex(old.id));
		this.entries.delete(path);
	}
	async getChunk(id: Uint8Array, index: number) {
		return this.chunks.get(this.key(id, index));
	}
	async putChunk(id: Uint8Array, index: number, piece: SealedPiece) {
		this.chunks.set(this.key(id, index), piece);
	}
	async deleteChunks(id: Uint8Array) {
		this.dropChunks(hex(id));
	}
	async chunkIds() {
		return new Set([...this.chunks.keys()].map((k) => k.slice(0, k.indexOf("/"))));
	}
	async infos() {
		return new Map([...this.entries].map(([p, e]) => [p, storedInfo(e)]));
	}
}

/** A write whose chunks are in the store but whose entry isn't yet (`stage`). */
interface Staged {
	id: Uint8Array;
	count: number;
	size: number;
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

/** The part of a DOM element `replaceStubUrl` needs, so it can be tested without a DOM. */
export interface UrlElement {
	getAttribute(name: string): string | null;
	setAttribute(name: string, value: string): void;
}

/**
 * Point the elements that still show a resource's stub URL (Obsidian adds `?<mtime>`) at its
 * decrypted URL. Live Preview keeps the image it rendered and doesn't ask again, so this is
 * how an image decrypted after it was rendered appears there. Returns how many it changed.
 */
export function replaceStubUrl(elements: Iterable<UrlElement>, stubUrl: string, url: string): number {
	const base = (s: string) => s.split("?")[0];
	const stub = base(stubUrl);
	let changed = 0;
	for (const el of elements) {
		const src = el.getAttribute("src");
		if (src !== null && base(src) === stub) {
			el.setAttribute("src", url);
			changed++;
		}
	}
	return changed;
}

export class LockedError extends Error {
	constructor() {
		super("The remote-only files are locked.");
	}
}

/** The bytes as an `ArrayBuffer`, without a copy when `data` already spans its whole buffer. */
function buffer(data: Uint8Array): ArrayBuffer {
	if (data.byteOffset === 0 && data.byteLength === data.buffer.byteLength) return data.buffer as ArrayBuffer;
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
	/** The size of the chunks a write is sealed in (default 4 MiB, as on the server). */
	chunkSize?: number;
}

export class StubAdapter {
	private key: Uint8Array | null = null;
	private orig: WrappedAdapter | null = null;
	private readonly queues = new Map<string, Promise<unknown>>();
	private readonly resources = new Map<string, string>();
	/** Resources being decrypted, so every caller waits for the same one. */
	private readonly warming = new Map<string, Promise<boolean>>();
	/** Resources a view was given the stub's URL for: it is asked to render again once ready. */
	private readonly asked = new Set<string>();
	/** Counts the writes of each path, so a resource decrypted before a write isn't kept. */
	private readonly writes = new Map<string, number>();
	/** The store's entries without their content, loaded by `load`. */
	private readonly index = new Map<string, EntryInfo>();
	private readonly urls: { create(blob: Blob): string; revoke(url: string): void };
	/** Set by `restoreAll`: the files go back on disk for good. */
	private restoring = false;
	/** Downloads whose chunks are stored, waiting for their Vault write (`stage`). */
	private readonly staged = new Map<string, Staged>();

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

	/**
	 * Read the store's index, and delete the chunks of writes that never finished (a crash
	 * between the chunks and the entry). Call once, before Obsidian reads through the wrapper.
	 */
	async load(): Promise<void> {
		this.index.clear();
		const used = new Set<string>();
		for (const [path, { size, mtime, ctime, id }] of await this.opts.store.infos()) {
			this.index.set(path, { size, mtime, ctime });
			if (id) used.add(id);
		}
		for (const id of await this.opts.store.chunkIds()) {
			if (!used.has(id)) await this.opts.store.deleteChunks(fromHex(id));
		}
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

	/**
	 * Seal `count` chunks into the store under a new entry id, without an entry yet. If the
	 * chunks don't come to `count`, or `chunks` throws, the ones stored are deleted.
	 */
	private async sealChunks(path: string, count: number, chunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>): Promise<Staged> {
		const id = randomBytes(ENTRY_ID_SIZE);
		let index = 0;
		let size = 0;
		try {
			for await (const plain of chunks) {
				if (index >= count) throw new Error("More chunks than expected.");
				const piece = sealLocalChunk(this.requireKey(), path, id, index, count, plain);
				await this.opts.store.putChunk(id, index++, piece);
				size += plain.length;
			}
			if (index !== count) throw new Error("Fewer chunks than expected.");
		} catch (e) {
			await this.opts.store.deleteChunks(id);
			throw e;
		}
		return { id, count, size };
	}

	private async commit(path: string, staged: Staged, mtime: number, ctime: number): Promise<void> {
		const entry: ChunkedEntry = { id: staged.id, count: staged.count, size: staged.size, mtime, ctime };
		await this.opts.store.put(path, entry);
		this.index.set(path, { size: entry.size, mtime, ctime });
	}

	/** The plaintext chunks of a stored entry, one at a time. */
	private async *chunksOf(path: string, entry: StoredEntry): AsyncGenerator<Uint8Array> {
		if (!("id" in entry)) {
			yield openLocal(this.requireKey(), "local-content", path, entry.nonce, entry.data);
			return;
		}
		let size = 0;
		for (let i = 0; i < entry.count; i++) {
			const piece = await this.opts.store.getChunk(entry.id, i);
			// Lost chunks: the content is missing, and the sync downloads the file again.
			if (!piece) throw new MissingContentError();
			const plain = openLocalChunk(this.requireKey(), path, entry.id, i, entry.count, piece.nonce, piece.data);
			size += plain.length;
			yield plain;
		}
		if (size !== entry.size) throw new MissingContentError();
	}

	/** The whole plaintext of an entry, in one buffer of its exact size. */
	private async open(path: string, entry: StoredEntry): Promise<Uint8Array> {
		if (!("id" in entry)) return openLocal(this.requireKey(), "local-content", path, entry.nonce, entry.data);
		const out = new Uint8Array(entry.size);
		let offset = 0;
		for await (const plain of this.chunksOf(path, entry)) {
			if (offset + plain.length > out.length) throw new MissingContentError();
			out.set(plain, offset);
			offset += plain.length;
		}
		return out;
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

	/** The plaintext of a remote-only file in chunks, so a large one is never whole in memory. */
	private async *contentChunks(path: string): AsyncGenerator<Uint8Array> {
		this.requireKey();
		const entry = await this.opts.store.get(path);
		if (entry) {
			yield* this.chunksOf(path, entry);
			return;
		}
		yield await this.content(path);
	}

	/** The hex SHA-256 of a remote-only file, read one chunk at a time. */
	async hash(path: string): Promise<string> {
		return this.serial(path, async () => {
			const h = sha256.create();
			for await (const plain of this.contentChunks(path)) h.update(plain);
			return hex(h.digest());
		});
	}

	/**
	 * Store a file that arrives in `count` chunks (a download), one chunk at a time. Its entry
	 * is written by the next empty `writeBinary` of `path`, through the Vault API, so Obsidian
	 * sees the change. If `chunks` throws (a chunk or the file hash failed its check), nothing
	 * is kept.
	 */
	async stage(path: string, count: number, chunks: AsyncIterable<Uint8Array>): Promise<void> {
		const staged = await this.sealChunks(path, count, chunks);
		const old = this.staged.get(path);
		if (old) await this.opts.store.deleteChunks(old.id);
		this.staged.set(path, staged);
	}

	/** Commits a staged write that no Vault write committed. Returns whether there was one. */
	async commitStaged(path: string, times: WriteOptions): Promise<boolean> {
		return this.serial(path, async () => {
			if (!this.staged.has(path)) return false;
			await this.put(path, new Uint8Array(0), times);
			return true;
		});
	}

	/** Drops a staged write that won't be committed (the Vault write failed). */
	async unstage(path: string): Promise<void> {
		const staged = this.staged.get(path);
		this.staged.delete(path);
		if (staged) await this.opts.store.deleteChunks(staged.id);
	}

	/** Stores the content and leaves an empty stub with the file's times, so Obsidian sees a change. */
	private async put(path: string, plain: Uint8Array, options?: WriteOptions): Promise<void> {
		const prev = this.index.get(path);
		const mtime = options?.mtime ?? Date.now();
		const ctime = prev?.ctime ?? options?.ctime ?? mtime;
		const staged = this.staged.get(path);
		this.staged.delete(path);
		if (staged && plain.length === 0) {
			await this.commit(path, staged, mtime, ctime);
		} else {
			if (staged) await this.opts.store.deleteChunks(staged.id);
			const size = this.opts.chunkSize ?? CHUNK_SIZE;
			const count = Math.ceil(plain.length / size);
			const pieces = function* () {
				for (let off = 0; off < plain.length; off += size) yield plain.subarray(off, off + size);
			};
			await this.commit(path, await this.sealChunks(path, count, pieces()), mtime, ctime);
		}
		this.dropResource(path);
		await this.raw.writeBinary(path, EMPTY, { ...options, mtime, ctime });
		// A view that asked for it before it was here (or before this write) renders it now.
		if (this.asked.has(path)) void this.warm(path);
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
			const plain = await this.open(path, entry);
			await this.raw.writeBinary(path, buffer(plain), { mtime: entry.mtime, ctime: entry.ctime });
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
		// Also when it is already being decrypted (for the note that was opened): the view is
		// asked to render again once it is ready, or once the sync brings the file.
		this.asked.add(path);
		void this.warm(path);
		return this.raw.getResourcePath(path);
	}

	/** The URL a view gets for a resource that isn't decrypted yet: the stub's. */
	stubUrl(path: string): string {
		return this.raw.getResourcePath(path);
	}

	/** The decrypted resource's `blob:` URL, once it is ready. */
	resourceUrl(path: string): string | undefined {
		return this.resources.get(path);
	}

	/**
	 * Decrypts a resource into a `blob:` URL ahead of `getResourcePath`. Resolves to whether
	 * it is ready; callers while it is being decrypted share the same promise.
	 */
	warm(path: string): Promise<boolean> {
		if (this.locked) return Promise.resolve(false);
		if (this.resources.has(path)) return Promise.resolve(true);
		const pending = this.warming.get(path);
		if (pending) return pending;
		const job = this.decryptResource(path).finally(() => this.warming.delete(path));
		this.warming.set(path, job);
		return job;
	}

	private async decryptResource(path: string): Promise<boolean> {
		const writes = this.writes.get(path) ?? 0;
		try {
			// Chunk by chunk into the Blob, so a large attachment is never one buffer here.
			const parts = await this.serial(path, async () => {
				const out: ArrayBuffer[] = [];
				for await (const plain of this.contentChunks(path)) out.push(buffer(plain));
				return out;
			});
			// Locked meanwhile, or written again: this content is no longer the file's.
			if (this.locked || (this.writes.get(path) ?? 0) !== writes) return false;
			const ext = path.slice(path.lastIndexOf(".") + 1).toLowerCase();
			const type = MIME[ext] ?? "application/octet-stream";
			this.resources.set(path, this.urls.create(new Blob(parts, { type })));
		} catch {
			// Not in the store yet (still to be downloaded), or locked: tried again at its write.
			return false;
		}
		if (this.asked.delete(path)) this.opts.onResource?.(path);
		return true;
	}

	private dropResource(path: string): void {
		const url = this.resources.get(path);
		if (url) this.urls.revoke(url);
		this.resources.delete(path);
		this.writes.set(path, (this.writes.get(path) ?? 0) + 1);
	}
}
