/**
 * The remote-only store (docs/remote-only.md 7) on IndexedDB: each file's content sealed
 * under the local key, and its size and times apart, so listing doesn't load the content.
 * Content is kept in chunks (`chunks`, keyed by `[entry id, index]`), so a large file is
 * never read or written whole. Entries from before chunking hold their content whole.
 * A database of its own, so the wipe on removal can delete it whole.
 */
import { hex } from "../crypto/bytes";
import type { EntryInfo, EntryStore, SealedPiece, StoredEntry, StoredInfo } from "../remote/stub-adapter";

const VERSION = 2;
const ENTRIES = "entries";
const INFO = "info";
const CHUNKS = "chunks";

function done<T>(request: IDBRequest<T>): Promise<T> {
	return new Promise((resolve, reject) => {
		request.onsuccess = () => resolve(request.result);
		request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
	});
}

function committed(tx: IDBTransaction): Promise<void> {
	return new Promise((resolve, reject) => {
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error ?? new Error("IndexedDB transaction failed"));
		tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));
	});
}

/** Every chunk of one entry. */
function chunksOf(id: string): IDBKeyRange {
	return IDBKeyRange.bound([id, 0], [id, Number.MAX_SAFE_INTEGER]);
}

function info(entry: StoredEntry): StoredInfo {
	const times: EntryInfo = { size: entry.size, mtime: entry.mtime, ctime: entry.ctime };
	return "id" in entry ? { ...times, id: hex(entry.id) } : times;
}

export class IndexedDbEntryStore implements EntryStore {
	private constructor(private readonly db: IDBDatabase) {}

	static async open(name: string, factory: IDBFactory = indexedDB): Promise<IndexedDbEntryStore> {
		const request = factory.open(name, VERSION);
		request.onupgradeneeded = () => {
			for (const store of [ENTRIES, INFO, CHUNKS]) {
				if (!request.result.objectStoreNames.contains(store)) request.result.createObjectStore(store);
			}
		};
		return new IndexedDbEntryStore(await done(request));
	}

	async get(path: string): Promise<StoredEntry | undefined> {
		const tx = this.db.transaction(ENTRIES, "readonly");
		return (await done(tx.objectStore(ENTRIES).get(path))) as StoredEntry | undefined;
	}

	/** Replaces the entry and drops the previous one's chunks, in one transaction. */
	async put(path: string, entry: StoredEntry): Promise<void> {
		const tx = this.db.transaction([ENTRIES, INFO, CHUNKS], "readwrite");
		const old = tx.objectStore(INFO).get(path);
		old.onsuccess = () => {
			const previous = old.result as StoredInfo | undefined;
			const next = info(entry);
			if (previous?.id && previous.id !== next.id) tx.objectStore(CHUNKS).delete(chunksOf(previous.id));
			tx.objectStore(ENTRIES).put(entry, path);
			tx.objectStore(INFO).put(next, path);
		};
		await committed(tx);
	}

	async delete(path: string): Promise<void> {
		const tx = this.db.transaction([ENTRIES, INFO, CHUNKS], "readwrite");
		const old = tx.objectStore(INFO).get(path);
		old.onsuccess = () => {
			const previous = old.result as StoredInfo | undefined;
			if (previous?.id) tx.objectStore(CHUNKS).delete(chunksOf(previous.id));
			tx.objectStore(ENTRIES).delete(path);
			tx.objectStore(INFO).delete(path);
		};
		await committed(tx);
	}

	async getChunk(id: Uint8Array, index: number): Promise<SealedPiece | undefined> {
		const tx = this.db.transaction(CHUNKS, "readonly");
		return (await done(tx.objectStore(CHUNKS).get([hex(id), index]))) as SealedPiece | undefined;
	}

	/** One transaction per chunk, so a large file never sits whole in a transaction. */
	async putChunk(id: Uint8Array, index: number, piece: SealedPiece): Promise<void> {
		const tx = this.db.transaction(CHUNKS, "readwrite");
		tx.objectStore(CHUNKS).put(piece, [hex(id), index]);
		await committed(tx);
	}

	async deleteChunks(id: Uint8Array): Promise<void> {
		const tx = this.db.transaction(CHUNKS, "readwrite");
		tx.objectStore(CHUNKS).delete(chunksOf(hex(id)));
		await committed(tx);
	}

	async chunkIds(): Promise<Set<string>> {
		const tx = this.db.transaction(CHUNKS, "readonly");
		const keys = await done(tx.objectStore(CHUNKS).getAllKeys());
		return new Set(keys.map((k) => (k as [string, number])[0]));
	}

	async infos(): Promise<Map<string, StoredInfo>> {
		const store = this.db.transaction(INFO, "readonly").objectStore(INFO);
		const [keys, values] = await Promise.all([done(store.getAllKeys()), done(store.getAll())]);
		return new Map(keys.map((k, i) => [k as string, values[i] as StoredInfo]));
	}

	close(): void {
		this.db.close();
	}
}

/** Delete a whole database. Resolves once it is gone, or blocked by a connection left open. */
export function deleteDatabase(name: string, factory: IDBFactory = indexedDB): Promise<void> {
	return new Promise((resolve, reject) => {
		const request = factory.deleteDatabase(name);
		request.onsuccess = () => resolve();
		request.onblocked = () => resolve();
		request.onerror = () => reject(request.error ?? new Error("IndexedDB delete failed"));
	});
}
