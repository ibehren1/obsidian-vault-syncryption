/**
 * The remote-only store (docs/remote-only.md 7) on IndexedDB: each file's content sealed
 * under the local key, and its size and times apart, so listing doesn't load the content.
 * A database of its own, so the wipe on removal can delete it whole.
 */
import type { EntryInfo, EntryStore, SealedEntry } from "../remote/stub-adapter";

const VERSION = 1;
const ENTRIES = "entries";
const INFO = "info";

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

export class IndexedDbEntryStore implements EntryStore {
	private constructor(private readonly db: IDBDatabase) {}

	static async open(name: string, factory: IDBFactory = indexedDB): Promise<IndexedDbEntryStore> {
		const request = factory.open(name, VERSION);
		request.onupgradeneeded = () => {
			for (const store of [ENTRIES, INFO]) {
				if (!request.result.objectStoreNames.contains(store)) request.result.createObjectStore(store);
			}
		};
		return new IndexedDbEntryStore(await done(request));
	}

	async get(path: string): Promise<SealedEntry | undefined> {
		const tx = this.db.transaction(ENTRIES, "readonly");
		return (await done(tx.objectStore(ENTRIES).get(path))) as SealedEntry | undefined;
	}

	async put(path: string, entry: SealedEntry): Promise<void> {
		const tx = this.db.transaction([ENTRIES, INFO], "readwrite");
		tx.objectStore(ENTRIES).put(entry, path);
		tx.objectStore(INFO).put({ size: entry.size, mtime: entry.mtime, ctime: entry.ctime } satisfies EntryInfo, path);
		await committed(tx);
	}

	async delete(path: string): Promise<void> {
		const tx = this.db.transaction([ENTRIES, INFO], "readwrite");
		tx.objectStore(ENTRIES).delete(path);
		tx.objectStore(INFO).delete(path);
		await committed(tx);
	}

	async infos(): Promise<Map<string, EntryInfo>> {
		const store = this.db.transaction(INFO, "readonly").objectStore(INFO);
		const [keys, values] = await Promise.all([done(store.getAllKeys()), done(store.getAll())]);
		return new Map(keys.map((k, i) => [k as string, values[i] as EntryInfo]));
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
