/** `SyncStore` on IndexedDB, available on desktop and mobile. */
import { newOutboxEntry, type OutboxEntry, type SyncedFile, type SyncStore } from "./state";

const VERSION = 1;
const META = "meta";
const FILES = "files";
const OUTBOX = "outbox";
const STORES = [META, FILES, OUTBOX];

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

export class IndexedDbStore implements SyncStore {
	private constructor(private readonly db: IDBDatabase) {}

	/** One database per local vault, server and remote vault (see `storeName`). */
	static async open(name: string, factory: IDBFactory = indexedDB): Promise<IndexedDbStore> {
		const request = factory.open(name, VERSION);
		request.onupgradeneeded = () => {
			for (const store of STORES) {
				if (!request.result.objectStoreNames.contains(store)) request.result.createObjectStore(store);
			}
		};
		return new IndexedDbStore(await done(request));
	}

	private async read<T>(store: string, key: string): Promise<T | undefined> {
		const tx = this.db.transaction(store, "readonly");
		return (await done(tx.objectStore(store).get(key))) as T | undefined;
	}

	private async write(store: string, fn: (s: IDBObjectStore) => void): Promise<void> {
		const tx = this.db.transaction(store, "readwrite");
		fn(tx.objectStore(store));
		await committed(tx);
	}

	getMeta<T>(key: string): Promise<T | undefined> {
		return this.read<T>(META, key);
	}
	setMeta(key: string, value: unknown): Promise<void> {
		return this.write(META, (s) => s.put(value, key));
	}
	getFile(path: string): Promise<SyncedFile | undefined> {
		return this.read<SyncedFile>(FILES, path);
	}
	putFile(path: string, file: SyncedFile): Promise<void> {
		return this.write(FILES, (s) => s.put(file, path));
	}
	removeFile(path: string): Promise<void> {
		return this.write(FILES, (s) => s.delete(path));
	}
	async files(): Promise<Map<string, SyncedFile>> {
		const tx = this.db.transaction(FILES, "readonly");
		const store = tx.objectStore(FILES);
		const [keys, values] = await Promise.all([done(store.getAllKeys()), done(store.getAll())]);
		return new Map(keys.map((k, i) => [k as string, values[i] as SyncedFile]));
	}

	async enqueue(path: string): Promise<void> {
		const tx = this.db.transaction(OUTBOX, "readwrite");
		const store = tx.objectStore(OUTBOX);
		const previous = (await done(store.get(path))) as OutboxEntry | undefined;
		const entry = newOutboxEntry(path);
		if (previous) entry.queuedAt = previous.queuedAt;
		store.put(entry, path);
		await committed(tx);
	}
	async outbox(): Promise<OutboxEntry[]> {
		const tx = this.db.transaction(OUTBOX, "readonly");
		const entries = (await done(tx.objectStore(OUTBOX).getAll())) as OutboxEntry[];
		return entries.sort((a, b) => a.queuedAt - b.queuedAt);
	}
	async dequeue(entry: OutboxEntry): Promise<void> {
		const tx = this.db.transaction(OUTBOX, "readwrite");
		const store = tx.objectStore(OUTBOX);
		const current = (await done(store.get(entry.path))) as OutboxEntry | undefined;
		if (current?.id === entry.id) store.delete(entry.path);
		await committed(tx);
	}

	async clear(): Promise<void> {
		const tx = this.db.transaction(STORES, "readwrite");
		for (const store of STORES) tx.objectStore(store).clear();
		await committed(tx);
	}

	close(): void {
		this.db.close();
	}
}
