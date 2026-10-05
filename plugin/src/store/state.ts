/** Local sync state (docs/architecture.md 4.1), behind an interface so tests can use memory. */

/** The last synced state of one path. */
export interface SyncedFile {
	fileId: string;
	/** The revision this path was last synced at: the `parentRev` of the next commit. */
	rev: number;
	deleted: boolean;
	/** Hex SHA-256 of the plaintext ("" for a deletion). */
	sha256: string;
	size: number;
	/** Local `mtime` after the last sync, to skip hashing unchanged files. */
	mtime: number;
	/** The key epoch of that revision. Absent in state from before rotation existed: epoch 1. */
	epoch?: number;
}

/** A path with local changes to push. What to push is decided when it is pushed. */
export interface OutboxEntry {
	path: string;
	/** Changes on every enqueue, so a push only removes the entry it pushed. */
	id: string;
	queuedAt: number;
}

export interface SyncStore {
	getMeta<T>(key: string): Promise<T | undefined>;
	setMeta(key: string, value: unknown): Promise<void>;
	getFile(path: string): Promise<SyncedFile | undefined>;
	putFile(path: string, file: SyncedFile): Promise<void>;
	removeFile(path: string): Promise<void>;
	files(): Promise<Map<string, SyncedFile>>;
	/** Add `path` to the outbox, or refresh its entry. */
	enqueue(path: string): Promise<void>;
	/** Oldest first. */
	outbox(): Promise<OutboxEntry[]>;
	/** Remove `entry`, unless the path was queued again since it was read. */
	dequeue(entry: OutboxEntry): Promise<void>;
	/** Forget everything, e.g. when the vault was recreated on the server. */
	clear(): Promise<void>;
	close(): void;
}

export function newOutboxEntry(path: string): OutboxEntry {
	return { path, id: crypto.randomUUID(), queuedAt: Date.now() };
}

export class MemoryStore implements SyncStore {
	private readonly meta = new Map<string, unknown>();
	private readonly synced = new Map<string, SyncedFile>();
	private readonly queue = new Map<string, OutboxEntry>();

	async getMeta<T>(key: string): Promise<T | undefined> {
		return structuredClone(this.meta.get(key)) as T | undefined;
	}
	async setMeta(key: string, value: unknown): Promise<void> {
		this.meta.set(key, structuredClone(value));
	}
	async getFile(path: string): Promise<SyncedFile | undefined> {
		const f = this.synced.get(path);
		return f && { ...f };
	}
	async putFile(path: string, file: SyncedFile): Promise<void> {
		this.synced.set(path, { ...file });
	}
	async removeFile(path: string): Promise<void> {
		this.synced.delete(path);
	}
	async files(): Promise<Map<string, SyncedFile>> {
		return new Map([...this.synced].map(([p, f]) => [p, { ...f }]));
	}
	async enqueue(path: string): Promise<void> {
		const previous = this.queue.get(path);
		const entry = newOutboxEntry(path);
		if (previous) entry.queuedAt = previous.queuedAt;
		this.queue.set(path, entry);
	}
	async outbox(): Promise<OutboxEntry[]> {
		return [...this.queue.values()].sort((a, b) => a.queuedAt - b.queuedAt).map((e) => ({ ...e }));
	}
	async dequeue(entry: OutboxEntry): Promise<void> {
		if (this.queue.get(entry.path)?.id === entry.id) this.queue.delete(entry.path);
	}
	async clear(): Promise<void> {
		this.meta.clear();
		this.synced.clear();
		this.queue.clear();
	}
	close(): void {}
}
