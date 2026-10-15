/**
 * The sync engine (docs/architecture.md 4.2): pull the change feed, scan local files, push
 * the outbox, merge when both sides changed, and re-encrypt files after a key rotation.
 */
import type { ApiClient, Revision } from "../api/client";
import { ApiError, NetworkError } from "../api/http";
import { KeyringError } from "../crypto/keyring";
import { ObjectError, type FileMeta } from "../crypto/objects";
import { countFiles, type OutboxEntry, type SyncedFile, type SyncStore } from "../store/state";
import { sha256Hex, type VaultCipher } from "./cipher";
import { collect, hashFile, isMissingContent, writeChunked, type FileStat, type VaultFs } from "./fs";
import { conflictPath, mergeText } from "./merge";

export const CURSOR = "cursor";
/** Remote revisions held back until the end of a pull, kept across restarts. */
export const DEFERRED = "deferred";
/** Remote revisions that couldn't be written here (store meta key), tried again on every pull. */
export const FAILED = "failed";
/** How often one sync pushes again after merges queued new changes. */
const MAX_PUSH_ROUNDS = 5;
/** Statuses that refuse one file's upload, not the whole sync. */
const REFUSED = new Set([400, 413, 422]);
/** Waits before each retry of a chunk download that failed to reach the server. */
const BLOB_RETRIES_MS = [1000, 4000];

export interface EngineOptions {
	api: ApiClient;
	vaultId: string;
	cipher: VaultCipher;
	fs: VaultFs;
	store: SyncStore;
	/** This device's id, recorded in every revision's metadata. */
	deviceId: string;
	/** Used in conflict-copy names. */
	deviceName: string;
	/** True for paths that are synced. */
	include: (path: string) => boolean;
	/**
	 * `app.vault.configDir`. Its `community-plugins.json` is written after everything else a
	 * pull brings, so plugins are in place before they are turned on, and the report says
	 * when the folder changed (Obsidian must reload to use it).
	 */
	configDir?: string;
	/**
	 * The keyring this device has. The change feed carries the server's keyring version, and
	 * a newer one is fetched and checked before any change is applied (crypto.md 8.4).
	 */
	keyring?: { version(): number; refresh(): Promise<void> };
	now?: () => Date;
	/** Called for problems that skip one file but don't stop the sync. Never gets plaintext. */
	onWarning?: (message: string) => void;
	/** Called as a sync goes through the change feed, the local files and the outbox. */
	onProgress?: (progress: SyncProgress) => void;
	/** Waits before each retry of a chunk download (default 1 s, then 4 s). */
	blobRetriesMs?: number[];
}

/**
 * How far a sync is. `pull`: `done` revisions of the change feed read since cursor `since`,
 * the last one `rev` (revisions are numbered by the vault's `seq`), and `path` while that
 * revision's file is being received. `scan`: local files checked. `push`: queued paths
 * committed in this round.
 */
export type SyncProgress =
	| { phase: "pull"; done: number; since: number; rev: number; path?: string }
	| { phase: "scan" | "push"; done: number; total: number };

export interface SyncReport {
	pulled: number;
	pushed: number;
	merged: number;
	conflicts: string[];
	/** Remote revisions that failed their integrity checks and were skipped. */
	rejected: number;
	/** Files committed again under the current epoch after a rotation. */
	reencrypted: number;
	/** Whether a remote change was written to the active config folder. */
	configChanged: boolean;
	/** Other plugins whose code (`main.js`) a remote change wrote: it runs after a reload. */
	pluginCode: PluginCodeChange[];
}

export interface PluginCodeChange {
	/** The plugin's folder name under `plugins/`. */
	plugin: string;
	/** The id of the device that wrote it, from the revision's encrypted metadata. */
	device: string;
	/** New on this device, rather than an update of a plugin it had. */
	added: boolean;
}

/** One revision of a file, from its encrypted metadata. */
export interface HistoryEntry {
	rev: number;
	/** When the server stored it. Not authenticated, only for display. */
	createdAt: string;
	deleted: boolean;
	/** Plaintext size in bytes. */
	size: number;
	mtime: number;
	/** The id of the device that wrote it. */
	device: string;
}

export interface HistoryPage {
	/** Newest first. */
	entries: HistoryEntry[];
	/** Pass as `before` to get the next, older page. Unset on the last page. */
	next?: number;
	/** Revisions that failed their integrity checks and were left out. */
	rejected: number;
}

interface LocalFile {
	exists: boolean;
	stat: FileStat | null;
	/** Set when the file exists, unless its content is missing. */
	data?: Uint8Array;
	sha256: string;
	/** The file exists, but its content isn't on this device (`MissingContentError`). */
	missing?: boolean;
}

/** The device has no room left for the local store or the sync state: the sync stops. */
export class StorageFullError extends Error {
	constructor() {
		super("This device's storage for Obsidian is full. Free some space, or exclude large files on this device.");
		this.name = "StorageFullError";
	}
}

/** A quota error from IndexedDB, possibly wrapped by Obsidian's Vault on the way. */
function isQuotaError(e: unknown): boolean {
	return e instanceof Error && (e.name === "QuotaExceededError" || /quota/i.test(e.message));
}

/** The engine was closed while a sync was running. */
class SyncStopped extends Error {
	constructor() {
		super("Sync stopped.");
	}
}

function emptyReport(): SyncReport {
	return { pulled: 0, pushed: 0, merged: 0, conflicts: [], rejected: 0, reencrypted: 0, configChanged: false, pluginCode: [] };
}

export class SyncEngine {
	private running: Promise<SyncReport> | null = null;
	private again = false;
	private report = emptyReport();
	private closed = false;
	/** The pull's position, for the progress of the file being received. */
	private pulling = { done: 0, since: 0 };

	constructor(private readonly opts: EngineOptions) {}

	/**
	 * Stop for good: a running sync fails at its next write or commit. Called when the plugin
	 * disconnects or locks, so a sync still running can't commit what it reads after that.
	 */
	close(): void {
		this.closed = true;
	}

	private checkOpen(): void {
		if (this.closed) throw new SyncStopped();
	}

	/**
	 * Pull, scan, push. Calls made while a sync is running are folded into one more run
	 * after it, so changes made during a sync are never missed.
	 */
	sync(): Promise<SyncReport> {
		if (this.running) {
			this.again = true;
			return this.running;
		}
		this.running = (async () => {
			try {
				do {
					this.again = false;
					await this.pull();
					await this.scan();
					await this.push();
					await this.reencrypt();
				} while (this.again);
				return this.report;
			} finally {
				this.running = null;
				this.report = emptyReport();
			}
		})();
		return this.running;
	}

	/** How many files are in sync: those with a synced state that isn't a deletion. */
	async fileCount(): Promise<number> {
		return countFiles(this.opts.store);
	}

	/** How many local files are synced, before any sync has run. */
	async localFileCount(): Promise<number> {
		return (await this.opts.fs.list()).filter((file) => this.opts.include(file.path)).length;
	}

	/** Note a local change from a vault event. The next sync pushes it. */
	async noteChange(path: string): Promise<void> {
		if (this.opts.include(path)) await this.opts.store.enqueue(path);
	}

	/** The local changes waiting to be pushed, oldest first. Reads only the local store. */
	async pending(): Promise<OutboxEntry[]> {
		return this.opts.store.outbox();
	}

	/** The synced paths of these file ids, for showing other devices' locks. */
	async pathsOf(fileIds: Set<string>): Promise<Map<string, string>> {
		const paths = new Map<string, string>();
		for (const [path, file] of await this.opts.store.files()) if (fileIds.has(file.fileId)) paths.set(file.fileId, path);
		return paths;
	}

	/** Synced paths whose last revision is a deletion, sorted: the files that can be restored. */
	async deletedPaths(): Promise<string[]> {
		const paths: string[] = [];
		for (const [path, file] of await this.opts.store.files()) {
			if (file.deleted && this.opts.include(path)) paths.push(path);
		}
		return paths.sort();
	}

	/** One page of the revisions of `path`, newest first. */
	async history(path: string, before?: number): Promise<HistoryPage> {
		const { api, vaultId, cipher } = this.opts;
		const fileId = cipher.fileId(path);
		const page = await api.revisions(vaultId, fileId, before);
		const entries: HistoryEntry[] = [];
		let rejected = 0;
		for (const revision of page.revisions) {
			let meta: FileMeta;
			try {
				meta = cipher.openMeta(fileId, revision.meta);
			} catch {
				rejected++;
				continue;
			}
			entries.push({
				rev: revision.rev,
				createdAt: revision.createdAt,
				deleted: meta.deleted,
				size: meta.size,
				mtime: meta.mtime,
				device: meta.device,
			});
		}
		const result: HistoryPage = { entries, rejected };
		if (page.more) result.next = page.revisions.at(-1)!.rev;
		return result;
	}

	/** The content of revision `rev` of `path`, or null for a deletion. Throws if it fails its checks. */
	async readRevision(path: string, rev: number): Promise<Uint8Array | null> {
		try {
			return await this.content(this.opts.cipher.fileId(path), rev);
		} catch (e) {
			// The server prunes old revisions (protocol.md 9.3).
			if (e instanceof ApiError && e.status === 404) throw new Error("This version is no longer kept on the server.");
			throw e;
		}
	}

	/**
	 * Commit the content of revision `rev` as the new head of `path`. A sync runs first, so
	 * local edits are pushed and stay in the history.
	 */
	async restore(path: string, rev: number): Promise<void> {
		if (!this.opts.include(path)) throw new Error("This file isn't synced.");
		await this.sync();
		const data = await this.readRevision(path, rev);
		if (data === null) throw new Error("This revision is a deletion and can't be restored.");
		await this.opts.fs.write(path, data, { mtime: this.now().getTime() });
		await this.opts.store.enqueue(path);
		await this.sync();
	}

	/** Apply every remote change since the cursor. */
	async pull(): Promise<void> {
		const { api, vaultId, store } = this.opts;
		let cursor = (await store.getMeta<number>(CURSOR)) ?? 0;
		const deferred = (await store.getMeta<Revision[]>(DEFERRED)) ?? [];
		const earlier = (await store.getMeta<Revision[]>(FAILED)) ?? [];
		const failed: Revision[] = [];
		const since = cursor;
		let done = 0;
		this.pulling = { done, since };
		for (;;) {
			const page = await api.changes(vaultId, cursor);
			const keyring = this.opts.keyring;
			if (keyring && page.keyringVersion > keyring.version()) await keyring.refresh();
			for (const revision of page.changes) {
				await this.applyOrKeep(revision, failed, deferred);
				this.pulling.done = ++done;
				this.progress({ phase: "pull", done, since, rev: revision.rev });
			}
			// Saved before the cursor moves past them, so they aren't lost if the sync stops here.
			await store.setMeta(DEFERRED, deferred);
			await store.setMeta(FAILED, [...earlier, ...failed]);
			cursor = page.cursor;
			await store.setMeta(CURSOR, cursor);
			if (!page.more) break;
		}
		// After the feed: a newer revision of the same file makes an older failure moot.
		for (const revision of earlier) await this.applyOrKeep(revision, failed, undefined, false);
		await store.setMeta(FAILED, failed);
		if (deferred.length === 0) return;
		for (const revision of deferred) await this.applyOrKeep(revision, failed);
		await store.setMeta(DEFERRED, []);
		await store.setMeta(FAILED, failed);
	}

	/**
	 * Apply a remote revision. If writing it here fails (a name the file system refuses, or
	 * one that differs only in case from another file), keep it to try again on the next
	 * pull instead of stopping the sync, and warn the first time. A revision the server has
	 * pruned since (a 404 for it or its blobs, protocol.md 9.3) is replaced by the file's head,
	 * which is never pruned.
	 */
	private async applyOrKeep(revision: Revision, failed: Revision[], deferred?: Revision[], first = true): Promise<void> {
		let current = revision;
		try {
			try {
				await this.applyRemote(revision, deferred);
			} catch (e) {
				if (!(e instanceof ApiError) || e.status !== 404) throw e;
				const head = await this.opts.api.head(this.opts.vaultId, revision.fileId);
				if (head.rev === revision.rev) throw e;
				current = head;
				// Skipped by applyRemote unless newer than the synced revision.
				await this.applyRemote(head, deferred);
			}
		} catch (e) {
			if (e instanceof ApiError || e instanceof NetworkError || e instanceof SyncStopped) throw e;
			// Every later file would fail the same way: stop, and say why once.
			if (isQuotaError(e)) throw new StorageFullError();
			failed.push(current);
			if (first) {
				const reason = e instanceof Error && e.message ? `: ${e.message}` : "";
				this.warn(`Couldn't write a remote change here (revision ${current.rev})${reason}. It is tried again on every sync.`);
			}
		}
	}

	/** Queue every local difference from the last synced state (startup and fallback). */
	async scan(): Promise<void> {
		const { fs, store, include } = this.opts;
		const synced = await store.files();
		const present = new Set<string>();
		const files = (await fs.list()).filter((file) => include(file.path));
		let done = 0;
		let refetched = 0;
		for (const file of files) {
			this.progress({ phase: "scan", done: done++, total: files.length });
			present.add(file.path);
			const s = synced.get(file.path);
			if (s && !s.deleted && s.size === file.size && s.mtime === file.mtime) continue;
			const local = await this.local(file.path, false);
			if (local.missing) {
				// Never committed as a change: the stub isn't the file's content.
				if (s && !s.deleted && (await this.refetch(file.path, s))) refetched++;
				continue;
			}
			if (s && !s.deleted && local.sha256 === s.sha256) {
				// Touched but not changed: remember the new mtime so it isn't hashed again.
				await store.putFile(file.path, { ...s, mtime: file.mtime });
			} else {
				await store.enqueue(file.path);
			}
		}
		for (const [path, s] of synced) {
			if (!s.deleted && !present.has(path) && include(path)) await store.enqueue(path);
		}
		if (refetched > 0) {
			this.warn(`Downloaded ${refetched === 1 ? "1 file" : `${refetched} files`} again: the content was missing on this device.`);
		}
	}

	/**
	 * Write the head of a synced file whose content is missing here. Returns whether it did.
	 */
	private async refetch(path: string, synced: SyncedFile): Promise<boolean> {
		const { api, vaultId } = this.opts;
		let head: Revision;
		try {
			head = await api.head(vaultId, synced.fileId);
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) return false;
			throw e;
		}
		const meta = await this.openRemoteMeta(head);
		if (meta === null || meta.path !== path) return false;
		this.checkOpen();
		if (meta.deleted) {
			await this.opts.fs.remove(path);
			await this.record(path, head, meta, null);
			return true;
		}
		try {
			await this.writeRemote(path, head, meta, await this.download(head, meta));
		} catch (e) {
			if (!(e instanceof ObjectError)) throw e;
			return false;
		}
		return true;
	}

	/** Commit every queued path. A merge after a `409` queues the result for the next round. */
	async push(): Promise<void> {
		const { store } = this.opts;
		for (let round = 0; round < MAX_PUSH_ROUNDS; round++) {
			const entries = await store.outbox();
			if (entries.length === 0) return;
			let done = 0;
			for (const entry of entries) {
				this.progress({ phase: "push", done: done++, total: entries.length });
				try {
					await this.pushPath(entry.path);
				} catch (e) {
					// A request the server refuses for this file only: keep it queued, go on.
					if (!(e instanceof ApiError) || !REFUSED.has(e.status)) throw e;
					this.warn(`Couldn't upload a file (${e.code}). It stays queued.`);
					continue;
				}
				await store.dequeue(entry);
			}
		}
	}

	/**
	 * Background re-encryption (crypto.md 8.4): commit every live file whose synced head is
	 * from an older epoch again, unchanged, under the current one. Files with local changes
	 * are left to the outbox. A newer sync request stops it, and the next round goes on.
	 */
	private async reencrypt(): Promise<void> {
		const { cipher, store, include } = this.opts;
		const current = cipher.currentEpoch();
		for (const [path, file] of await store.files()) {
			if (this.again) return;
			if (file.deleted || (file.epoch ?? 1) >= current || !include(path)) continue;
			try {
				await this.pushPath(path, true);
			} catch (e) {
				if (!(e instanceof ApiError) || !REFUSED.has(e.status)) throw e;
				this.warn(`Couldn't re-encrypt a file (${e.code}).`);
			}
		}
	}

	/** With `again`, commit an unchanged file anyway (re-encryption); the content must match the head. */
	private async pushPath(path: string, again = false): Promise<void> {
		const { api, vaultId, cipher, store, include } = this.opts;
		if (!include(path)) return;
		const synced = await store.getFile(path);
		if (!again && synced && !synced.deleted && synced.mtime !== 0) {
			// Same size and time as synced (a file the pull just wrote): unchanged, as in the scan.
			const stat = await this.opts.fs.stat(path);
			if (stat && stat.size === synced.size && stat.mtime === synced.mtime) return;
			// Touched, maybe not changed: hash in chunks first, so an unchanged remote-only file
			// isn't read whole.
			if (this.opts.fs.hash) {
				const peek = await this.local(path, false);
				if (peek.missing) return;
				if (peek.exists && peek.sha256 === synced.sha256) {
					await store.putFile(path, { ...synced, mtime: peek.stat!.mtime });
					return;
				}
			}
		}
		const local = await this.local(path);
		// The scan downloads it again.
		if (local.missing) return;
		if (!local.exists && (!synced || synced.deleted)) return;
		const unchanged = local.exists && synced && !synced.deleted && local.sha256 === synced.sha256;
		if (again ? !unchanged : unchanged) return;

		const stat = local.stat;
		const now = this.now().getTime();
		const sealed = cipher.seal(
			path,
			local.exists ? local.data! : null,
			{ mtime: stat?.mtime ?? now, ctime: stat?.ctime ?? now },
			this.opts.deviceId,
		);
		const missing = new Set(await api.missingBlobs(vaultId, sealed.chunks.map((c) => c.id)));
		for (const chunk of sealed.chunks) {
			if (missing.has(chunk.id)) await api.putBlob(vaultId, chunk.id, chunk.object);
		}
		const fileId = cipher.fileId(path);
		let revision: Revision;
		this.checkOpen();
		try {
			revision = await api.commit(vaultId, fileId, {
				parentRev: synced?.rev ?? null,
				deleted: !local.exists,
				meta: sealed.meta,
				blobs: sealed.chunks.map((c) => c.id),
			});
		} catch (e) {
			if (e instanceof ApiError && e.code === "stale_parent") {
				const head = e.details["head"] as Revision | null | undefined;
				if (head) {
					await this.applyRemote(head);
				} else {
					// The file is gone on the server (it shouldn't be): commit it as new.
					await store.removeFile(path);
					await store.enqueue(path);
				}
				return;
			}
			throw e;
		}
		await store.putFile(path, {
			fileId,
			rev: revision.rev,
			deleted: !local.exists,
			sha256: local.exists ? sealed.sha256 : "",
			size: local.exists ? local.data!.length : 0,
			mtime: stat?.mtime ?? 0,
			epoch: cipher.epoch(sealed.meta),
		});
		if (again) this.report.reencrypted++;
		else this.report.pushed++;
	}

	/**
	 * Apply one remote revision: write it, merge it with local changes, or skip it. With
	 * `deferred`, a revision that must come last is added there instead.
	 */
	private async applyRemote(revision: Revision, deferred?: Revision[]): Promise<void> {
		const { store, include } = this.opts;
		const meta = await this.openRemoteMeta(revision);
		if (meta === null) {
			this.report.rejected++;
			this.warn(`Skipped a remote change that failed its integrity check (revision ${revision.rev}).`);
			return;
		}
		const path = meta.path;
		if (!include(path)) return;
		if (deferred && this.opts.configDir !== undefined && path === `${this.opts.configDir}/community-plugins.json`) {
			deferred.push(revision);
			return;
		}
		const synced = await store.getFile(path);
		if (synced && revision.rev <= synced.rev) return;
		this.checkOpen();
		this.progress({ phase: "pull", done: this.pulling.done, since: this.pulling.since, rev: revision.rev, path });
		// Always hashed: a stat that looks unchanged mustn't let a remote write replace an edit.
		const local = await this.local(path, false);
		// Content missing here: nothing to keep, the remote revision replaces the stub.
		const unchanged =
			local.missing ||
			(synced ? (synced.deleted ? !local.exists : local.exists && local.sha256 === synced.sha256) : !local.exists);
		this.report.pulled++;

		if (meta.deleted) {
			if (unchanged || !local.exists) {
				if (local.exists) {
					await this.opts.fs.remove(path);
					await this.noteWrite(path);
				}
				await this.record(path, revision, meta, null);
			} else {
				// Edited here, deleted there: keep the edit and commit it on top of the deletion.
				await this.record(path, revision, meta, null);
				await store.enqueue(path);
			}
			return;
		}

		if (local.exists && local.sha256 === meta.sha256) {
			await this.record(path, revision, meta, local.stat);
			return;
		}
		const rejected = (e: unknown): boolean => {
			if (!(e instanceof ObjectError)) return false;
			this.report.rejected++;
			this.warn(`Skipped a remote change whose content failed its integrity check (revision ${revision.rev}).`);
			return true;
		};
		// Deleted here but edited there: the edit wins. And a device's first sync: its own
		// defaults in the config folder give way to the vault's settings, without conflict copies.
		if (unchanged || !local.exists || (!synced && this.inConfig(path))) {
			// Streamed: received, checked and written one chunk at a time.
			try {
				await this.writeRemoteChunks(path, revision, meta);
			} catch (e) {
				if (!rejected(e)) throw e;
			}
			return;
		}
		let remote: Uint8Array;
		try {
			remote = await this.download(revision, meta);
		} catch (e) {
			if (!rejected(e)) throw e;
			return;
		}

		// Both sides changed.
		const localData = local.data ?? (await this.opts.fs.read(path));
		const base = synced && !synced.deleted ? await this.base(revision.fileId, synced.rev) : null;
		const merged = mergeText(path, base, localData, remote);
		if (merged !== null) {
			if (sha256Hex(merged) === meta.sha256) {
				await this.writeRemote(path, revision, meta, remote);
			} else {
				// The merge goes on top of the remote revision. No mtime is recorded, so the
				// next scan hashes the file instead of trusting its stat.
				await this.opts.fs.write(path, merged, { mtime: this.now().getTime() });
				await this.noteWrite(path, meta);
				await this.record(path, revision, meta, null);
				await store.enqueue(path);
			}
			this.report.merged++;
			return;
		}
		const files = new Set((await this.opts.fs.list()).map((f) => f.path));
		const copy = conflictPath(path, this.opts.deviceName, this.now(), (p) => files.has(p));
		await this.opts.fs.write(copy, localData, { mtime: this.now().getTime() });
		await store.enqueue(copy);
		await this.writeRemote(path, revision, meta, remote);
		this.report.conflicts.push(copy);
	}

	/**
	 * A revision's metadata, or null if it fails its checks. Under an epoch this keyring
	 * doesn't have, the keyring is refreshed once first; errors from that refresh stop the sync.
	 */
	private async openRemoteMeta(revision: Revision): Promise<FileMeta | null> {
		const { cipher, keyring } = this.opts;
		const open = (): FileMeta | KeyringError | null => {
			try {
				return cipher.openMeta(revision.fileId, revision.meta);
			} catch (e) {
				return e instanceof KeyringError ? e : null;
			}
		};
		let meta = open();
		if (meta instanceof KeyringError && keyring) {
			await keyring.refresh();
			meta = open();
		}
		return meta instanceof KeyringError ? null : meta;
	}

	private async writeRemote(path: string, revision: Revision, meta: FileMeta, data: Uint8Array): Promise<void> {
		this.checkOpen();
		await this.opts.fs.write(path, data, { mtime: meta.mtime, ctime: meta.ctime });
		await this.noteWrite(path, meta);
		await this.record(path, revision, meta, await this.opts.fs.stat(path));
	}

	/** Download and write a revision chunk by chunk. Throws `ObjectError` before writing if a check fails. */
	private async writeRemoteChunks(path: string, revision: Revision, meta: FileMeta): Promise<void> {
		this.checkOpen();
		const times = { mtime: meta.mtime, ctime: meta.ctime };
		await writeChunked(this.opts.fs, path, meta.size, meta.chunks.length, this.chunks(revision, meta), times);
		await this.noteWrite(path, meta);
		await this.record(path, revision, meta, await this.opts.fs.stat(path));
	}

	/** Remember `revision` as the synced state of `path`. */
	private async record(path: string, revision: Revision, meta: FileMeta, stat: FileStat | null): Promise<void> {
		const file: SyncedFile = {
			fileId: revision.fileId,
			rev: revision.rev,
			deleted: meta.deleted,
			sha256: meta.deleted ? "" : meta.sha256,
			size: meta.size,
			mtime: stat?.mtime ?? 0,
			epoch: this.opts.cipher.epoch(revision.meta),
		};
		await this.opts.store.putFile(path, file);
	}

	private async download(revision: Revision, meta: FileMeta): Promise<Uint8Array> {
		return collect(meta.size, this.chunks(revision, meta));
	}

	/**
	 * A revision's plaintext, one chunk at a time. Each chunk is checked as it comes, and the
	 * file's hash after the last one: the generator throws `ObjectError` instead of finishing.
	 */
	private async *chunks(revision: Revision, meta: FileMeta): AsyncGenerator<Uint8Array> {
		const opener = this.opts.cipher.contentOpener(revision.fileId, meta);
		for (const [i, chunk] of meta.chunks.entries()) {
			this.checkOpen();
			yield opener.open(i, await this.blob(chunk.id));
		}
		opener.finish();
	}

	/** One blob, tried again after a short wait when the server can't be reached. */
	private async blob(id: string): Promise<Uint8Array> {
		const { api, vaultId } = this.opts;
		const waits = this.opts.blobRetriesMs ?? BLOB_RETRIES_MS;
		for (let attempt = 0; ; attempt++) {
			try {
				return await api.getBlob(vaultId, id);
			} catch (e) {
				if (!(e instanceof NetworkError) || attempt >= waits.length) throw e;
				await new Promise((resolve) => window.setTimeout(resolve, waits[attempt]));
				this.checkOpen();
			}
		}
	}

	/** The content of a revision, or null for a deletion. */
	private async content(fileId: string, rev: number): Promise<Uint8Array | null> {
		const revision = await this.opts.api.revision(this.opts.vaultId, fileId, rev);
		const meta = this.opts.cipher.openMeta(fileId, revision.meta);
		return meta.deleted ? null : this.download(revision, meta);
	}

	/** The content of an earlier revision, as the merge base. Null if it can't be read. */
	private async base(fileId: string, rev: number): Promise<Uint8Array | null> {
		try {
			return await this.content(fileId, rev);
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) return null;
			throw e;
		}
	}

	/**
	 * The local state of `path`, and its content unless `withData` is false. Without it, a
	 * file system that can hash in chunks (a remote-only device) never reads the file whole.
	 */
	private async local(path: string, withData = true): Promise<LocalFile> {
		const stat = await this.opts.fs.stat(path);
		if (!stat) return { exists: false, stat: null, sha256: "" };
		try {
			if (!withData && this.opts.fs.hash) {
				return { exists: true, stat, sha256: await hashFile(this.opts.fs, path, sha256Hex) };
			}
			const data = await this.opts.fs.read(path);
			return { exists: true, stat, data, sha256: sha256Hex(data) };
		} catch (e) {
			if (!isMissingContent(e)) throw e;
			return { exists: true, stat, sha256: "", missing: true };
		}
	}

	private inConfig(path: string): boolean {
		return this.opts.configDir !== undefined && path.startsWith(`${this.opts.configDir}/`);
	}

	/** Called before `record`, so the store still has what this device had before. */
	private async noteWrite(path: string, written?: FileMeta): Promise<void> {
		if (!this.inConfig(path)) return;
		this.report.configChanged = true;
		const [, folder, plugin, name, ...rest] = path.split("/");
		if (!written || folder !== "plugins" || name !== "main.js" || rest.length > 0 || plugin === undefined) return;
		if (this.report.pluginCode.some((c) => c.plugin === plugin)) return;
		const before = await this.opts.store.getFile(path);
		this.report.pluginCode.push({ plugin, device: written.device, added: !before || before.deleted });
	}

	private now(): Date {
		return this.opts.now?.() ?? new Date();
	}

	private warn(message: string): void {
		this.opts.onWarning?.(message);
	}

	private progress(progress: SyncProgress): void {
		this.opts.onProgress?.(progress);
	}
}
