/**
 * The sync engine (docs/architecture.md 4.2): pull the change feed, scan local files, push
 * the outbox, merge when both sides changed, and re-encrypt files after a key rotation.
 */
import type { ApiClient, Revision } from "../api/client";
import { ApiError, NetworkError } from "../api/http";
import { KeyringError } from "../crypto/keyring";
import { ObjectError, type FileMeta } from "../crypto/objects";
import type { SyncedFile, SyncStore } from "../store/state";
import { sha256Hex, type VaultCipher } from "./cipher";
import type { FileStat, VaultFs } from "./fs";
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
}

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
	/** Set when the file exists. */
	data?: Uint8Array;
	sha256: string;
}

function emptyReport(): SyncReport {
	return { pulled: 0, pushed: 0, merged: 0, conflicts: [], rejected: 0, reencrypted: 0, configChanged: false };
}

export class SyncEngine {
	private running: Promise<SyncReport> | null = null;
	private again = false;
	private report = emptyReport();

	constructor(private readonly opts: EngineOptions) {}

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
		let count = 0;
		for (const file of (await this.opts.store.files()).values()) if (!file.deleted) count++;
		return count;
	}

	/** Note a local change from a vault event. The next sync pushes it. */
	async noteChange(path: string): Promise<void> {
		if (this.opts.include(path)) await this.opts.store.enqueue(path);
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
	readRevision(path: string, rev: number): Promise<Uint8Array | null> {
		return this.content(this.opts.cipher.fileId(path), rev);
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
		for (;;) {
			const page = await api.changes(vaultId, cursor);
			const keyring = this.opts.keyring;
			if (keyring && page.keyringVersion > keyring.version()) await keyring.refresh();
			for (const revision of page.changes) await this.applyOrKeep(revision, failed, deferred);
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
	 * pull instead of stopping the sync, and warn the first time.
	 */
	private async applyOrKeep(revision: Revision, failed: Revision[], deferred?: Revision[], first = true): Promise<void> {
		try {
			await this.applyRemote(revision, deferred);
		} catch (e) {
			if (e instanceof ApiError || e instanceof NetworkError) throw e;
			failed.push(revision);
			if (first) {
				const reason = e instanceof Error && e.message ? `: ${e.message}` : "";
				this.warn(`Couldn't write a remote change here (revision ${revision.rev})${reason}. It is tried again on every sync.`);
			}
		}
	}

	/** Queue every local difference from the last synced state (startup and fallback). */
	async scan(): Promise<void> {
		const { fs, store, include } = this.opts;
		const synced = await store.files();
		const present = new Set<string>();
		for (const file of await fs.list()) {
			if (!include(file.path)) continue;
			present.add(file.path);
			const s = synced.get(file.path);
			if (s && !s.deleted && s.size === file.size && s.mtime === file.mtime) continue;
			const local = await this.local(file.path);
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
	}

	/** Commit every queued path. A merge after a `409` queues the result for the next round. */
	async push(): Promise<void> {
		const { store } = this.opts;
		for (let round = 0; round < MAX_PUSH_ROUNDS; round++) {
			const entries = await store.outbox();
			if (entries.length === 0) return;
			for (const entry of entries) {
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
		const local = await this.local(path);
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
		// Always hashed: a stat that looks unchanged mustn't let a remote write replace an edit.
		const local = await this.local(path);
		const unchanged = synced
			? synced.deleted
				? !local.exists
				: local.exists && local.sha256 === synced.sha256
			: !local.exists;
		this.report.pulled++;

		if (meta.deleted) {
			if (unchanged || !local.exists) {
				if (local.exists) {
					await this.opts.fs.remove(path);
					this.noteWrite(path);
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
		let remote: Uint8Array;
		try {
			remote = await this.download(revision, meta);
		} catch (e) {
			if (!(e instanceof ObjectError)) throw e;
			this.report.rejected++;
			this.warn(`Skipped a remote change whose content failed its integrity check (revision ${revision.rev}).`);
			return;
		}
		if (unchanged || !local.exists) {
			// Deleted here but edited there: the edit wins.
			await this.writeRemote(path, revision, meta, remote);
			return;
		}
		if (!synced && this.inConfig(path)) {
			// A device's first sync: its own defaults give way to the vault's settings, without
			// conflict copies in the config folder.
			await this.writeRemote(path, revision, meta, remote);
			return;
		}

		// Both sides changed.
		const localData = local.data!;
		const base = synced && !synced.deleted ? await this.base(revision.fileId, synced.rev) : null;
		const merged = mergeText(path, base, localData, remote);
		if (merged !== null) {
			if (sha256Hex(merged) === meta.sha256) {
				await this.writeRemote(path, revision, meta, remote);
			} else {
				// The merge goes on top of the remote revision. No mtime is recorded, so the
				// next scan hashes the file instead of trusting its stat.
				await this.opts.fs.write(path, merged, { mtime: this.now().getTime() });
				this.noteWrite(path);
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
		await this.opts.fs.write(path, data, { mtime: meta.mtime, ctime: meta.ctime });
		this.noteWrite(path);
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
		const { api, vaultId, cipher } = this.opts;
		const objects: Uint8Array[] = [];
		for (const chunk of meta.chunks) objects.push(await api.getBlob(vaultId, chunk.id));
		return cipher.openContent(revision.fileId, meta, objects);
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

	/** The local state and content of `path`. */
	private async local(path: string): Promise<LocalFile> {
		const stat = await this.opts.fs.stat(path);
		if (!stat) return { exists: false, stat: null, sha256: "" };
		const data = await this.opts.fs.read(path);
		return { exists: true, stat, data, sha256: sha256Hex(data) };
	}

	private inConfig(path: string): boolean {
		return this.opts.configDir !== undefined && path.startsWith(`${this.opts.configDir}/`);
	}

	private noteWrite(path: string): void {
		if (this.inConfig(path)) this.report.configChanged = true;
	}

	private now(): Date {
		return this.opts.now?.() ?? new Date();
	}

	private warn(message: string): void {
		this.opts.onWarning?.(message);
	}
}
