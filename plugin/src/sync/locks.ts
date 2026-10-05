/**
 * Soft lease locks (docs/protocol.md 11): this device holds a lock on the file open in the
 * active editor and renews it, and keeps the locks of other devices to warn about them.
 * Locks never block editing or a commit.
 */
import type { ApiClient, Lock } from "../api/client";
import { ApiError } from "../api/http";
import { toB64u } from "../crypto/bytes";
import type { VaultCipher } from "./cipher";

export const LOCK_TTL_S = 120;

/** A new installation id: 16 random bytes, base64url. */
export function newClientId(): string {
	return toB64u(crypto.getRandomValues(new Uint8Array(16)));
}

export interface LockOptions {
	api: ApiClient;
	vaultId: string;
	cipher: VaultCipher;
	deviceId: string;
	/** This installation, so installations that share a key see each other's locks. */
	clientId: string;
	ttl?: number;
	now?: () => number;
}

export class LockManager {
	private current: { path: string; fileId: string } | null = null;
	/** Other holders' locks, by `fileId`. */
	private others = new Map<string, Lock>();
	private seq = 0;

	constructor(private readonly opts: LockOptions) {}

	get ttl(): number {
		return this.opts.ttl ?? LOCK_TTL_S;
	}

	/** The path this device holds a lock on (or tries to), if any. */
	get held(): string | null {
		return this.current?.path ?? null;
	}

	/**
	 * Hold a lock on `path` instead of the current one (null releases it). Returns the other
	 * holder's lock if someone else is editing `path`.
	 */
	async hold(path: string | null): Promise<Lock | null> {
		if (path === this.current?.path) return this.renew();
		const previous = this.current;
		this.current = path === null ? null : { path, fileId: this.opts.cipher.fileId(path) };
		if (previous) await this.release(previous.fileId);
		return this.renew();
	}

	/** Acquire or renew the current lock. Called every `ttl / 2` seconds by the plugin. */
	async renew(): Promise<Lock | null> {
		const current = this.current;
		if (!current) return null;
		const { api, vaultId, clientId } = this.opts;
		try {
			await api.lock(vaultId, current.fileId, clientId, this.ttl);
			this.others.delete(current.fileId);
			return null;
		} catch (e) {
			if (!(e instanceof ApiError && e.code === "locked")) throw e;
			const lock = e.details["lock"] as Lock;
			this.others.set(current.fileId, lock);
			return lock;
		}
	}

	/** Fetch every lock in the vault. Returns true if the list changed. */
	async refresh(): Promise<boolean> {
		const { locks, locksSeq } = await this.opts.api.locks(this.opts.vaultId);
		const changed = locksSeq !== this.seq;
		this.seq = locksSeq;
		this.others = new Map(locks.filter((l) => !this.mine(l)).map((l) => [l.fileId, l]));
		return changed;
	}

	/** Another device's live lock on `path`, if any. */
	heldByOther(path: string): Lock | null {
		const lock = this.others.get(this.opts.cipher.fileId(path));
		if (!lock) return null;
		const now = this.opts.now?.() ?? Date.now();
		return Date.parse(lock.expiresAt) > now ? lock : null;
	}

	/** Release the current lock, for example when Obsidian goes to the background. */
	async releaseAll(): Promise<void> {
		const current = this.current;
		this.current = null;
		if (current) await this.release(current.fileId);
	}

	private async release(fileId: string): Promise<void> {
		await this.opts.api.unlock(this.opts.vaultId, fileId, this.opts.clientId);
	}

	private mine(lock: Lock): boolean {
		return lock.device === this.opts.deviceId && lock.clientId === this.opts.clientId;
	}
}
