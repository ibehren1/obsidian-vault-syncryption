/**
 * Live updates through long-poll (docs/protocol.md 10.2): wait until the vault, its locks or
 * its keyring change, then sync or refresh the locks, and wait again.
 */
import type { ApiClient } from "../api/client";
import { ApiError } from "../api/http";

const MIN_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 60_000;
/** Cap a server's `Retry-After`, so a wrong value can't stop live updates for long. */
const MAX_RETRY_AFTER_MS = 600_000;

export interface LiveOptions {
	api: ApiClient;
	vaultId: string;
	/** The change-feed cursor the engine has applied up to. */
	cursor(): Promise<number>;
	/** The keyring version this device has. A newer one on the server also triggers `onChanges`. */
	keyringVersion?(): number;
	/** Pull and push. Errors are the caller's to report; the loop backs off after them. */
	onChanges(): Promise<void>;
	onLocks(): Promise<void>;
	/** A failed wait, before the loop backs off. */
	onError?(e: unknown): void;
	/** Seconds per wait, at most 25. */
	timeout?: number;
	sleep?: (ms: number) => Promise<void>;
}

export class LiveLoop {
	private stopped = false;
	private running: Promise<void> | null = null;
	private locksSince = 0;
	private backoff = MIN_BACKOFF_MS;
	private woken: (() => void) | null = null;

	constructor(private readonly opts: LiveOptions) {}

	start(): void {
		this.running ??= this.run();
	}

	/**
	 * Stop after the current wait returns. A wait can't be cancelled, but its result is
	 * ignored, and the server ends the oldest wait when a device opens too many.
	 */
	stop(): Promise<void> {
		this.stopped = true;
		return this.running ?? Promise.resolve();
	}

	private async run(): Promise<void> {
		const { api, vaultId } = this.opts;
		while (!this.stopped) {
			try {
				const since = await this.opts.cursor();
				const keyring = this.opts.keyringVersion?.();
				const r = await api.wait(vaultId, since, this.locksSince, this.opts.timeout ?? 25, keyring);
				if (this.stopped) break;
				if (r.locksSeq > this.locksSince) {
					this.locksSince = r.locksSeq;
					await this.opts.onLocks();
				}
				if (r.seq > since || (keyring !== undefined && r.keyringVersion > keyring)) {
					await this.opts.onChanges();
					// The sync failed or didn't catch up: don't spin on the same answer.
					const behind = keyring !== undefined && this.opts.keyringVersion!() < r.keyringVersion;
					if ((await this.opts.cursor()) < r.seq || behind) await this.pause();
					else this.backoff = MIN_BACKOFF_MS;
				} else {
					this.backoff = MIN_BACKOFF_MS;
				}
			} catch (e) {
				if (this.stopped) break;
				this.opts.onError?.(e);
				// Maintenance (503) and rate limits say when to come back.
				const retryAfter = e instanceof ApiError && e.retryAfter !== undefined ? e.retryAfter * 1000 : 0;
				await this.pause(Math.min(retryAfter, MAX_RETRY_AFTER_MS));
			}
		}
	}

	/** End a backoff now, for example when the app comes back to the foreground. */
	wake(): void {
		this.woken?.();
	}

	/** Back off, for at least `minMs`. */
	private async pause(minMs = 0): Promise<void> {
		const sleep = this.opts.sleep ?? ((ms) => new Promise<void>((r) => window.setTimeout(r, ms)));
		let woken = false;
		const wake = new Promise<void>((resolve) => {
			this.woken = () => {
				woken = true;
				resolve();
			};
		});
		await Promise.race([sleep(Math.max(this.backoff, minMs)), wake]);
		this.woken = null;
		this.backoff = woken ? MIN_BACKOFF_MS : Math.min(this.backoff * 2, MAX_BACKOFF_MS);
	}
}
