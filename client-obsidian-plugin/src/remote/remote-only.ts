/**
 * Remote-only devices (docs/remote-only.md): the Obsidian wiring for `StubAdapter`, the
 * lease, the wipe on removal and the compliance report.
 *
 * The keyring decides whether this device is remote-only. A flag in local storage remembers
 * it between starts, so the wrapper is installed (locked) before the first connection: a
 * cold start offline stays locked, as the keyring and with it the local key are only in
 * memory.
 */
import { getLinkpath, MarkdownView, TFile, type App, type TAbstractFile } from "obsidian";

import type { ApiClient } from "../api/client";
import { deriveLocalKey } from "../crypto/kdf";
import { indexKey } from "../crypto/keyring";
import { deleteDatabase, IndexedDbEntryStore } from "../store/entries";
import type { HashMode, SealedHashStore } from "../store/sealed";
import { isHiddenPath } from "../sync/adapter-fs";
import type { VaultSession } from "../sync/session";
import { complianceReport, type ComplianceReport, type RemoteOnlyFlag } from "./compliance";
import { replaceStubUrl, StubAdapter } from "./stub-adapter";

/** Local storage: this device is remote-only for this vault (`RemoteOnlyFlag`). */
const FLAG = "syncryption-remote-only";

/** Undocumented: re-reads one file into the metadata cache. */
interface MetadataInternals {
	computeFileMetadataAsync?: (file: TFile) => Promise<void> | void;
}

/** Undocumented: the core plugins, here File Recovery. */
interface InternalPlugins {
	internalPlugins?: { getPluginById?(id: string): { enabled?: boolean } | null };
}

export class FileRecoveryError extends Error {
	constructor() {
		super(
			"This device is remote-only, and the File Recovery core plugin keeps plaintext copies of notes. Turn it off in Settings → Core plugins, then connect again.",
		);
	}
}

export class OtherVaultError extends Error {
	constructor() {
		super(
			"This Obsidian vault holds the remote-only files of another vault. Connect to that vault, or remove this device from it on another device.",
		);
	}
}

export interface RemoteOnlyOptions {
	installId(): string;
	/** Register a teardown with the plugin. */
	register(fn: () => void): void;
}

export class RemoteOnly {
	stub: StubAdapter | null = null;
	private entries: IndexedDbEntryStore | null = null;
	private uninstall: (() => void) | null = null;
	private key: Uint8Array | null = null;
	/** The client whose logins renew the lease. Kept after a disconnect: the lease runs on. */
	private api: ApiClient | null = null;

	constructor(
		private readonly app: App,
		private readonly opts: RemoteOnlyOptions,
	) {}

	get flag(): RemoteOnlyFlag | null {
		const flag = this.app.loadLocalStorage(FLAG) as RemoteOnlyFlag | null;
		return flag && typeof flag.vaultId === "string" ? flag : null;
	}

	private setFlag(flag: RemoteOnlyFlag | null): void {
		this.app.saveLocalStorage(FLAG, flag);
	}

	get unlocked(): boolean {
		return this.key !== null;
	}

	/** Called first in `onload`: Obsidian's reads go through the wrapper as early as possible. */
	async load(): Promise<void> {
		const flag = this.flag;
		if (flag) await this.install(flag.vaultId);
	}

	isRemote(path: string): boolean {
		const p = path.replace(/^\/+/, "");
		const configDir = this.app.vault.configDir;
		return p !== "" && !isHiddenPath(p) && p !== configDir && !p.startsWith(`${configDir}/`);
	}

	private entryDb(vaultId: string): string {
		return `syncryption-${this.opts.installId()}-${vaultId}-remote`;
	}

	private async install(vaultId: string): Promise<StubAdapter> {
		if (this.stub) return this.stub;
		const entries = await IndexedDbEntryStore.open(this.entryDb(vaultId));
		const stub = new StubAdapter({ isRemote: (p) => this.isRemote(p), store: entries, onResource: (p) => this.rerender(p) });
		await stub.load();
		this.uninstall = stub.install(this.app.vault.adapter);
		this.entries = entries;
		this.stub = stub;
		this.opts.register(() => this.teardown());
		return stub;
	}

	private teardown(): void {
		this.uninstall?.();
		this.uninstall = null;
		this.entries?.close();
		this.entries = null;
		this.stub = null;
		this.key = null;
	}

	/** How the sync state stores content hashes, for the store of `vaultId`. */
	hashMode(vaultId: string): HashMode {
		if (this.flag?.vaultId !== vaultId) return "plain";
		return this.key ?? "locked";
	}

	fileRecoveryEnabled(): boolean {
		return (this.app as App & InternalPlugins).internalPlugins?.getPluginById?.("file-recovery")?.enabled === true;
	}

	/**
	 * After connecting: follow this device's policy in the keyring. Becoming remote-only seals
	 * the content hashes and turns every file into a stub; becoming a full device again puts
	 * the files back on disk. Throws when sync must not start.
	 */
	async apply(session: VaultSession, store: SealedHashStore): Promise<"remote-only" | "full" | "restored"> {
		const flag = this.flag;
		const vaultId = session.vault.id;
		if (flag && flag.vaultId !== vaultId) throw new OtherVaultError();
		const key = deriveLocalKey(indexKey(session.keyring));
		if (!session.remoteOnly) {
			if (!flag) return "full";
			await this.restoreAll(vaultId, key, store);
			return "restored";
		}
		if (this.fileRecoveryEnabled()) {
			this.lock();
			throw new FileRecoveryError();
		}
		const stub = await this.install(vaultId);
		stub.unlock(key);
		this.key = key;
		this.api = session.api;
		// The store is this device's only copy: ask the browser not to evict it under storage
		// pressure. It may refuse, which changes nothing else.
		void navigator.storage?.persist?.().catch(() => false);
		this.setFlag({ vaultId });
		await store.sealAll(key);
		// Only a full device's empty files are empty notes. Later, an empty file without its
		// content in the store is a stub: the sync downloads it again.
		for (const file of this.remoteFiles()) {
			if (((await stub.diskSize(file.path)) ?? 0) > 0 || !stub.info(file.path)) await stub.convert(file.path, !flag);
		}
		await this.reindex();
		return "remote-only";
	}

	/** Back to a full device: every file back on disk, the hashes opened, the store deleted. */
	private async restoreAll(vaultId: string, key: Uint8Array, store: SealedHashStore): Promise<void> {
		const stub = await this.install(vaultId);
		stub.unlock(key);
		const left = await stub.restoreAll();
		// The store is deleted next: never while it holds the only copy of a file.
		if (left.length) throw new Error(`${left.length} remote-only files couldn't be put back on disk. Connect again to retry.`);
		await store.openAll(key);
		this.teardown();
		await deleteDatabase(this.entryDb(vaultId));
		this.setFlag(null);
		this.api = null;
	}

	/** Drop the local key and every decrypted resource. Reads of remote-only files fail. */
	lock(): void {
		this.key = null;
		this.stub?.lock();
	}

	/** The lease, from the last login of the last connection. */
	lease(): { at: number; graceSeconds: number } | null {
		const login = this.api?.lastLogin;
		return login ? { at: login.at, graceSeconds: login.graceSeconds } : null;
	}

	/** Whether the files are unlocked past the grace period (remote-only.md 5). */
	leaseExpired(now = Date.now()): boolean {
		if (!this.unlocked) return false;
		const lease = this.lease();
		return lease === null || now - lease.at > lease.graceSeconds * 1000;
	}

	/** A file was created or changed on disk outside the wrapper: move its content into the store. */
	async noteDiskChange(file: TAbstractFile): Promise<void> {
		const stub = this.stub;
		if (!stub || !this.unlocked || !(file instanceof TFile) || !this.isRemote(file.path)) return;
		if (((await stub.diskSize(file.path)) ?? 0) > 0) await stub.convert(file.path);
	}

	/**
	 * The device was removed from the vault (remote-only.md 5): delete every remote-only file
	 * and both databases of the vault. Only the plugin's own state is touched: `configDir`
	 * stays.
	 */
	async wipe(): Promise<void> {
		const flag = this.flag;
		if (!flag) return;
		this.lock();
		for (const child of [...this.app.vault.getRoot().children]) {
			if (!this.isRemote(child.path)) continue;
			try {
				// Deleted through the adapter, not trashed: the wipe leaves nothing behind.
				const adapter = this.app.vault.adapter;
				if (child instanceof TFile) await adapter.remove(child.path);
				else await adapter.rmdir(child.path, true);
			} catch {
				// Gone already, or the adapter refused: the stubs are empty either way.
			}
		}
		this.teardown();
		this.api = null;
		await deleteDatabase(this.entryDb(flag.vaultId)).catch(() => {});
		await deleteDatabase(`syncryption-${this.opts.installId()}-${flag.vaultId}`).catch(() => {});
		this.setFlag(null);
	}

	private remoteFiles(): TFile[] {
		return this.app.vault.getFiles().filter((f) => this.isRemote(f.path));
	}

	/** What the compliance report shows. `session`: the connection, if any. */
	async report(session: VaultSession | null, store: SealedHashStore | null): Promise<ComplianceReport> {
		const stub = this.stub;
		const files = this.remoteFiles();
		const plaintext: string[] = [];
		let missing = 0;
		if (stub) {
			for (const file of files) {
				if (((await stub.diskSize(file.path)) ?? 0) > 0) plaintext.push(file.path);
				else if (!stub.info(file.path)) missing++;
			}
		} else if (this.flag) {
			for (const file of files) if (file.stat.size > 0) plaintext.push(file.path);
		}
		const paths = new Set(files.map((f) => f.path));
		const stored = stub?.paths() ?? [];
		return complianceReport({
			keyringRemoteOnly: session ? session.remoteOnly : null,
			flag: this.flag,
			installed: stub !== null,
			locked: !this.unlocked,
			lease: this.lease(),
			now: Date.now(),
			remoteFiles: files.length,
			plaintext,
			storeEntries: stored.length,
			orphans: stored.filter((p) => !paths.has(p)).length,
			missing,
			fileRecovery: this.fileRecoveryEnabled(),
			plainHashes: store && this.flag ? await store.plainHashes() : null,
		});
	}

	/** Notes indexed from their empty stub are read again through the wrapper. */
	private async reindex(): Promise<void> {
		const cache = this.app.metadataCache as typeof this.app.metadataCache & MetadataInternals;
		for (const file of this.remoteFiles()) {
			if (file.extension !== "md" || !this.stub?.info(file.path)) continue;
			if (cache.getFileCache(file)?.sections?.length) continue;
			await cache.computeFileMetadataAsync?.(file);
		}
	}

	/** Decrypt the opened note's embeds before they render. */
	async warmEmbeds(file: TFile | null): Promise<void> {
		const stub = this.stub;
		if (!file || !stub || !this.unlocked) return;
		for (const embed of this.app.metadataCache.getFileCache(file)?.embeds ?? []) {
			const target = this.app.metadataCache.getFirstLinkpathDest(getLinkpath(embed.link), file.path);
			if (target && this.isRemote(target.path)) await stub.warm(target.path);
		}
	}

	/**
	 * A resource was decrypted after it was first asked for: show it where the stub's URL was
	 * rendered. Reading view renders again; Live Preview keeps its rendered embeds, so their
	 * elements get the new URL directly.
	 */
	private rerender(path: string): void {
		const stub = this.stub;
		const url = stub?.resourceUrl(path);
		const file = this.app.vault.getFileByPath(path);
		if (file) this.app.vault.trigger("modify", file);
		this.app.workspace.iterateAllLeaves((leaf) => {
			if (leaf.view instanceof MarkdownView && leaf.view.getMode() === "preview") {
				leaf.view.previewMode.rerender(true);
			} else if (stub && url) {
				replaceStubUrl(Array.from(leaf.view.containerEl.querySelectorAll("img, video, audio")), stub.stubUrl(path), url);
			}
		});
	}
}
