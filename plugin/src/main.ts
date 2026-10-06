import { debounce, Notice, Plugin, requireApiVersion, TAbstractFile, TFile, type EventRef, type Vault } from "obsidian";

import { ApiClient } from "./api/client";
import { disabledText, isDisabled, isMaintenance, maintenanceText, NetworkError } from "./api/http";
import { hasSecretStorage, MIN_APP_VERSION } from "./compat";
import { generateRecoveryKey } from "./crypto/keyring";
import type { OpenSshKey } from "./crypto/openssh";
import { loadKeyText, unlockKey } from "./keys";
import { requestUrlTransport } from "./obsidian/transport";
import { ObsidianFs } from "./obsidian/fs";
import { DEFAULT_SETTINGS, initialDeviceName, isConfigured, SyncryptionSettingTab, type SyncryptionSettings } from "./settings";
import { IndexedDbStore } from "./store/idb";
import { AdapterFs, isHiddenPath, SplitFs } from "./sync/adapter-fs";
import { VaultCipher } from "./sync/cipher";
import { CURSOR, SyncEngine, type SyncReport } from "./sync/engine";
import { parseExcludes, pathFilter, type PathFilter } from "./sync/filter";
import { LiveLoop } from "./sync/live";
import { LockManager, newClientId } from "./sync/locks";
import { isMergeable } from "./sync/merge";
import { connect, SetupCancelled, type VaultSession } from "./sync/session";
import { DeletedFilesModal, HistoryModal, type HistorySource } from "./ui/history";
import { ApproveModal, ConfirmModal, PairingModal, prompt, ReloadModal, type PendingApproval } from "./ui/modals";
import { showRecoveryKey } from "./ui/recovery";

/** Long-poll brings remote changes; the timer is a fallback. Local changes sync soon after. */
const SYNC_INTERVAL_MS = 120_000;
const CHANGE_DELAY_MS = 2_000;
const INSTALL_ID = "syncryption-install-id";
const CLIENT_ID = "syncryption-client-id";
/** Store meta: the recovery key was offered after creating the vault. */
const RECOVERY_OFFERED = "recoveryOffered";
/** Maintenance: retry after the server's `Retry-After`, within these bounds (seconds). */
const MAINTENANCE_RETRY_S = { default: 60, min: 5, max: 600 };

type State = "off" | "connecting" | "idle" | "syncing" | "offline" | "maintenance" | "error";

/** Undocumented: fired for every change on disk, including the hidden config folder. */
interface RawEvents {
	on(name: "raw", callback: (path: string) => void): EventRef;
}

/** Undocumented: runs a command by id, here `app:reload`. */
interface Commands {
	commands?: { executeCommandById(id: string): boolean };
}

export default class SyncryptionPlugin extends Plugin {
	override settings: SyncryptionSettings = { ...DEFAULT_SETTINGS };
	private key: OpenSshKey | null = null;
	private session: VaultSession | null = null;
	private engine: SyncEngine | null = null;
	private abort: AbortController | null = null;
	private state: State = "off";
	private detail = "";
	private lastSync: Date | null = null;
	private lastReport: SyncReport | null = null;
	private fileCount: number | null = null;
	private lastError = "";
	private statusBar: HTMLElement | null = null;
	private announced = new Set<string>();
	private include: PathFilter | null = null;
	private reloadAsked = false;
	private locks: LockManager | null = null;
	private live: LiveLoop | null = null;
	private lockBar: HTMLElement | null = null;
	/** The path last warned about, so reopening the same note doesn't warn again. */
	private warnedLock: string | null = null;
	/** The retry while the server is in maintenance, and when it is due. */
	private retryTimer = 0;
	private retryAt = 0;
	/** The maintenance notice was shown: once per maintenance period, not on every retry. */
	private maintenanceNoticed = false;
	private readonly scheduleSync = debounce(
		() => {
			if (!this.paused()) void this.syncNow();
		},
		CHANGE_DELAY_MS,
		true,
	);

	override async onload(): Promise<void> {
		if (!requireApiVersion(MIN_APP_VERSION) || !hasSecretStorage(this.app)) {
			new Notice(`Vault Syncryption needs Obsidian ${MIN_APP_VERSION} or later. Please update Obsidian.`);
			return;
		}
		await this.loadSettings();
		this.addSettingTab(new SyncryptionSettingTab(this.app, this));
		this.statusBar = this.addStatusBarItem();
		this.lockBar = this.addStatusBarItem();
		this.render();
		this.register(() => window.clearTimeout(this.retryTimer));

		this.addCommand({ id: "sync-now", name: "Sync now", callback: () => void this.syncNow(true) });
		this.addCommand({ id: "connect", name: "Connect again", callback: () => void this.restart() });
		// The status bar isn't shown on mobile.
		this.addCommand({ id: "status", name: "Show sync status", callback: () => new Notice(this.statusText(), 8000) });
		this.addCommand({ id: "approve-devices", name: "Approve devices", callback: () => void this.openApprovals() });
		this.addCommand({
			id: "file-history",
			name: "Show file history",
			checkCallback: (checking) => {
				const file = this.app.workspace.getActiveFile();
				if (!file || !this.filter()(file.path)) return false;
				if (!checking) this.openHistory(file.path);
				return true;
			},
		});
		this.addCommand({ id: "restore-deleted", name: "Restore a deleted file", callback: () => void this.openDeleted() });
		this.registerEvent(
			this.app.workspace.on("file-menu", (menu, file) => {
				if (!(file instanceof TFile) || !this.filter()(file.path)) return;
				menu.addItem((item) =>
					item
						.setTitle("Sync history")
						.setIcon("history")
						.onClick(() => this.openHistory(file.path)),
				);
			}),
		);

		this.app.workspace.onLayoutReady(() => {
			// Registered after the vault has loaded, so the initial `create` events are skipped.
			const changed = (file: TAbstractFile) => {
				if (file instanceof TFile) this.noteChange(file.path);
			};
			this.registerEvent(this.app.vault.on("create", changed));
			this.registerEvent(this.app.vault.on("modify", changed));
			this.registerEvent(this.app.vault.on("delete", changed));
			this.registerEvent(
				this.app.vault.on("rename", (file, oldPath) => {
					changed(file);
					if (file instanceof TFile) this.noteChange(oldPath);
				}),
			);
			// The Vault API doesn't see hidden folders: the raw event covers the config folders.
			this.registerEvent(
				(this.app.vault as Vault & RawEvents).on("raw", (path) => {
					if (isHiddenPath(path)) this.noteChange(path.replace(/^\/+/, ""));
				}),
			);
			this.registerInterval(window.setInterval(() => this.tick(), SYNC_INTERVAL_MS));
			this.registerEvent(this.app.workspace.on("file-open", () => void this.holdActive()));
			// Mobile apps are suspended in the background: let the lock go instead of letting it expire.
			this.registerDomEvent(document, "visibilitychange", () => {
				if (document.visibilityState === "hidden") {
					void this.locks?.releaseAll().catch(() => {});
					return;
				}
				// Timers and the long-poll don't run while a mobile app is in the background.
				void this.holdActive();
				this.live?.wake();
				this.tick();
			});
			this.registerDomEvent(window, "online", () => {
				this.live?.wake();
				this.tick();
			});
			if (isConfigured(this.settings)) void this.start();
		});
	}

	override onunload(): void {
		this.stop();
	}

	async loadSettings(): Promise<void> {
		this.settings = { ...DEFAULT_SETTINGS, ...((await this.loadData()) as Partial<SyncryptionSettings> | null) };
		if (this.settings.deviceName === "") {
			this.settings.deviceName = initialDeviceName();
			await this.saveSettings();
		}
	}

	async saveSettings(): Promise<void> {
		await this.saveData(this.settings);
	}

	/** Rebuild the path filter after the exclude list changed. The next scan uses it. */
	updateExcludes(): void {
		this.include = null;
	}

	private filter(): PathFilter {
		this.include ??= pathFilter({
			configDir: this.app.vault.configDir,
			pluginFolder: this.manifest.dir?.split("/").pop() ?? this.manifest.id,
			exclude: parseExcludes(this.settings.exclude),
		});
		return this.include;
	}

	/** Drop the unlocked key, after it was replaced in the settings. */
	forgetKey(): void {
		this.key = null;
	}

	/** Only keys imported by plugin versions before 0.1.3 can have a passphrase. */
	private askPassphrase(retry: boolean): Promise<string | null> {
		return prompt(this.app, {
			title: "Unlock the encryption key",
			description: retry ? "Wrong passphrase. Try again." : "This encryption key is protected with a passphrase.",
			label: "Passphrase",
			password: true,
			submit: "Unlock",
		});
	}

	statusText(): string {
		switch (this.state) {
			case "off":
				return isConfigured(this.settings) ? "Not connected." : "Fill in the settings above, then connect.";
			case "connecting":
				return "Connecting…";
			case "syncing":
				return "Syncing…";
			case "idle":
				return this.syncedText();
			case "offline":
				return `Offline. ${this.detail}`;
			case "maintenance":
			case "error":
				return this.detail;
		}
	}

	async restart(): Promise<void> {
		this.stop();
		if (!isConfigured(this.settings)) {
			new Notice("Fill in the server URL, username, vault name and encryption key first.");
			return;
		}
		await this.start();
	}

	private stop(): void {
		this.abort?.abort();
		this.abort = null;
		void this.live?.stop();
		this.live = null;
		void this.locks?.releaseAll().catch(() => {});
		this.locks = null;
		window.clearInterval(this.renewTimer);
		this.renderLock();
		this.session?.store.close();
		this.session = null;
		this.engine = null;
		this.setState("off");
	}

	private async start(): Promise<void> {
		if (this.state === "connecting") return;
		this.setState("connecting");
		const abort = new AbortController();
		this.abort = abort;
		let pairing: PairingModal | null = null;
		try {
			const key = await this.unlock();
			if (key === null) throw new SetupCancelled();
			const deviceName = this.settings.deviceName;
			const api = new ApiClient({
				endpoint: this.settings.endpoint,
				identity: { username: this.settings.username, seed: key.seed },
				deviceName,
				transport: requestUrlTransport,
			});
			const session = await connect({
				api,
				vaultName: this.settings.vaultName,
				deviceName,
				seed: key.seed,
				openStore: (vaultId) => IndexedDbStore.open(`syncryption-${this.installId()}-${vaultId}`),
				callbacks: {
					askSharedSecret: () =>
						prompt(this.app, {
							title: "Join the server",
							description:
								"This key is new to the server. Enter the server's shared secret to join. It is used once and not stored.",
							label: "Shared secret",
							password: true,
							submit: "Join",
						}),
					showPairing: (code, recover) => {
						pairing = new PairingModal(this.app, code, () => abort.abort(), recover);
						pairing.open();
					},
				},
				signal: abort.signal,
			});
			(pairing as PairingModal | null)?.finish();
			if (abort.signal.aborted) {
				session.store.close();
				return;
			}
			this.session = session;
			this.engine = new SyncEngine({
				api,
				vaultId: session.vault.id,
				cipher: new VaultCipher(() => session.keyring),
				fs: new SplitFs(
					new ObsidianFs(this.app),
					new AdapterFs(this.app.vault.adapter, {
						configDir: this.app.vault.configDir,
						skipsFolder: (folder) => this.filter().skipsFolder(folder),
					}),
				),
				store: session.store,
				deviceId: session.deviceId,
				deviceName,
				include: (path) => this.filter()(path),
				configDir: this.app.vault.configDir,
				keyring: { version: () => session.keyring.version, refresh: () => session.refreshKeyring() },
				onWarning: (message) => new Notice(`Sync: ${message}`),
			});
			this.startLive(session);
			this.setState("idle");
			void this.offerRecoveryKey(session);
			void this.finishRevocations(session);
			await this.syncNow();
		} catch (e) {
			(pairing as PairingModal | null)?.finish();
			if (this.abort !== abort) return; // stopped or restarted meanwhile
			if (e instanceof SetupCancelled) {
				this.setState("off");
				return;
			}
			this.fail(e);
		}
	}

	private renewTimer = 0;

	private startLive(session: VaultSession): void {
		const locks = new LockManager({
			api: session.api,
			vaultId: session.vault.id,
			cipher: new VaultCipher(() => session.keyring),
			deviceId: session.deviceId,
			clientId: this.clientId(),
		});
		this.locks = locks;
		this.renewTimer = window.setInterval(() => {
			if (this.locks === locks) void locks.renew().then(() => this.renderLock(), () => {});
		}, (locks.ttl * 1000) / 2);
		this.registerInterval(this.renewTimer);
		this.live = new LiveLoop({
			api: session.api,
			vaultId: session.vault.id,
			cursor: async () => (await session.store.getMeta<number>(CURSOR)) ?? 0,
			keyringVersion: () => session.keyring.version,
			onChanges: () => this.syncNow(),
			onLocks: async () => {
				if (this.locks !== locks) return;
				await locks.refresh();
				this.renderLock();
			},
		});
		this.live.start();
		void this.holdActive();
	}

	/** Lock the note in the active editor, and warn if another device is editing it. */
	private async holdActive(): Promise<void> {
		const locks = this.locks;
		if (!locks || document.visibilityState === "hidden") return;
		const path = this.app.workspace.getActiveFile()?.path ?? null;
		const lockable = path !== null && isMergeable(path) && this.filter()(path) ? path : null;
		try {
			const other = await locks.hold(lockable);
			if (this.locks !== locks) return;
			if (other && lockable !== this.warnedLock) {
				new Notice(`${other.deviceName} is editing this note. Your edits will be merged.`, 8000);
			}
			this.warnedLock = other ? lockable : null;
		} catch {
			// Locks are only a warning: sync errors are reported by the sync itself.
		}
		this.renderLock();
	}

	private renderLock(): void {
		if (!this.lockBar) return;
		const path = this.app.workspace.getActiveFile()?.path;
		const other = path ? this.locks?.heldByOther(path) : null;
		this.lockBar.setText(other ? `Vault Syncryption: ${other.deviceName} is editing` : "");
		this.lockBar.toggle(Boolean(other));
	}

	/** This installation's lock holder id (protocol.md 11), kept with the install id. */
	private clientId(): string {
		let id = this.app.loadLocalStorage(CLIENT_ID) as string | null;
		if (!id) {
			id = newClientId();
			this.app.saveLocalStorage(CLIENT_ID, id);
		}
		return id;
	}

	private async unlock(): Promise<OpenSshKey | null> {
		if (this.key) return this.key;
		const pem = loadKeyText(this.app, this.settings.keyId);
		if (pem === null) throw new Error("The encryption key is missing from this device's secret storage. Generate a new one in the settings.");
		this.key = await unlockKey(pem, (retry) => this.askPassphrase(retry));
		return this.key;
	}

	private installId(): string {
		let id = this.app.loadLocalStorage(INSTALL_ID) as string | null;
		if (!id) {
			id = crypto.randomUUID();
			this.app.saveLocalStorage(INSTALL_ID, id);
		}
		return id;
	}

	/** Sync, or connect again if the last attempt failed for want of a network or for maintenance. */
	private tick(): void {
		if (this.paused()) return;
		if (this.engine) void this.syncNow();
		else if ((this.state === "offline" || this.state === "maintenance") && isConfigured(this.settings)) void this.start();
	}

	/** In maintenance, background syncs wait for the retry the server asked for. */
	private paused(): boolean {
		return this.state === "maintenance" && Date.now() < this.retryAt;
	}

	/** Try again after `seconds` (the server's `Retry-After`), through `tick`. */
	private scheduleRetry(seconds: number | undefined): void {
		const { min, max } = MAINTENANCE_RETRY_S;
		const ms = Math.min(Math.max(seconds ?? MAINTENANCE_RETRY_S.default, min), max) * 1000;
		this.clearRetry();
		this.retryAt = Date.now() + ms;
		this.retryTimer = window.setTimeout(() => {
			this.retryTimer = 0;
			this.retryAt = 0;
			this.tick();
		}, ms);
	}

	private clearRetry(): void {
		window.clearTimeout(this.retryTimer);
		this.retryTimer = 0;
		this.retryAt = 0;
	}

	private noteChange(path: string): void {
		if (!this.engine) return;
		void this.engine.noteChange(path).then(() => this.scheduleSync());
	}

	async syncNow(manual = false): Promise<void> {
		const engine = this.engine;
		if (!engine) {
			if (manual) await this.restart();
			return;
		}
		this.setState("syncing");
		try {
			const report = await engine.sync();
			if (this.engine !== engine) return;
			this.lastSync = new Date();
			this.lastReport = report;
			this.fileCount = await engine.fileCount();
			this.lastError = "";
			this.setState("idle");
			this.announce(report);
			await this.checkApprovals();
		} catch (e) {
			if (this.engine === engine) this.fail(e, manual);
		}
	}

	/** "Synced at 12:03. 42 files in sync. Last sync: 2 uploaded, 1 received." */
	private syncedText(): string {
		if (!this.lastSync) return "Connected.";
		const parts = [`Synced at ${this.lastSync.toLocaleTimeString()}.`];
		if (this.fileCount !== null) parts.push(`${plural(this.fileCount, "file")} in sync.`);
		const report = this.lastReport;
		if (report && (report.pushed || report.pulled)) {
			parts.push(`Last sync: ${report.pushed} uploaded, ${report.pulled} received.`);
		}
		if (report?.reencrypted) parts.push(`${plural(report.reencrypted, "file")} re-encrypted with the new key.`);
		return parts.join(" ");
	}

	private announce(report: SyncReport): void {
		if (report.configChanged && !this.reloadAsked) {
			// Asked once: after "Later", the next start of Obsidian picks the changes up.
			this.reloadAsked = true;
			new ReloadModal(this.app, () => (this.app as Commands).commands?.executeCommandById("app:reload")).open();
		}
		for (const copy of report.conflicts) {
			new Notice(`Conflicting edits. Your version was saved as “${copy}”.`, 10_000);
		}
	}

	/** Tell the user once about each device that waits for approval. */
	private async checkApprovals(): Promise<void> {
		if (!this.session) return;
		const pending = await this.session.pendingMembers();
		const fresh = pending.filter((p) => !this.announced.has(p.member.device.id));
		for (const p of fresh) this.announced.add(p.member.device.id);
		if (fresh.length) new Notice("A device is waiting for approval. Approve it in the sync settings.", 10_000);
	}

	/** The devices waiting for this device's approval, for the settings tab. */
	async pendingCount(): Promise<number | null> {
		const session = this.session;
		if (!session) return null;
		const members = await session.pendingMembers();
		const devices = await session.pendingDevices();
		return members.length + devices.filter((d) => !members.some((m) => m.member.device.id === d.device.id)).length;
	}

	async openApprovals(): Promise<void> {
		const session = this.session;
		if (!session) {
			new Notice("Not connected to the sync server.");
			return;
		}
		try {
			const members = await session.pendingMembers();
			const devices = await session.pendingDevices();
			const items: PendingApproval[] = [
				...members.map((p) => ({
					name: `${p.member.device.name} (wants to sync this vault)`,
					code: p.code,
					approve: () => session.approve(p.member),
				})),
				...devices
					.filter((d) => !members.some((m) => m.member.device.id === d.device.id))
					.map((p) => ({
						name: `${p.device.name} (new device of this account)`,
						code: p.code,
						approve: async () => void (await session.api.approveDevice(p.device.id)),
					})),
			];
			new ApproveModal(this.app, items).open();
		} catch (e) {
			this.fail(e, true);
		}
	}

	/** The recovery key's state for the settings tab, or null when not connected. */
	recoveryStatus(): { set: false } | { set: true; setBy: string } | null {
		const keyring = this.session?.keyring;
		if (!keyring) return null;
		if (keyring.recovery === undefined) return { set: false };
		const setBy = keyring.devices.find((d) => d.id === keyring.recoverySetBy)?.name ?? "a removed device";
		return { set: true, setBy };
	}

	/** Create a recovery key, show it once, and set it once the user has stored it. */
	async createRecoveryKey(): Promise<boolean> {
		const session = this.session;
		if (!session) {
			new Notice("Not connected to the sync server.");
			return false;
		}
		const key = await generateRecoveryKey();
		if (!(await showRecoveryKey(this.app, key.identity))) return false;
		try {
			await session.setRecovery(key);
		} catch (e) {
			this.fail(e, true);
			return false;
		}
		new Notice("Recovery key set.");
		return true;
	}

	async removeRecoveryKey(): Promise<boolean> {
		const session = this.session;
		if (!session) return false;
		try {
			await session.setRecovery(undefined);
		} catch (e) {
			this.fail(e, true);
			return false;
		}
		new Notice("Recovery key removed.");
		return true;
	}

	/** The other devices in the keyring, for the settings tab, or null when not connected. */
	keyringDevices(): { id: string; name: string }[] | null {
		const session = this.session;
		if (!session) return null;
		return session.keyring.devices.filter((d) => d.id !== session.deviceId).map(({ id, name }) => ({ id, name }));
	}

	/**
	 * Remove a device from this vault, or from every vault of the account, and rotate the
	 * vault key (crypto.md 8.4).
	 */
	async removeDevice(id: string, everywhere: boolean): Promise<boolean> {
		const session = this.session;
		if (!session) {
			new Notice("Not connected to the sync server.");
			return false;
		}
		const name = session.keyring.devices.find((d) => d.id === id)?.name ?? "The device";
		const hadRecovery = session.keyring.recovery !== undefined;
		try {
			await session.removeDevice(id, everywhere);
		} catch (e) {
			this.fail(e, true);
			return false;
		}
		new Notice(`${name} was removed. Files are re-encrypted with a new key in the background.`);
		if (hadRecovery && session.keyring.recovery === undefined) this.recoveryCleared();
		void this.syncNow();
		return true;
	}

	/** Finish revocations done from another vault or interrupted before the key rotation. */
	private async finishRevocations(session: VaultSession): Promise<void> {
		const hadRecovery = session.keyring.recovery !== undefined;
		let names: string[];
		try {
			names = await session.removeStaleDevices();
		} catch {
			return; // tried again on the next start
		}
		if (names.length === 0 || this.session !== session) return;
		new Notice(`Removed ${names.join(", ")} from this vault's key, as they no longer have access.`);
		if (hadRecovery && session.keyring.recovery === undefined) this.recoveryCleared();
		void this.syncNow();
	}

	/** The recovery key was set by a removed device and is gone with it. */
	private recoveryCleared(): void {
		new ConfirmModal(this.app, {
			title: "Recovery key removed",
			text: "The recovery key was set by the removed device, so it no longer works. Create a new one to keep a way back into this vault.",
			confirm: "Create recovery key",
			cancel: "Later",
			onConfirm: () => void this.createRecoveryKey(),
		}).open();
	}

	/**
	 * Offer a recovery key once per device while the vault has none. Device keys can't be
	 * exported, so it is the only way back in when every device is lost.
	 */
	private async offerRecoveryKey(session: VaultSession): Promise<void> {
		if (session.keyring.recovery !== undefined || (await session.store.getMeta(RECOVERY_OFFERED))) return;
		await session.store.setMeta(RECOVERY_OFFERED, true);
		new ConfirmModal(this.app, {
			title: "Create a recovery key?",
			text: "This vault has no recovery key. Each device's encryption key stays on that device, so if you lose every device of this vault, a recovery key is the only way to read it again. You can also create one later in the settings.",
			confirm: "Create recovery key",
			cancel: "Not now",
			onConfirm: () => void this.createRecoveryKey(),
		}).open();
	}

	openHistory(path: string): void {
		const source = this.historySource();
		if (source) new HistoryModal(this.app, source, path).open();
	}

	private async openDeleted(): Promise<void> {
		const source = this.historySource();
		if (!source || !this.engine) return;
		const paths = await this.engine.deletedPaths();
		new DeletedFilesModal(this.app, paths, (path) => new HistoryModal(this.app, source, path).open()).open();
	}

	/** History access for the dialogs, bound to the current connection. */
	private historySource(): HistorySource | null {
		const engine = this.engine;
		const session = this.session;
		if (!engine || !session) {
			new Notice("Not connected to the sync server.");
			return null;
		}
		return {
			history: (path, before) => engine.history(path, before),
			readRevision: (path, rev) => engine.readRevision(path, rev),
			restore: async (path, rev) => {
				this.setState("syncing");
				try {
					await engine.restore(path, rev);
				} finally {
					if (this.engine === engine) await this.syncNow();
				}
			},
			deviceName: (id) => session.keyring.devices.find((d) => d.id === id)?.name ?? null,
		};
	}

	/** Report a failure. `userAction`: the user asked for it, so always show a notice. */
	private fail(e: unknown, userAction = false): void {
		if (e instanceof NetworkError) {
			this.detail = e.message;
			this.setState("offline");
			return;
		}
		if (isMaintenance(e)) {
			// A pause, not an error: keep the session and try again when the server says.
			this.detail = maintenanceText(e.details);
			this.setState("maintenance");
			this.scheduleRetry(e.retryAfter);
			if (!this.maintenanceNoticed || userAction) new Notice(`Sync: ${this.detail}`, 10_000);
			this.maintenanceNoticed = true;
			return;
		}
		let message = e instanceof Error ? e.message : "Sync failed.";
		if (isDisabled(e)) {
			message = disabledText(e);
			this.stop(); // until the user reconnects
		}
		// Syncs retry on every wake-up and timer tick: show each error once, not on every retry.
		const repeated = this.lastError === message;
		this.lastError = message;
		this.detail = message;
		this.setState("error");
		if (!repeated || userAction) new Notice(`Sync: ${message}`);
	}

	private setState(state: State): void {
		if (state !== "maintenance" && state !== "syncing" && state !== "connecting") {
			// Back from maintenance (or stopped): no retry pending, notice again next time.
			this.clearRetry();
			if (state === "idle" || state === "off") this.maintenanceNoticed = false;
		}
		this.state = state;
		this.render();
	}

	private render(): void {
		if (!this.statusBar) return;
		const label: Record<State, string> = {
			off: "Vault Syncryption: off",
			connecting: "Vault Syncryption: connecting",
			syncing: "Vault Syncryption: syncing",
			idle: this.fileCount === null ? "Vault Syncryption: synced" : `Vault Syncryption: ${plural(this.fileCount, "file")} synced`,
			offline: "Vault Syncryption: offline",
			maintenance: "Vault Syncryption: maintenance",
			error: "Vault Syncryption: error",
		};
		this.statusBar.setText(label[this.state]);
		this.statusBar.setAttr("aria-label", this.statusText());
	}
}

function plural(n: number, word: string): string {
	return `${n} ${word}${n === 1 ? "" : "s"}`;
}
