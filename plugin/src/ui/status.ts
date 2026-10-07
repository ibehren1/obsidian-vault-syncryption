/** The sync status window, opened from the status bar or the "Show sync status" command. */
import { type App, debounce, Modal, Setting } from "obsidian";

import { fingerprint, parsePublicKeyText } from "../crypto/openssh";
import type SyncryptionPlugin from "../main";
import type { SyncReport } from "../sync/engine";
import { keyDescription, keyServerStatus } from "./keys";

export interface StatusDetails {
	text: string;
	state: string;
	paused: boolean;
	connected: boolean;
	syncing: boolean;
	lastSync: Date | null;
	lastReport: SyncReport | null;
	fileCount: number | null;
	endpoint: string;
	vault: string;
	deviceName: string;
	fingerprint: string | null;
}

/** Paths listed under "Waiting to upload"; the rest are counted. */
const MAX_LISTED = 50;
/** The window follows the status at most this often. */
const REFRESH_MS = 500;

const STATE_NAMES: Record<string, string> = {
	off: "Not connected",
	connecting: "Connecting",
	idle: "Synced",
	syncing: "Syncing",
	offline: "Offline",
	maintenance: "Server maintenance",
	error: "Error",
	paused: "Paused",
};

export class StatusModal extends Modal {
	private unfollow: (() => void) | null = null;
	private syncEl!: HTMLElement;
	private waitingEl!: HTMLElement;
	private detailsEl!: HTMLElement;
	private readonly refresh = debounce(() => this.renderLive(), REFRESH_MS, false);

	constructor(
		app: App,
		private readonly plugin: SyncryptionPlugin,
	) {
		super(app);
	}

	override onOpen(): void {
		this.setTitle("Sync status");
		this.syncEl = this.contentEl.createDiv();
		this.waitingEl = this.contentEl.createDiv();
		this.detailsEl = this.contentEl.createDiv();
		this.renderLive();
		this.renderDetails();
		this.unfollow = this.plugin.onStatusChange(() => this.refresh());
	}

	override onClose(): void {
		this.unfollow?.();
		this.refresh.cancel();
		this.contentEl.empty();
	}

	/** The parts that change during a sync: the state and what waits to upload. */
	private renderLive(): void {
		this.renderSync();
		void this.renderWaiting();
	}

	private renderSync(): void {
		const d = this.plugin.statusDetails();
		const el = this.syncEl;
		el.empty();
		new Setting(el).setName(STATE_NAMES[d.state] ?? d.state).setDesc(d.text).setHeading();
		if (d.lastSync) {
			const report = d.lastReport;
			const parts = [d.lastSync.toLocaleString()];
			if (report) parts.push(`${report.pushed} uploaded, ${report.pulled} received`);
			if (report?.merged) parts.push(`${report.merged} merged`);
			if (report?.conflicts.length) parts.push(`${report.conflicts.length} conflict copies`);
			new Setting(el).setName("Last sync").setDesc(parts.join(" · "));
		}
		if (d.fileCount !== null) new Setting(el).setName("Files in sync").setDesc(String(d.fileCount));
		const buttons = new Setting(el);
		if (d.paused) {
			buttons.setDesc("Sync is paused on this device until you resume it. Sync now syncs once and stays paused.");
		}
		buttons.addButton((b) =>
			b
				.setButtonText(d.paused ? "Resume sync" : "Pause sync")
				.setCta()
				.onClick(() => this.plugin.togglePause()),
		);
		buttons.addButton((b) =>
			b
				.setButtonText(d.connected ? "Sync now" : "Connect")
				.setDisabled(d.syncing)
				.onClick(() => void this.plugin.syncNow(true)),
		);
	}

	private async renderWaiting(): Promise<void> {
		const entries = await this.plugin.waitingChanges();
		const el = this.waitingEl;
		el.empty();
		const heading = new Setting(el).setName("Waiting to upload").setHeading();
		if (entries === null) {
			heading.setDesc("Connect to see the changes waiting on this device.");
			return;
		}
		heading.setDesc(entries.length ? `${entries.length} ${entries.length === 1 ? "change" : "changes"}` : "Nothing: every noted change is uploaded.");
		if (entries.length) {
			const list = el.createEl("ul", { cls: "syncryption-status-list" });
			for (const entry of entries.slice(0, MAX_LISTED)) {
				const item = list.createEl("li");
				item.createSpan({ text: entry.path });
				item.createSpan({ cls: "syncryption-note", text: ` · ${new Date(entry.queuedAt).toLocaleString()}` });
			}
			if (entries.length > MAX_LISTED) list.createEl("li", { cls: "syncryption-note", text: `and ${entries.length - MAX_LISTED} more` });
		}
		el.createEl("p", {
			cls: "syncryption-note",
			text: "Changes made while Obsidian was closed are found at the next sync.",
		});
	}

	/** This device, the vault's keys and the server: rendered once, as they rarely change. */
	private renderDetails(): void {
		const d = this.plugin.statusDetails();
		const el = this.detailsEl;
		new Setting(el).setName("This device").setHeading();
		new Setting(el).setName("Server").setDesc(d.endpoint || "Not set");
		new Setting(el).setName("Vault").setDesc(d.vault || "Not set");
		new Setting(el).setName("Device name").setDesc(d.deviceName);
		new Setting(el).setName("Encryption key").setDesc(d.fingerprint ?? "None yet. Generate one in the settings.");

		new Setting(el).setName("Vault keys").setHeading();
		const keys = this.plugin.vaultKeys();
		if (keys === null) {
			el.createEl("p", { cls: "syncryption-note", text: "Connect to see the keys of this vault." });
		} else {
			// Paused means no requests: the server's view of each key waits until sync resumes.
			const status = d.paused ? null : this.plugin.vaultKeyStatus();
			for (const key of keys) {
				const row = new Setting(el).setName(key.name).setDesc(keyDescription(key));
				row.descEl.createDiv({ text: fingerprint(parsePublicKeyText(key.publicKey)) });
				const server = row.descEl.createDiv();
				if (status) void status.then((devices) => server.setText(keyServerStatus(devices.get(key.id))), () => {});
			}
			el.createEl("p", { cls: "syncryption-note", text: "Remove a lost or old device's key in the plugin settings." });
		}

		const recovery = this.plugin.recoveryStatus();
		if (recovery !== null) {
			new Setting(el).setName("Recovery key").setDesc(recovery.set ? `Set by ${recovery.setBy}.` : "Not set. Create one in the plugin settings.");
		}
		if (d.connected && !d.paused) {
			const approvals = new Setting(el).setName("Keys waiting for approval");
			approvals.addButton((b) => b.setButtonText("Approve").onClick(() => void this.plugin.openApprovals()));
			void this.plugin.pendingCount().then(
				(n) => approvals.setDesc(n === null ? "" : String(n)),
				() => {},
			);
		}
		void this.renderEditing(el.createDiv());
	}

	private async renderEditing(el: HTMLElement): Promise<void> {
		const editing = await this.plugin.editingElsewhere();
		if (!editing?.length) return;
		new Setting(el).setName("Being edited on other devices").setHeading();
		const list = el.createEl("ul", { cls: "syncryption-status-list" });
		for (const lock of editing) list.createEl("li", { text: `${lock.path ?? "A file not synced here yet"} · ${lock.deviceName}` });
	}
}
