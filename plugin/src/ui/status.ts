/** The sync status window, opened from the ribbon, the status bar or the "Show sync status" command. */
import { type App, ButtonComponent, debounce, Modal, setTooltip } from "obsidian";

import { fingerprint, parsePublicKeyText } from "../crypto/openssh";
import type SyncryptionPlugin from "../main";
import type { OutboxEntry } from "../store/state";
import type { SyncReport } from "../sync/engine";
import { logo } from "./icon";
import { formatDate, type KeyStateKind, keyServerState, type VaultKey } from "./keys";

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
	/** Remote-only (docs/remote-only.md): no vault management, and a compliance report. */
	remoteOnly: boolean;
	/** The remote-only files can be read: the device is connected and not locked. */
	remoteUnlocked: boolean;
}

/** Paths listed under "Waiting to upload"; the rest are counted. */
const MAX_LISTED = 50;
/** The window follows the status at most this often. */
const REFRESH_MS = 500;
/** The logo in the window's header, in pixels. */
const LOGO_SIZE = 28;

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

/** The colour of the state pill: only states that need attention get one. */
const STATE_KINDS: Record<string, KeyStateKind> = {
	off: "off",
	connecting: "unknown",
	idle: "ok",
	syncing: "unknown",
	offline: "warn",
	maintenance: "warn",
	error: "error",
	paused: "warn",
};

export class StatusModal extends Modal {
	private unfollow: (() => void) | null = null;
	private headEl!: HTMLElement;
	private detailEl!: HTMLElement;
	private tilesEl!: HTMLElement;
	private queueEl!: HTMLElement;
	private deviceEl!: HTMLElement;
	private keysEl!: HTMLElement;
	private footEl!: HTMLElement;
	private readonly refresh = debounce(() => this.renderLive(), REFRESH_MS, false);

	constructor(
		app: App,
		private readonly plugin: SyncryptionPlugin,
	) {
		super(app);
	}

	override onOpen(): void {
		this.setTitle("Sync status");
		// The window's own header replaces the modal title: it carries the state and the actions.
		this.titleEl.remove();
		this.modalEl.addClass("syncryption-status");
		const el = this.contentEl;
		this.headEl = el.createDiv({ cls: "syncryption-head" });
		this.detailEl = el.createDiv({ cls: "syncryption-detail" });
		this.tilesEl = el.createDiv({ cls: "syncryption-tiles" });
		const cols = el.createDiv({ cls: "syncryption-cols" });
		this.queueEl = cols.createDiv({ cls: "syncryption-col" });
		this.deviceEl = cols.createDiv({ cls: "syncryption-col" });
		this.keysEl = el.createDiv({ cls: "syncryption-keys" });
		this.footEl = el.createDiv({ cls: "syncryption-foot" });
		this.renderLive();
		this.renderDevice();
		this.renderKeys();
		this.renderFoot();
		this.unfollow = this.plugin.onStatusChange(() => this.refresh());
	}

	override onClose(): void {
		this.unfollow?.();
		this.refresh.cancel();
		this.contentEl.empty();
	}

	/** The parts that change during a sync: the state, the numbers and what is in flight. */
	private renderLive(): void {
		const d = this.plugin.statusDetails();
		this.renderHead(d);
		void this.renderQueue(d);
	}

	/** Identity, state and the two actions. */
	private renderHead(d: StatusDetails): void {
		const el = this.headEl;
		el.empty();
		logo(el, LOGO_SIZE);
		const id = el.createDiv({ cls: "syncryption-id" });
		id.createDiv({ cls: "syncryption-id-name", text: "Sync status" });
		const where = [hostOf(d.endpoint), d.vault].filter(Boolean).join(" · ");
		id.createDiv({ cls: "syncryption-id-where", text: where || "Not set up yet" });
		const state = STATE_NAMES[d.state] ?? d.state;
		el.createSpan({ cls: `syncryption-pill mod-${STATE_KINDS[d.state] ?? "unknown"}`, text: state });
		el.createDiv({ cls: "syncryption-spacer" });
		const actions = el.createDiv({ cls: "syncryption-actions" });
		new ButtonComponent(actions).setButtonText(d.paused ? "Resume sync" : "Pause sync").onClick(() => this.plugin.togglePause());
		new ButtonComponent(actions)
			.setButtonText(d.connected ? "Sync now" : "Connect")
			.setCta()
			.setDisabled(d.syncing)
			.onClick(() => void this.plugin.syncNow(true));

		// Everything the state line says beyond "Synced": an error, why it is offline, the
		// pause hint. Hidden when synced, where the tiles already say it.
		this.detailEl.empty();
		this.detailEl.toggle(d.state !== "idle");
		if (d.state !== "idle") this.detailEl.setText(d.paused ? `${d.text} "Sync now" syncs once and leaves sync paused.` : d.text);
	}

	/** The four numbers, then what waits to upload and what others are editing. */
	private async renderQueue(d: StatusDetails): Promise<void> {
		const entries = await this.plugin.waitingChanges();
		this.renderTiles(d, entries);
		const el = this.queueEl;
		el.empty();
		const waiting = section(el, "Waiting to upload", entries === null ? "" : count(entries.length, "change"));
		if (entries === null) {
			waiting.body.createEl("p", { cls: "syncryption-note", text: "Connect to see the changes waiting on this device." });
		} else if (!entries.length) {
			waiting.body.createEl("p", { cls: "syncryption-note", text: "Nothing: every noted change is uploaded." });
		} else {
			const table = rows(waiting.body.createDiv({ cls: "syncryption-scroll" }), ["Path", "Queued"]);
			for (const entry of entries.slice(0, MAX_LISTED)) {
				const row = table.createEl("tr");
				row.createEl("td", { cls: "syncryption-ellipsis", text: entry.path });
				row.createEl("td", { cls: "syncryption-right syncryption-muted", text: new Date(entry.queuedAt).toLocaleTimeString() });
			}
			if (entries.length > MAX_LISTED) {
				const row = table.createEl("tr");
				row.createEl("td", { attr: { colspan: 2 }, cls: "syncryption-note", text: `and ${entries.length - MAX_LISTED} more` });
			}
		}
		waiting.body.createEl("p", { cls: "syncryption-note", text: "Changes made while Obsidian was closed are found at the next sync." });
		await this.renderEditing(el);
	}

	private renderTiles(d: StatusDetails, entries: OutboxEntry[] | null): void {
		const el = this.tilesEl;
		el.empty();
		tile(el, "Last sync", d.lastSync ? relativeTime(d.lastSync) : "Never", d.lastSync?.toLocaleString() ?? "No sync on this device yet");
		const report = d.lastReport;
		const extra = [];
		if (report?.merged) extra.push(count(report.merged, "merge"));
		if (report?.conflicts.length) extra.push(`${count(report.conflicts.length, "conflict copy", "conflict copies")}`);
		tile(el, "Last run", report ? `${report.pushed} ↑ ${report.pulled} ↓` : "—", report ? (extra.join(" · ") || "No merges or conflicts") : "Nothing run yet");
		tile(el, "Files in sync", d.fileCount === null ? "—" : d.fileCount.toLocaleString(), mode(d));
		const oldest = entries?.length ? entries.reduce((a, b) => (a.queuedAt <= b.queuedAt ? a : b)) : null;
		tile(
			el,
			"Waiting to upload",
			entries === null ? "—" : entries.length.toLocaleString(),
			oldest ? `Oldest ${new Date(oldest.queuedAt).toLocaleTimeString()}` : "",
		);
	}

	private async renderEditing(el: HTMLElement): Promise<void> {
		const editing = await this.plugin.editingElsewhere();
		if (!editing?.length) return;
		const sec = section(el, "Being edited elsewhere", String(editing.length));
		const table = rows(sec.body, null);
		for (const lock of editing) {
			const row = table.createEl("tr");
			row.createEl("td", { cls: "syncryption-ellipsis", text: lock.path ?? "A file not synced here yet" });
			row.createEl("td", { cls: "syncryption-right syncryption-muted", text: lock.deviceName });
		}
	}

	/** This device's facts: rendered once, as they rarely change while the window is open. */
	private renderDevice(): void {
		const d = this.plugin.statusDetails();
		const sec = section(this.deviceEl, "This device", "");
		const list = sec.body.createEl("dl", { cls: "syncryption-kv" });
		pair(list, "Device").createSpan({ text: d.deviceName || "Not set" });
		const server = pair(list, "Server");
		server.createSpan({ cls: "syncryption-ellipsis", text: d.endpoint || "Not set" });
		pair(list, "Vault").createSpan({ text: d.vault || "Not set" });
		const key = pair(list, "Encryption key");
		if (d.fingerprint) short(key, d.fingerprint);
		else key.createSpan({ text: "None yet. Generate one in the settings." });

		const modeRow = pair(list, "Mode");
		modeRow.createSpan({ text: mode(d) });
		modeRow.createDiv({ cls: "syncryption-spacer" });
		if (d.remoteOnly) {
			new ButtonComponent(modeRow)
				.setButtonText(d.remoteUnlocked ? "Lock" : "Unlock")
				.onClick(() => (d.remoteUnlocked ? this.plugin.lockRemote() : void this.plugin.unlockRemote()));
		}
		new ButtonComponent(modeRow).setButtonText("Compliance report").onClick(() => this.plugin.openCompliance());

		const recovery = this.plugin.recoveryStatus();
		if (recovery !== null && !d.remoteOnly) {
			const row = pair(list, "Recovery key");
			dot(row, recovery.set ? "ok" : "warn");
			row.createSpan({ text: recovery.set ? `Set by ${recovery.setBy}` : "Not set. Create one in the plugin settings." });
		}
	}

	/** Every key of the vault, with the server's view of it and the approvals it needs. */
	private renderKeys(): void {
		const d = this.plugin.statusDetails();
		const keys = this.plugin.vaultKeys();
		const sec = section(this.keysEl, "Vault keys", keys === null ? "" : count(keys.length, "key"));
		if (keys === null) {
			sec.body.createEl("p", { cls: "syncryption-note", text: "Connect to see the keys of this vault." });
			return;
		}
		if (d.connected && !d.paused && !d.remoteOnly) this.renderApprovals(sec.head);
		// Paused means no requests: the server's view of each key waits until sync resumes.
		const status = d.paused ? null : this.plugin.vaultKeyStatus();
		const table = rows(sec.body, ["Device", "Fingerprint", "Added", "Server", "Last seen"]);
		for (const key of keys) {
			const row = table.createEl("tr");
			const name = row.createEl("td");
			name.createSpan({ text: key.name });
			if (key.self) name.createSpan({ cls: "syncryption-tag mod-self", text: "This device" });
			if (key.remoteOnly) name.createSpan({ cls: "syncryption-tag mod-remote", text: "Remote-only" });
			short(row.createEl("td", { cls: "syncryption-muted" }), fingerprint(parsePublicKeyText(key.publicKey)));
			row.createEl("td", { cls: "syncryption-muted", text: formatDate(key.added) });
			const server = row.createEl("td");
			const seen = row.createEl("td", { cls: "syncryption-right syncryption-muted", text: "—" });
			if (status) void status.then((devices) => keyRow(server, seen, devices.get(key.id), key), () => undefined);
			else server.createSpan({ cls: "syncryption-muted", text: "Paused" });
		}
	}

	private renderApprovals(head: HTMLElement): void {
		const warn = head.createDiv({ cls: "syncryption-warn" });
		warn.hide();
		void this.plugin.pendingCount().then((n) => {
			if (!n) return;
			dot(warn, "warn");
			warn.createSpan({ text: `${count(n, "key")} waiting for approval` });
			new ButtonComponent(warn)
				.setButtonText("Approve")
				.setCta()
				.onClick(() => void this.plugin.openApprovals());
			warn.show();
		}, () => undefined);
	}

	private renderFoot(): void {
		const d = this.plugin.statusDetails();
		if (d.remoteOnly || this.plugin.vaultKeys() === null) return;
		this.footEl.setText("Remove a lost or old device's key in the plugin settings.");
	}
}

/** "Full device" or how a remote-only device stands (remote-only.md 2). */
function mode(d: StatusDetails): string {
	if (!d.remoteOnly) return "Full device";
	return `Remote-only · ${d.remoteUnlocked ? "Unlocked" : "Locked"}`;
}

/** The server's state and last-seen cells of one key's row. */
function keyRow(server: HTMLElement, seen: HTMLElement, device: Parameters<typeof keyServerState>[0], key: VaultKey): void {
	const state = keyServerState(device);
	server.empty();
	dot(server, state.kind);
	server.createSpan({ text: state.label });
	if (key.self) seen.setText("Now");
	else if (device?.lastSeenAt) seen.setText(formatDate(device.lastSeenAt));
}

/** The host of an endpoint URL, or the endpoint itself when it doesn't parse. */
function hostOf(endpoint: string): string {
	if (!endpoint) return "";
	try {
		return new URL(endpoint).host;
	} catch {
		return endpoint;
	}
}

/** A fingerprint shortened to fit a cell; the whole one stays selectable in the tooltip. */
function short(parent: HTMLElement, value: string): void {
	const el = parent.createSpan({ cls: "syncryption-mono", text: value.length > 24 ? `${value.slice(0, 13)}…${value.slice(-5)}` : value });
	setTooltip(el, value);
}

function tile(parent: HTMLElement, key: string, value: string, detail: string): void {
	const el = parent.createDiv({ cls: "syncryption-tile" });
	el.createDiv({ cls: "syncryption-tile-key", text: key });
	el.createDiv({ cls: "syncryption-tile-value", text: value });
	el.createDiv({ cls: "syncryption-tile-detail", text: detail });
}

function section(parent: HTMLElement, title: string, count: string): { head: HTMLElement; body: HTMLElement } {
	const el = parent.createDiv({ cls: "syncryption-sec" });
	const head = el.createDiv({ cls: "syncryption-sec-head" });
	head.createSpan({ cls: "syncryption-sec-name", text: title });
	if (count) head.createSpan({ cls: "syncryption-sec-count", text: count });
	head.createDiv({ cls: "syncryption-spacer" });
	return { head, body: el.createDiv() };
}

/** A table with an optional header row; returns the body to add rows to. */
function rows(parent: HTMLElement, headers: string[] | null): HTMLElement {
	const table = parent.createEl("table", { cls: "syncryption-table" });
	if (headers) {
		const row = table.createEl("thead").createEl("tr");
		for (const [i, header] of headers.entries()) {
			row.createEl("th", { cls: i === headers.length - 1 && headers.length > 2 ? "syncryption-right" : "", text: header });
		}
	}
	return table.createEl("tbody");
}

function pair(list: HTMLElement, label: string): HTMLElement {
	list.createEl("dt", { text: label });
	return list.createEl("dd");
}

function dot(parent: HTMLElement, kind: KeyStateKind): void {
	parent.createSpan({ cls: `syncryption-dot mod-${kind}` });
}

function count(n: number, word: string, plural = `${word}s`): string {
	return `${n} ${n === 1 ? word : plural}`;
}

/** "2 minutes ago", in the user's locale. */
function relativeTime(date: Date): string {
	const seconds = (date.getTime() - Date.now()) / 1000;
	const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
	if (Math.abs(seconds) < 45) return "just now";
	if (Math.abs(seconds) < 3600) return relative.format(Math.round(seconds / 60), "minute");
	if (Math.abs(seconds) < 86400) return relative.format(Math.round(seconds / 3600), "hour");
	return relative.format(Math.round(seconds / 86400), "day");
}
