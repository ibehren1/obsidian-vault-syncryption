/** Browsing a file's revisions and restoring one, and finding deleted files to restore. */
import { App, FuzzySuggestModal, Modal, Notice, Setting } from "obsidian";

import type { HistoryEntry, HistoryPage } from "../sync/engine";
import { isMergeable } from "../sync/merge";

/** Preview at most this much of a text revision. */
const PREVIEW_BYTES = 256 * 1024;

export interface HistorySource {
	history(path: string, before?: number): Promise<HistoryPage>;
	readRevision(path: string, rev: number): Promise<Uint8Array | null>;
	restore(path: string, rev: number): Promise<void>;
	/** The name of a device from the keyring, or null if it was removed. */
	deviceName(id: string): string | null;
}

/** The revisions of one file, newest first, with preview and restore buttons. */
export class HistoryModal extends Modal {
	private list!: HTMLElement;
	private more: HTMLElement | null = null;
	private first = true;

	constructor(
		app: App,
		private readonly source: HistorySource,
		private readonly path: string,
	) {
		super(app);
	}

	override onOpen(): void {
		this.setTitle(`History of ${baseName(this.path)}`);
		this.contentEl.createEl("p", { text: this.path, cls: "syncryption-path" });
		this.list = this.contentEl.createDiv();
		void this.load();
	}

	private async load(before?: number): Promise<void> {
		this.more?.remove();
		this.more = null;
		const status = this.list.createEl("p", { text: "Loading…" });
		let page: HistoryPage;
		try {
			page = await this.source.history(this.path, before);
		} catch (e) {
			status.setText(errorText(e, "Couldn't load the history."));
			return;
		}
		status.remove();
		if (this.first && page.entries.length === 0) {
			this.list.createEl("p", { text: "This file has no synced revisions yet." });
		}
		for (const entry of page.entries) {
			this.row(entry, this.first);
			this.first = false;
		}
		if (page.rejected) {
			this.list.createEl("p", {
				text: `${page.rejected} revision(s) failed their integrity check and are not shown.`,
				cls: "mod-warning",
			});
		}
		if (page.next !== undefined) {
			const next = page.next;
			this.more = this.contentEl.createDiv();
			new Setting(this.more).addButton((b) => b.setButtonText("Show older").onClick(() => void this.load(next)));
		}
	}

	private row(entry: HistoryEntry, current: boolean): void {
		const device = this.source.deviceName(entry.device) ?? "a removed device";
		const when = new Date(entry.createdAt).toLocaleString();
		const what = entry.deleted ? "Deleted" : formatSize(entry.size);
		const setting = new Setting(this.list)
			.setName(current ? `${when} (current)` : when)
			.setDesc(`${what}, from ${device}`);
		if (entry.deleted) return;
		if (isMergeable(this.path)) {
			setting.addButton((b) =>
				b.setButtonText("Preview").onClick(() => {
					new PreviewModal(this.app, this.source, this.path, entry, current, () => this.close()).open();
				}),
			);
		}
		if (!current) {
			setting.addButton((b) =>
				b
					.setButtonText("Restore")
					.setCta()
					.onClick(async () => {
						b.setDisabled(true);
						if (await restore(this.source, this.path, entry)) this.close();
						else b.setDisabled(false);
					}),
			);
		}
	}

	override onClose(): void {
		this.contentEl.empty();
	}
}

/** The text of one revision. */
class PreviewModal extends Modal {
	constructor(
		app: App,
		private readonly source: HistorySource,
		private readonly path: string,
		private readonly entry: HistoryEntry,
		private readonly current: boolean,
		private readonly restored: () => void,
	) {
		super(app);
	}

	override onOpen(): void {
		this.setTitle(`${baseName(this.path)}, ${new Date(this.entry.createdAt).toLocaleString()}`);
		const pre = this.contentEl.createEl("pre", { text: "Loading…", cls: "syncryption-preview" });
		void this.source.readRevision(this.path, this.entry.rev).then(
			(data) => {
				if (data === null) return pre.setText("");
				const cut = data.length > PREVIEW_BYTES;
				const text = new TextDecoder().decode(cut ? data.subarray(0, PREVIEW_BYTES) : data);
				pre.setText(cut ? `${text}\n…` : text);
			},
			(e: unknown) => pre.setText(errorText(e, "Couldn't load this revision.")),
		);
		if (this.current) return;
		new Setting(this.contentEl).addButton((b) =>
			b
				.setButtonText("Restore this version")
				.setCta()
				.onClick(async () => {
					b.setDisabled(true);
					if (await restore(this.source, this.path, this.entry)) {
						this.close();
						this.restored();
					} else {
						b.setDisabled(false);
					}
				}),
		);
	}

	override onClose(): void {
		this.contentEl.empty();
	}
}

/** Pick a deleted file, then open its history. */
export class DeletedFilesModal extends FuzzySuggestModal<string> {
	constructor(
		app: App,
		private readonly paths: string[],
		private readonly choose: (path: string) => void,
	) {
		super(app);
		this.setPlaceholder("Restore a deleted file…");
		this.emptyStateText = "No deleted files.";
	}

	getItems(): string[] {
		return this.paths;
	}

	getItemText(path: string): string {
		return path;
	}

	onChooseItem(path: string): void {
		this.choose(path);
	}
}

async function restore(source: HistorySource, path: string, entry: HistoryEntry): Promise<boolean> {
	try {
		await source.restore(path, entry.rev);
	} catch (e) {
		new Notice(errorText(e, "Restore failed."));
		return false;
	}
	new Notice(`Restored “${baseName(path)}” from ${new Date(entry.createdAt).toLocaleString()}.`);
	return true;
}

function baseName(path: string): string {
	return path.slice(path.lastIndexOf("/") + 1);
}

function errorText(e: unknown, fallback: string): string {
	return e instanceof Error && e.message ? e.message : fallback;
}

export function formatSize(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
