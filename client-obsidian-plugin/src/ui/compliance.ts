/** The remote-only compliance report (docs/remote-only.md 10): what this device enforces, checked now. */
import { type App, Modal, Setting } from "obsidian";

import type { ComplianceReport } from "../remote/compliance";

/** Locking and unlocking this device's remote-only files. */
export interface RemoteLock {
	unlocked(): boolean;
	lock(): void;
	unlock(): Promise<void>;
}

export class ComplianceModal extends Modal {
	constructor(
		app: App,
		private readonly load: () => Promise<ComplianceReport>,
		private readonly remoteLock?: RemoteLock,
	) {
		super(app);
	}

	override onOpen(): void {
		this.setTitle("Remote-only compliance");
		void this.render();
	}

	private async render(): Promise<void> {
		const el = this.contentEl;
		el.empty();
		const loading = el.createEl("p", { text: "Checking this device…" });
		let report: ComplianceReport;
		try {
			report = await this.load();
		} catch (e) {
			loading.setText(`The check failed: ${e instanceof Error ? e.message : String(e)}`);
			return;
		}
		el.empty();
		const source = report.source === "keyring" ? "the vault's keyring" : "this device, until it connects";
		if (!report.remoteOnly) {
			new Setting(el).setName("Full device").setDesc(`Per ${source}. Files are stored on this device in plaintext.`).setHeading();
		} else {
			new Setting(el)
				.setName(report.compliant ? "Compliant" : "Not compliant")
				.setDesc(`Remote-only, per ${source}.`)
				.setHeading();
		}
		for (const check of report.checks) {
			const row = new Setting(el).setName(`${check.ok ? "✓" : "✗"} ${check.name}`).setDesc(check.detail);
			row.settingEl.toggleClass("syncryption-check-failed", !check.ok);
		}
		if (report.facts.length) {
			new Setting(el).setName("Details").setHeading();
			for (const [name, value] of report.facts) new Setting(el).setName(name).setDesc(value);
		}
		if (report.remoteOnly) {
			el.createEl("p", {
				cls: "syncryption-note",
				text: "Only this plugin enforces these rules. Obsidian's metadata cache, other plugins and the operating system may still keep parts of notes, and paths stay readable on disk.",
			});
		}
		const buttons = new Setting(el);
		const lock = this.remoteLock;
		if (report.remoteOnly && lock) {
			buttons.addButton((b) =>
				lock.unlocked()
					? b.setButtonText("Lock files").onClick(() => {
							lock.lock();
							void this.render();
						})
					: b.setButtonText("Unlock files").onClick(async () => {
							await lock.unlock();
							void this.render();
						}),
			);
		}
		buttons.addButton((b) => b.setButtonText("Check again").onClick(() => void this.render()));
	}

	override onClose(): void {
		this.contentEl.empty();
	}
}
