/** Dialogs for joining, unlocking the key, pairing and approving devices. */
import { App, ButtonComponent, Modal, Setting, TextAreaComponent } from "obsidian";

interface PromptOptions {
	title: string;
	description: string;
	label: string;
	password?: boolean;
	multiline?: boolean;
	submit?: string;
}

/** Ask for one value. Resolves with null if the dialog is closed without submitting. */
export function prompt(app: App, opts: PromptOptions): Promise<string | null> {
	return new Promise((resolve) => {
		new PromptModal(app, opts, resolve).open();
	});
}

class PromptModal extends Modal {
	private value = "";
	private submitted = false;

	constructor(
		app: App,
		private readonly opts: PromptOptions,
		private readonly done: (value: string | null) => void,
	) {
		super(app);
	}

	override onOpen(): void {
		this.setTitle(this.opts.title);
		this.contentEl.createEl("p", { text: this.opts.description });
		const setting = new Setting(this.contentEl).setName(this.opts.label);
		if (this.opts.multiline) {
			setting.settingEl.addClass("syncryption-stacked");
			const area = new TextAreaComponent(setting.controlEl).onChange((v) => (this.value = v));
			area.inputEl.rows = 8;
			noAutocorrect(area.inputEl);
			area.inputEl.addClass("syncryption-wide");
			area.inputEl.focus();
		} else {
			setting.addText((text) => {
				if (this.opts.password) text.inputEl.type = "password";
				noAutocorrect(text.inputEl);
				text.onChange((v) => (this.value = v));
				text.inputEl.addEventListener("keydown", (e) => {
					if (e.key === "Enter") this.submit();
				});
				text.inputEl.focus();
			});
		}
		new Setting(this.contentEl).addButton((b) =>
			b
				.setButtonText(this.opts.submit ?? "Continue")
				.setCta()
				.onClick(() => this.submit()),
		);
	}

	private submit(): void {
		if (this.value === "") return;
		this.submitted = true;
		this.close();
	}

	override onClose(): void {
		this.contentEl.empty();
		this.done(this.submitted ? this.value : null);
	}
}

/**
 * Shown while this device waits to be approved. Closing it cancels the setup. With
 * `recover`, the user can add this device with the vault's recovery key instead.
 */
export class PairingModal extends Modal {
	private finished = false;

	constructor(
		app: App,
		private readonly code: string,
		private readonly onCancel: () => void,
		private readonly recover?: (identity: string) => Promise<void>,
	) {
		super(app);
	}

	override onOpen(): void {
		this.setTitle("Approve this device");
		this.contentEl.createEl("p", {
			text: "On a device that already syncs this vault, approve this device in the sync settings, and check that it shows this code:",
		});
		this.contentEl.createEl("p", { text: this.code, cls: "syncryption-code" });
		this.contentEl.createEl("p", { text: "This dialog closes by itself once the device is approved." });
		const status = this.contentEl.createEl("p");
		const buttons = new Setting(this.contentEl);
		const recover = this.recover;
		if (recover) {
			buttons.setDesc("No device left to approve this one?");
			buttons.addButton((b) =>
				b.setButtonText("Use a recovery key").onClick(async () => {
					const identity = await prompt(this.app, {
						title: "Use a recovery key",
						description:
							"Enter the vault's recovery key (AGE-SECRET-KEY-1…). This device is then added to the vault without an approval. The key is not stored.",
						label: "Recovery key",
						password: true,
						submit: "Recover",
					});
					if (identity === null) return;
					b.setDisabled(true);
					status.setText("Recovering…");
					try {
						await recover(identity);
						status.setText("Recovered. Connecting…");
					} catch (e) {
						b.setDisabled(false);
						status.setText(recoveryError(e));
					}
				}),
			);
		}
		buttons.addButton((b) => b.setButtonText("Cancel").onClick(() => this.close()));
	}

	/** Close after approval, without cancelling. */
	finish(): void {
		this.finished = true;
		this.close();
	}

	override onClose(): void {
		this.contentEl.empty();
		if (!this.finished) this.onCancel();
	}
}

function recoveryError(e: unknown): string {
	const code = (e as { code?: unknown } | null)?.code;
	if (code === "not-a-recipient" || (e instanceof Error && e.message === "not a recovery key")) {
		return "This is not the recovery key of this vault.";
	}
	if (code === "no_recovery") return "This vault has no recovery key.";
	return e instanceof Error && e.message ? e.message : "Recovery failed.";
}

export interface PendingApproval {
	name: string;
	code: string;
	approve(): Promise<void>;
}

/** Lists the devices waiting for approval, each with its pairing code. */
export class ApproveModal extends Modal {
	constructor(
		app: App,
		private readonly pending: PendingApproval[],
	) {
		super(app);
	}

	override onOpen(): void {
		this.setTitle("Approve devices");
		if (this.pending.length === 0) {
			this.contentEl.createEl("p", { text: "No device is waiting for approval." });
			return;
		}
		this.contentEl.createEl("p", {
			text: "Approve a device only if it shows exactly the same code. An approved device can read the whole vault.",
		});
		for (const item of this.pending) {
			const setting = new Setting(this.contentEl).setName(item.name).setDesc(item.code);
			setting.addButton((b: ButtonComponent) =>
				b
					.setButtonText("Codes match, approve")
					.setCta()
					.onClick(async () => {
						b.setDisabled(true);
						try {
							await item.approve();
							setting.setDesc(`${item.code}: approved`);
							b.buttonEl.remove();
						} catch (e) {
							b.setDisabled(false);
							setting.setDesc(`${item.code}: ${e instanceof Error ? e.message : "approval failed"}`);
						}
					}),
			);
		}
	}

	override onClose(): void {
		this.contentEl.empty();
	}
}

interface ConfirmOptions {
	title: string;
	text: string;
	confirm: string;
	cancel?: string;
	warning?: boolean;
	/** A toggle shown above the buttons; its value is passed to `onConfirm`. */
	option?: string;
	onConfirm(option: boolean): void | Promise<void>;
}

/** A question with a confirm and a cancel button. */
export class ConfirmModal extends Modal {
	constructor(
		app: App,
		private readonly opts: ConfirmOptions,
	) {
		super(app);
	}

	override onOpen(): void {
		this.setTitle(this.opts.title);
		this.contentEl.createEl("p", { text: this.opts.text });
		let option = false;
		if (this.opts.option) {
			new Setting(this.contentEl).setName(this.opts.option).addToggle((t) => t.onChange((v) => (option = v)));
		}
		new Setting(this.contentEl)
			.addButton((b) => b.setButtonText(this.opts.cancel ?? "Cancel").onClick(() => this.close()))
			.addButton((b) => {
				b.setButtonText(this.opts.confirm).onClick(() => {
					this.close();
					void this.opts.onConfirm(option);
				});
				if (this.opts.warning) b.setDestructive();
				else b.setCta();
			});
	}

	override onClose(): void {
		this.contentEl.empty();
	}
}

/** Asks to reload Obsidian after another device changed the settings, plugins or themes. */
export class ReloadModal extends Modal {
	constructor(
		app: App,
		private readonly reload: () => void,
	) {
		super(app);
	}

	override onOpen(): void {
		this.setTitle("Reload Obsidian?");
		this.contentEl.createEl("p", {
			text: "Settings, plugins or themes changed on another device. Obsidian uses them after a reload.",
		});
		new Setting(this.contentEl)
			.addButton((b) => b.setButtonText("Later").onClick(() => this.close()))
			.addButton((b) =>
				b
					.setButtonText("Reload")
					.setCta()
					.onClick(() => {
						this.close();
						this.reload();
					}),
			);
	}

	override onClose(): void {
		this.contentEl.empty();
	}
}

/** Keys, secrets and names must reach us as typed: mobile keyboards would change them. */
function noAutocorrect(el: HTMLInputElement | HTMLTextAreaElement): void {
	el.setAttr("autocapitalize", "off");
	el.setAttr("autocorrect", "off");
	el.setAttr("autocomplete", "off");
	el.spellcheck = false;
}
