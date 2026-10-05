/** Creating a recovery key (docs/crypto.md 9): shown once, set only after the user stored it. */
import { App, Modal, Notice, Setting } from "obsidian";

/**
 * Show a new recovery key once. Resolves true if the user confirmed they stored it, and
 * false if the dialog was closed first (then the key isn't set).
 */
export function showRecoveryKey(app: App, identity: string): Promise<boolean> {
	return new Promise((resolve) => new RecoveryKeyModal(app, identity, resolve).open());
}

class RecoveryKeyModal extends Modal {
	private stored = false;

	constructor(
		app: App,
		private readonly identity: string,
		private readonly done: (stored: boolean) => void,
	) {
		super(app);
	}

	override onOpen(): void {
		this.setTitle("Your recovery key");
		this.contentEl.createEl("p", {
			text: "If every device of this vault is lost, this key lets a new device read the vault and add itself. Store it offline, for example in a password manager or on paper. It is shown only now and is not stored on any device or on the server.",
		});
		this.contentEl.createEl("p", { text: this.identity, cls: "syncryption-code syncryption-secret" });
		this.contentEl.createEl("p", {
			text: "Anyone with this key, an account and access to the server can read the vault. Keep it as safe as the vault itself.",
			cls: "mod-warning",
		});
		let confirmed = false;
		let save: HTMLButtonElement | null = null;
		new Setting(this.contentEl).setName("I have stored the recovery key").addToggle((t) =>
			t.onChange((v) => {
				confirmed = v;
				save?.toggleAttribute("disabled", !v);
			}),
		);
		new Setting(this.contentEl)
			.addButton((b) =>
				b.setButtonText("Copy").onClick(async () => {
					try {
						await navigator.clipboard.writeText(this.identity);
						new Notice("Recovery key copied. Clear it from the clipboard after storing it.");
					} catch {
						new Notice("Couldn't copy. Select the key above and copy it by hand.");
					}
				}),
			)
			.addButton((b) => {
				save = b.buttonEl;
				b.setButtonText("Use this key")
					.setCta()
					.setDisabled(true)
					.onClick(() => {
						if (!confirmed) return;
						this.stored = true;
						this.close();
					});
			});
	}

	override onClose(): void {
		this.contentEl.empty();
		this.done(this.stored);
	}
}
