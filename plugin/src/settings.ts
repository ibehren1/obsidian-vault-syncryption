/** Settings: endpoint, username, vault name, the device key and the exclude list (docs/PLAN.md). */
import { App, Notice, Platform, PluginSettingTab, type Setting, type SettingDefinition, type SettingDefinitionGroup, type SettingDefinitionItem } from "obsidian";

import { normalizeEndpoint } from "./api/client";
import { fingerprint, generateDeviceKey, isEncryptedOpenSshKey, parseOpenSshPrivateKey, parsePublicKeyText, publicKeyText, writeOpenSshPrivateKey } from "./crypto/openssh";
import { saveKeyText, secretId, unlockKey } from "./keys";
import type SyncryptionPlugin from "./main";
import { ConfirmModal, prompt } from "./ui/modals";

export interface SyncryptionSettings {
	endpoint: string;
	username: string;
	vaultName: string;
	/** The SecretStorage id of the private key. The key itself is never stored here. */
	keyId: string;
	/** OpenSSH public key text, to show and copy. */
	publicKey: string;
	/** Paths this device doesn't sync, one pattern per line. */
	exclude: string;
}

export const DEFAULT_SETTINGS: SyncryptionSettings = {
	endpoint: "",
	username: "",
	vaultName: "",
	keyId: "",
	publicKey: "",
	exclude: "",
};

export function isConfigured(s: SyncryptionSettings): boolean {
	return s.endpoint !== "" && s.username !== "" && s.vaultName !== "" && s.keyId !== "";
}

export class SyncryptionSettingTab extends PluginSettingTab {
	constructor(
		app: App,
		private readonly plugin: SyncryptionPlugin,
	) {
		super(app, plugin);
	}

	/** Declarative settings (Obsidian 1.13). Call `update()` after a change that adds or removes rows. */
	override getSettingDefinitions(): SettingDefinitionItem[] {
		return [
			{
				name: "Mobile support is in beta",
				desc: "Keep a backup of your vault.",
				visible: Platform.isMobile,
				searchable: false,
			},
			{
				name: "Server URL",
				desc: "The address of your sync server.",
				control: { type: "text", key: "endpoint", placeholder: "https://sync.example.com" },
			},
			{
				name: "Username",
				desc: "Your account on the server. It is created the first time you connect.",
				control: { type: "text", key: "username" },
			},
			{
				name: "Vault name",
				desc: "The vault on the server. Use the same name on every device that syncs this vault.",
				control: { type: "text", key: "vaultName" },
			},
			{ name: "SSH key", aliases: ["Ed25519", "Import", "Generate"], render: (setting) => this.renderKey(setting) },
			{
				name: "Excluded paths",
				desc: "Files and folders this device doesn't sync, one per line. Use * to match within a folder name and ** to match across folders, for example *.mp4.",
				control: { type: "textarea", key: "exclude", placeholder: "Private\n**/*.mp4", rows: 4 },
			},
			{
				name: "Connect",
				render: (setting) => {
					setting.setDesc(this.plugin.statusText()).addButton((b) =>
						b
							.setButtonText("Connect")
							.setCta()
							.onClick(async () => {
								await this.plugin.restart();
								this.update();
							}),
					);
				},
			},
			{
				name: "Approve devices",
				render: (setting) => {
					setting
						.setDesc("New devices of this vault wait here until a connected device approves them.")
						.addButton((b) => b.setButtonText("Approve devices").onClick(() => void this.plugin.openApprovals()));
					void this.plugin.pendingCount().then(
						(n) => {
							if (n === null) setting.setDesc("Connect first to approve new devices.");
							else if (n > 0) setting.setDesc(`${n === 1 ? "1 device is" : `${n} devices are`} waiting for approval.`);
							else setting.setDesc("No devices are waiting for approval.");
						},
						() => {},
					);
				},
			},
			this.devices(),
			{ name: "Recovery key", render: (setting) => this.renderRecovery(setting) },
		];
	}

	/** Trim the text fields; a new exclude list rebuilds the path filter. */
	override async setControlValue(key: string, value: unknown): Promise<void> {
		const settings = this.plugin.settings;
		const text = typeof value === "string" ? value : "";
		if (key === "exclude") settings.exclude = text;
		else if (key === "endpoint" || key === "username" || key === "vaultName") settings[key] = text.trim();
		else return;
		await this.plugin.saveSettings();
		if (key === "exclude") this.plugin.updateExcludes();
	}

	private renderKey(setting: Setting): void {
		const settings = this.plugin.settings;
		if (settings.publicKey) {
			setting.setDesc(`Ed25519 ${fingerprint(parsePublicKeyText(settings.publicKey))}`);
			setting.addButton((b) =>
				b.setButtonText("Copy public key").onClick(async () => {
					try {
						await navigator.clipboard.writeText(settings.publicKey);
						new Notice("Public key copied.");
					} catch {
						new Notice(`Couldn't copy. Your public key: ${settings.publicKey}`, 0);
					}
				}),
			);
		} else {
			setting.setDesc("Generate a key for this device, or import an SSH key (type ed25519) you already use with this account.");
		}
		setting.addButton((b) => b.setButtonText("Generate").onClick(() => this.generate()));
		setting.addButton((b) => b.setButtonText("Import").onClick(() => this.import()));
	}

	private devices(): SettingDefinitionGroup {
		const devices = this.plugin.keyringDevices();
		let note: string;
		if (devices === null) note = "Connect first to see the devices of this vault.";
		else if (devices.length === 0) note = "No other devices sync this vault.";
		else note = "The other devices that sync this vault. Remove a lost or old device to end its access.";
		return {
			type: "group",
			heading: "Devices",
			items: [
				{ name: "Other devices", desc: note, searchable: false },
				...(devices ?? []).map(
					(device): SettingDefinition => ({
						name: device.name,
						searchable: false,
						render: (setting) => {
							setting.addButton((b) =>
								b
									.setButtonText("Remove")
									.setDestructive()
									.onClick(() => {
										new ConfirmModal(this.app, {
											title: `Remove ${device.name}?`,
											text: "It can no longer sync this vault. The vault gets a new key, and this device re-encrypts the files with it in the background. Files the device already has stay on it.",
											option: "Also remove it from every other vault of this account",
											confirm: "Remove",
											warning: true,
											onConfirm: async (everywhere) => {
												if (await this.plugin.removeDevice(device.id, everywhere)) this.update();
											},
										}).open();
									}),
							);
						},
					}),
				),
			],
		};
	}

	private renderRecovery(setting: Setting): void {
		const status = this.plugin.recoveryStatus();
		if (status === null) {
			setting.setDesc("Connect first to create or change the recovery key.");
			return;
		}
		if (!status.set) {
			setting.setDesc("Not set. Without a recovery key, losing every device of this vault means losing the vault.");
			setting.addButton((b) =>
				b
					.setButtonText("Create recovery key")
					.setCta()
					.onClick(async () => {
						if (await this.plugin.createRecoveryKey()) this.update();
					}),
			);
			return;
		}
		setting.setDesc(`Set by ${status.setBy}. Replace it if someone else may have seen it.`);
		setting.addButton((b) =>
			b.setButtonText("Replace").onClick(async () => {
				if (await this.plugin.createRecoveryKey()) this.update();
			}),
		);
		setting.addButton((b) =>
			b
				.setButtonText("Remove")
				.setDestructive()
				.onClick(() => {
					new ConfirmModal(this.app, {
						title: "Remove the recovery key?",
						text: "The recovery key can no longer add devices, and new changes are encrypted with a new key it can't open. Without a recovery key, losing every device of this vault means losing the vault.",
						confirm: "Remove",
						warning: true,
						onConfirm: async () => {
							if (await this.plugin.removeRecoveryKey()) this.update();
						},
					}).open();
				}),
		);
	}

	/** The secret id depends on the server and username, so those come first. */
	private keySlot(): string | null {
		const settings = this.plugin.settings;
		try {
			if (settings.username === "") throw new Error("Enter the username first.");
			return secretId(normalizeEndpoint(settings.endpoint), settings.username);
		} catch (e) {
			new Notice(e instanceof Error ? e.message : "Enter the server URL and username first.");
			return null;
		}
	}

	private async confirmReplace(): Promise<boolean> {
		if (!this.plugin.settings.publicKey) return true;
		const answer = await prompt(this.app, {
			title: "Replace the SSH key?",
			description:
				"This device will use the new key. Unless the key is already known to the server, it must join and be approved again. Type REPLACE to continue.",
			label: "Confirm",
			submit: "Replace",
		});
		return answer === "REPLACE";
	}

	private async generate(): Promise<void> {
		const id = this.keySlot();
		if (id === null || !(await this.confirmReplace())) return;
		const key = generateDeviceKey(`syncryption ${this.plugin.settings.username}`);
		await this.store(id, writeOpenSshPrivateKey(key.seed, { comment: key.comment }), publicKeyText(key.publicKey, key.comment));
	}

	private async import(): Promise<void> {
		const id = this.keySlot();
		if (id === null) return;
		const pem = await prompt(this.app, {
			title: "Import an SSH key",
			description: "Paste an OpenSSH Ed25519 private key (the contents of a file like ~/.ssh/id_ed25519). It is stored only in Obsidian's secret storage.",
			label: "Private key",
			multiline: true,
			submit: "Import",
		});
		if (pem === null || !(await this.confirmReplace())) return;
		try {
			const key = isEncryptedOpenSshKey(pem)
				? await unlockKey(pem, (retry) => this.plugin.askPassphrase(retry))
				: parseOpenSshPrivateKey(pem);
			if (key === null) return;
			// Stored as imported, with its passphrase if it has one (crypto.md 3.3).
			await this.store(id, pem.trim() + "\n", publicKeyText(key.publicKey, key.comment));
		} catch (e) {
			new Notice(e instanceof Error ? e.message : "The key couldn't be imported.");
		}
	}

	private async store(id: string, pem: string, publicKey: string): Promise<void> {
		saveKeyText(this.app, id, pem);
		this.plugin.settings.keyId = id;
		this.plugin.settings.publicKey = publicKey;
		await this.plugin.saveSettings();
		this.plugin.forgetKey();
		new Notice("SSH key saved.");
		this.update();
	}
}
