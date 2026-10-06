/** Settings: endpoint, username, vault name, device name, the device key and the exclude list (docs/PLAN.md). */
import { App, Notice, Platform, PluginSettingTab, type Setting, type SettingDefinition, type SettingDefinitionGroup, type SettingDefinitionItem } from "obsidian";

import { normalizeEndpoint } from "./api/client";
import { cleanDeviceName, defaultDeviceName, desktopHostname } from "./device";
import { fingerprint, generateDeviceKey, parsePublicKeyText, publicKeyText, writeOpenSshPrivateKey } from "./crypto/openssh";
import { saveKeyText, secretId } from "./keys";
import type SyncryptionPlugin from "./main";
import { ConfirmModal, prompt } from "./ui/modals";

export interface SyncryptionSettings {
	endpoint: string;
	username: string;
	vaultName: string;
	/** A friendly name for this installation. Starts as the hostname; data.json isn't synced. */
	deviceName: string;
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
	deviceName: "",
	keyId: "",
	publicKey: "",
	exclude: "",
};

export function isConfigured(s: SyncryptionSettings): boolean {
	return s.endpoint !== "" && s.username !== "" && s.vaultName !== "" && s.keyId !== "";
}

/** The hostname on desktop, else a platform name such as "iPhone". */
export function initialDeviceName(): string {
	return defaultDeviceName(Platform, desktopHostname(Platform));
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
			{ name: "Encryption key", aliases: ["SSH", "SSH key", "Ed25519", "Private key", "Generate"], render: (setting) => this.renderKey(setting) },
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
		else if (key === "deviceName") settings.deviceName = cleanDeviceName(text) || initialDeviceName();
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
			setting.setDesc("Generate an encryption key for this device. Each device has its own key, and a device that already syncs the vault approves it.");
		}
		setting.addButton((b) => b.setButtonText("Generate").onClick(() => this.generate()));
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
			title: "Replace the encryption key?",
			description:
				"This device will use a new key, so it must join and be approved again. Type REPLACE to continue.",
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

	private async store(id: string, pem: string, publicKey: string): Promise<void> {
		saveKeyText(this.app, id, pem);
		this.plugin.settings.keyId = id;
		this.plugin.settings.publicKey = publicKey;
		await this.plugin.saveSettings();
		this.plugin.forgetKey();
		new Notice("Encryption key saved.");
		this.update();
	}
}
