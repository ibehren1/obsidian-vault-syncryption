/** Settings: endpoint, username, vault name, device name, the device key and the exclude list (docs/PLAN.md). */
import { App, Notice, Platform, PluginSettingTab, type Setting, type SettingDefinition, type SettingDefinitionGroup, type SettingDefinitionItem } from "obsidian";

import { normalizeEndpoint } from "./api/client";
import { cleanDeviceName, defaultDeviceName, desktopHostname, keyComment } from "./device";
import { fingerprint, generateDeviceKey, parsePublicKeyText, publicKeyText, writeOpenSshPrivateKey } from "./crypto/openssh";
import { normalizeVaultName, saveKeyText, secretId, storedPublicKey } from "./keys";
import type SyncryptionPlugin from "./main";
import { ConfirmModal, prompt } from "./ui/modals";

export interface SyncryptionSettings {
	endpoint: string;
	username: string;
	vaultName: string;
	/** A friendly name for this installation. Starts as the hostname; data.json isn't synced. */
	deviceName: string;
	/**
	 * The SecretStorage id of the private key for the current server, username and vault
	 * (`currentKeySlot`). The key itself is never stored here.
	 */
	keyId: string;
	/** OpenSSH public key text of that key, to show and copy. */
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
	return s.keyId !== "" && s.keyId === currentKeySlot(s);
}

/** The key slot of the server, username and vault in the settings, or null if one is missing. */
export function currentKeySlot(s: SyncryptionSettings): string | null {
	if (s.username === "" || normalizeVaultName(s.vaultName) === "") return null;
	try {
		return secretId(normalizeEndpoint(s.endpoint), s.username, s.vaultName);
	} catch {
		return null;
	}
}

/**
 * Point `keyId` and `publicKey` at the key of the current server, username and vault:
 * the key in that slot, or none (Generate is needed). Other slots are kept. Returns
 * whether the settings changed.
 */
export function syncKeySlot(app: App, s: SyncryptionSettings): boolean {
	const slot = currentKeySlot(s);
	if (slot !== null && slot === s.keyId) return false;
	const publicKey = slot === null ? null : storedPublicKey(app, slot);
	const keyId = publicKey === null ? "" : slot!;
	if (s.keyId === keyId && s.publicKey === (publicKey ?? "")) return false;
	s.keyId = keyId;
	s.publicKey = publicKey ?? "";
	return true;
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
			{
				name: "Encryption key",
				aliases: ["SSH", "SSH key", "Ed25519", "Private key", "Generate", "Fingerprint"],
				render: (setting) => this.renderKey(setting),
			},
			{
				name: "Excluded paths",
				desc: "Files and folders this device doesn't sync, one per line. Use * to match within a folder name and ** to match across folders, for example *.mp4.",
				control: { type: "textarea", key: "exclude", placeholder: "Private\n**/*.mp4", rows: 4 },
			},
			{
				name: "Connect",
				render: (setting) => {
					// Follows the connection and the progress of a sync while the tab is open.
					this.plugin.onStatus = (text) => {
						setting.setDesc(text);
					};
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
				name: "Approve new keys",
				render: (setting) => {
					setting
						.setDesc("New keys of this vault wait here until a device that syncs the vault approves them.")
						.addButton((b) => b.setButtonText("Approve").onClick(() => void this.plugin.openApprovals()));
					void this.plugin.pendingCount().then(
						(n) => {
							if (n === null) setting.setDesc("Connect first to approve new keys.");
							else if (n > 0) setting.setDesc(`${n === 1 ? "1 key is" : `${n} keys are`} waiting for approval.`);
							else setting.setDesc("No keys are waiting for approval.");
						},
						() => {},
					);
				},
			},
			this.vaultKeys(),
			{ name: "Recovery key", render: (setting) => this.renderRecovery(setting) },
		];
	}

	override hide(): void {
		this.plugin.onStatus = null;
		super.hide();
	}

	/** Trim the text fields; a new exclude list rebuilds the path filter. */
	override async setControlValue(key: string, value: unknown): Promise<void> {
		const settings = this.plugin.settings;
		const text = typeof value === "string" ? value : "";
		if (key === "exclude") settings.exclude = text;
		else if (key === "endpoint" || key === "username" || key === "vaultName") settings[key] = text.trim();
		else if (key === "deviceName") settings.deviceName = cleanDeviceName(text) || initialDeviceName();
		else return;
		// Each server, username and vault has its own key slot.
		if (key !== "exclude") syncKeySlot(this.app, settings);
		await this.plugin.saveSettings();
		if (key === "exclude") this.plugin.updateExcludes();
	}

	private renderKey(setting: Setting): void {
		const settings = this.plugin.settings;
		if (syncKeySlot(this.app, settings)) void this.plugin.saveSettings();
		if (isConfigured(settings)) {
			setting.setDesc(fingerprint(parsePublicKeyText(settings.publicKey)));
			setting.descEl.createDiv({ text: `${settings.deviceName} · ${settings.username} / ${normalizeVaultName(settings.vaultName)}` });
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
		} else if (currentKeySlot(settings) === null) {
			setting.setDesc("Enter the server URL, username and vault name, then generate this device's key for the vault.");
		} else {
			setting.setDesc(
				"Generate this device's key for this vault. Each device has its own key for each vault, and a device that already syncs the vault approves it.",
			);
		}
		setting.addButton((b) => b.setButtonText("Generate").onClick(() => this.generate()));
	}

	/** Every key in the vault's keyring, with the server's status when it answers. */
	private vaultKeys(): SettingDefinitionGroup {
		const keys = this.plugin.vaultKeys();
		const status = this.plugin.vaultKeyStatus();
		let note: string;
		if (keys === null) note = "Connect first to see the keys of this vault.";
		else if (keys.length <= 1) note = "Only this device's key can open this vault.";
		else note = "Each key is one device's access to this vault. Remove the key of a lost or old device to end its access.";
		const removable = (keys?.length ?? 0) > 1;
		return {
			type: "group",
			heading: "Vault keys",
			items: [
				{ name: "Keys", desc: note, searchable: false },
				...(keys ?? []).map(
					(key): SettingDefinition => ({
						name: fingerprint(parsePublicKeyText(key.publicKey)),
						searchable: false,
						render: (setting) => {
							const parts = [key.name, `added ${formatDate(key.added)}`];
							if (key.self) parts.push("This device");
							setting.setDesc(parts.join(" · "));
							const server = setting.descEl.createDiv();
							void status?.then(
								(devices) => {
									const device = devices.get(key.id);
									if (!device) server.setText("Not on the server");
									else if (device.status === "active") {
										server.setText(device.lastSeenAt ? `Active · last seen ${formatDate(device.lastSeenAt)}` : "Active");
									} else server.setText(device.status === "pending" ? "Waiting for approval" : "Revoked");
								},
								() => {},
							);
							if (key.self || !removable) return;
							setting.addButton((b) =>
								b
									.setButtonText("Remove")
									.setDestructive()
									.onClick(() => {
										new ConfirmModal(this.app, {
											title: `Remove the key of ${key.name}?`,
											text: "That device can no longer sync this vault. The vault gets a new key, and this device re-encrypts the files with it in the background. Files the device already has stay on it.",
											confirm: "Remove",
											warning: true,
											onConfirm: async () => {
												if (await this.plugin.removeDevice(key.id)) this.update();
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

	/** The secret id depends on the server, username and vault, so those come first. */
	private keySlot(): string | null {
		const slot = currentKeySlot(this.plugin.settings);
		if (slot === null) {
			const settings = this.plugin.settings;
			try {
				normalizeEndpoint(settings.endpoint);
				new Notice("Enter the username and vault name first.");
			} catch (e) {
				new Notice(e instanceof Error ? e.message : "Enter the server URL first.");
			}
		}
		return slot;
	}

	/** Type REPLACE to replace the key of this vault on this device. */
	private async confirmReplace(handOver: boolean): Promise<boolean> {
		const answer = await prompt(this.app, {
			title: "Replace the encryption key?",
			description: handOver
				? "This device gets a new key for this vault. The current key approves the new one, then it is removed and the vault gets a new key. Type REPLACE to continue."
				: "This device gets a new key for this vault. It isn't connected with the current key, so the new key must be approved again on a device that syncs the vault, or with the recovery key. Type REPLACE to continue.",
			label: "Confirm",
			submit: "Replace",
		});
		return answer === "REPLACE";
	}

	/** Ask for this device's name, prefilled with the current one. Null if cancelled. */
	private async askDeviceName(): Promise<string | null> {
		const settings = this.plugin.settings;
		for (;;) {
			const answer = await prompt(this.app, {
				title: "Device name",
				description: "Other devices of this vault see this name with the key, for example when it waits for approval.",
				label: "Device name",
				value: cleanDeviceName(settings.deviceName) || initialDeviceName(),
				submit: "Generate",
				cancel: "Cancel",
			});
			if (answer === null) return null;
			const name = cleanDeviceName(answer);
			if (name !== "") return name;
			new Notice("Enter a device name.");
		}
	}

	private async generate(): Promise<void> {
		const settings = this.plugin.settings;
		const id = this.keySlot();
		if (id === null) return;
		if (syncKeySlot(this.app, settings)) await this.plugin.saveSettings();
		const replacing = settings.keyId === id;
		const handOver = replacing && this.plugin.canHandOver(id);
		if (replacing && !(await this.confirmReplace(handOver))) return;
		const deviceName = await this.askDeviceName();
		if (deviceName === null) return;
		settings.deviceName = deviceName;
		await this.plugin.saveSettings();
		const key = generateDeviceKey(keyComment(settings.username, deviceName));
		if (handOver) {
			new Notice("Replacing the encryption key…");
			// On failure the current key stays, and still works.
			await this.plugin.replaceKey(id, key);
			this.update();
			return;
		}
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

/** A date for the key list, in the user's locale. */
function formatDate(iso: string): string {
	const date = new Date(iso);
	return Number.isNaN(date.getTime()) ? iso : date.toLocaleDateString();
}
