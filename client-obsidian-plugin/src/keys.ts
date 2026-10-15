/** The device key in `SecretStorage` (docs/crypto.md 3.3): one key per server, user and vault. */
import { sha256 } from "@noble/hashes/sha2.js";
import type { App } from "obsidian";

import { hex, utf8 } from "./crypto/bytes";
import { isEncryptedOpenSshKey, parseOpenSshPrivateKey, publicKeyText, SshKeyError, type OpenSshKey } from "./crypto/openssh";

/** The server's form of a vault name: NFC, trimmed. The keyring and the login use it too. */
export function normalizeVaultName(name: string): string {
	return name.normalize("NFC").trim();
}

/**
 * `syncryption-key-` + the first 8 bytes of SHA-256(origin + "\n" + username + "\n" +
 * vault name), in hex. A key belongs to one vault, so each vault has its own slot.
 */
export function secretId(origin: string, username: string, vaultName: string): string {
	const input = `${origin}\n${username}\n${normalizeVaultName(vaultName)}`;
	return `syncryption-key-${hex(sha256(utf8(input)).slice(0, 8))}`;
}

export function loadKeyText(app: App, id: string): string | null {
	return app.secretStorage.getSecret(id);
}

export function saveKeyText(app: App, id: string, pem: string): void {
	app.secretStorage.setSecret(id, pem);
}

/**
 * The public key text of the key stored at `id`, or null if there is none (or it can't be
 * read without a passphrase).
 */
export function storedPublicKey(app: App, id: string): string | null {
	const pem = loadKeyText(app, id);
	if (pem === null) return null;
	try {
		if (isEncryptedOpenSshKey(pem)) return null;
		const key = parseOpenSshPrivateKey(pem);
		return publicKeyText(key.publicKey, key.comment);
	} catch {
		return null;
	}
}

/** Parse a stored key, asking for its passphrase if it has one. Null if the user cancels. */
export async function unlockKey(pem: string, askPassphrase: (retry: boolean) => Promise<string | null>): Promise<OpenSshKey | null> {
	if (!isEncryptedOpenSshKey(pem)) return parseOpenSshPrivateKey(pem);
	for (let retry = false; ; retry = true) {
		const passphrase = await askPassphrase(retry);
		if (passphrase === null) return null;
		try {
			return parseOpenSshPrivateKey(pem, passphrase);
		} catch (e) {
			if (!(e instanceof SshKeyError && e.code === "wrong-passphrase")) throw e;
		}
	}
}
