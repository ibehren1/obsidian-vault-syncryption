/** The device key in `SecretStorage` (docs/crypto.md 3.3). */
import { sha256 } from "@noble/hashes/sha2.js";
import type { App } from "obsidian";

import { hex, utf8 } from "./crypto/bytes";
import { isEncryptedOpenSshKey, parseOpenSshPrivateKey, SshKeyError, type OpenSshKey } from "./crypto/openssh";

/** `syncryption-key-` + the first 8 bytes of SHA-256(origin + "\n" + username), in hex. */
export function secretId(origin: string, username: string): string {
	return `syncryption-key-${hex(sha256(utf8(`${origin}\n${username}`)).slice(0, 8))}`;
}

export function loadKeyText(app: App, id: string): string | null {
	return app.secretStorage.getSecret(id);
}

export function saveKeyText(app: App, id: string, pem: string): void {
	app.secretStorage.setSecret(id, pem);
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
