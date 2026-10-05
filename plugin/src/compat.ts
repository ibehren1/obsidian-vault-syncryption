import type { App } from "obsidian";

/** Same as `minAppVersion` in manifest.json: SecretStorage and the declarative settings API. */
export const MIN_APP_VERSION = "1.13.0";

/** The private key is stored only in SecretStorage, so the plugin can't run without it. */
export function hasSecretStorage(app: App): boolean {
	return typeof app.secretStorage?.getSecret === "function";
}
