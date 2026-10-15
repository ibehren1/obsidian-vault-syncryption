import type { App } from "obsidian";
import { describe, expect, it } from "vitest";

import { hasSecretStorage } from "../src/compat";

describe("hasSecretStorage", () => {
	it("is true when the app exposes SecretStorage", () => {
		const app = { secretStorage: { getSecret: () => null } } as unknown as App;
		expect(hasSecretStorage(app)).toBe(true);
	});

	it("is false on Obsidian versions without SecretStorage", () => {
		expect(hasSecretStorage({} as App)).toBe(false);
	});
});
