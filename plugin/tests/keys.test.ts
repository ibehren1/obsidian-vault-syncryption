import { describe, expect, it } from "vitest";

import { generateDeviceKey, writeOpenSshPrivateKey } from "../src/crypto/openssh";
import { secretId, unlockKey } from "../src/keys";

describe("secretId", () => {
	it("depends on the server and username", () => {
		const id = secretId("https://sync.example.com", "alice");
		expect(id).toMatch(/^syncryption-key-[0-9a-f]{16}$/);
		expect(secretId("https://sync.example.com", "alice")).toBe(id);
		expect(secretId("https://sync.example.com", "bob")).not.toBe(id);
		expect(secretId("https://other.example.com", "alice")).not.toBe(id);
	});
});

describe("unlockKey", () => {
	const key = generateDeviceKey();

	it("doesn't ask for a passphrase when there is none", async () => {
		const unlocked = await unlockKey(writeOpenSshPrivateKey(key.seed), () => {
			throw new Error("asked");
		});
		expect(unlocked!.seed).toEqual(key.seed);
	});

	it("asks again after a wrong passphrase, and stops when cancelled", async () => {
		const pem = writeOpenSshPrivateKey(key.seed, { passphrase: "right", rounds: 1 });
		const answers = ["wrong", "right"];
		const retries: boolean[] = [];
		const unlocked = await unlockKey(pem, async (retry) => {
			retries.push(retry);
			return answers.shift()!;
		});
		expect(unlocked!.seed).toEqual(key.seed);
		expect(retries).toEqual([false, true]);
		expect(await unlockKey(pem, async () => null)).toBeNull();
	});
});
