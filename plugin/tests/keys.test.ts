import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import { hex, utf8 } from "../src/crypto/bytes";
import { generateDeviceKey, writeOpenSshPrivateKey } from "../src/crypto/openssh";
import { secretId, unlockKey } from "../src/keys";

describe("secretId", () => {
	it("depends on the server, username and vault", () => {
		const id = secretId("https://sync.example.com", "alice", "Notes");
		expect(id).toMatch(/^syncryption-key-[0-9a-f]{16}$/);
		expect(secretId("https://sync.example.com", "alice", "Notes")).toBe(id);
		expect(secretId("https://sync.example.com", "bob", "Notes")).not.toBe(id);
		expect(secretId("https://other.example.com", "alice", "Notes")).not.toBe(id);
		expect(secretId("https://sync.example.com", "alice", "Work")).not.toBe(id);
	});

	it("is SHA-256 of origin, username and the NFC, trimmed vault name", () => {
		const expected = `syncryption-key-${hex(sha256(utf8("https://sync.example.com\nalice\nCaf\u00e9")).slice(0, 8))}`;
		expect(secretId("https://sync.example.com", "alice", " Cafe\u0301 ")).toBe(expected);
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
