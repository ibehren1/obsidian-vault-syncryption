/// <reference types="node" />
/**
 * Interop with the reference command-line tools (docs/crypto.md 10): plugin output must
 * decrypt with Go `age` and verify with `ssh-keygen -Y verify`.
 *
 * `age` is found through `$AGE` or `PATH`. Without it these tests are skipped, unless
 * `REQUIRE_AGE=1` (set in CI), where a missing binary fails the run.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { Encrypter } from "age-encryption";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import { SshEd25519Recipient } from "../src/crypto/age-ssh";
import { fromUtf8, utf8 } from "../src/crypto/bytes";
import { createKeyring, generateRecoveryKey, sealKeyring } from "../src/crypto/keyring";
import { publicKeyText, writeOpenSshPrivateKey } from "../src/crypto/openssh";
import { NAMESPACE_KEYRING, signSshsig } from "../src/crypto/sshsig";

const AGE = process.env.AGE ?? "age";
const haveAge = spawnSync(AGE, ["--version"]).status === 0;
if (!haveAge && process.env.REQUIRE_AGE === "1") {
	throw new Error(`REQUIRE_AGE=1 but no working age binary at ${AGE}`);
}

const dir = mkdtempSync(join(tmpdir(), "syncryption-cli-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function file(name: string, data: string | Uint8Array, mode = 0o600): string {
	const path = join(dir, name);
	writeFileSync(path, data, { mode });
	return path;
}

const seed = crypto.getRandomValues(new Uint8Array(32));
const publicKey = ed25519.getPublicKey(seed);
const keyPath = file("id_ed25519", writeOpenSshPrivateKey(seed, { comment: "test" }));

function ageDecrypt(identityPath: string, input: Uint8Array): string {
	return execFileSync(AGE, ["-d", "-i", identityPath], { input, encoding: "utf8" });
}

describe.skipIf(!haveAge)("Go age", () => {
	it("decrypts a file the plugin encrypted to an ssh-ed25519 key", async () => {
		const e = new Encrypter();
		e.addRecipient(new SshEd25519Recipient(publicKey));
		const other = crypto.getRandomValues(new Uint8Array(32));
		e.addRecipient(new SshEd25519Recipient(ed25519.getPublicKey(other)));
		const ct = await e.encrypt(utf8("hello from the plugin\n"));
		expect(ageDecrypt(keyPath, ct)).toBe("hello from the plugin\n");
	});

	it("decrypts a sealed keyring with the device key and the recovery key", async () => {
		const recovery = await generateRecoveryKey();
		const device = { id: "d_cli", name: "cli", publicKey: publicKeyText(publicKey) };
		const keyring = createKeyring({ vaultId: "v-cli", name: "CLI", device, recovery });
		const blob = await sealKeyring(keyring, seed);
		expect(JSON.parse(ageDecrypt(keyPath, blob.keyring))).toEqual(keyring);
		const recoveryPath = file("recovery.txt", recovery.identity + "\n");
		expect(JSON.parse(ageDecrypt(recoveryPath, blob.keyring))).toEqual(keyring);
	});
});

describe("ssh-keygen -Y verify", () => {
	it("accepts a plugin keyring signature", () => {
		const message = utf8("keyring bytes");
		const sig = file("msg.sig", signSshsig(seed, NAMESPACE_KEYRING, message));
		const signers = file("allowed_signers", `device ${publicKeyText(publicKey)}\n`);
		const out = execFileSync(
			"ssh-keygen",
			["-Y", "verify", "-f", signers, "-I", "device", "-n", NAMESPACE_KEYRING, "-s", sig],
			{ input: message },
		);
		expect(fromUtf8(out)).toContain("Good");
	});
});
