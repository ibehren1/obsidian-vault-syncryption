/// <reference types="node" />
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import { fromHex, hex } from "../src/crypto/bytes";
import {
	generateDeviceKey,
	parseOpenSshPrivateKey,
	publicKeyText,
	SshKeyError,
	writeOpenSshPrivateKey,
} from "../src/crypto/openssh";

interface Valid {
	name: string;
	pem: string;
	passphrase: string;
	seed: string;
	comment: string;
	checkint: number;
	salt?: string;
	rounds?: number;
}

const vectors = JSON.parse(
	readFileSync(new URL("../../testvectors/openssh-keys.json", import.meta.url), "utf8"),
) as { valid: Valid[] };

const dir = mkdtempSync(join(tmpdir(), "syncryption-ssh-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** `ssh-keygen -y`: derive the public key from a private key file. */
function sshKeygenPublic(pem: string, passphrase: string): string {
	const path = join(dir, `key-${Math.random().toString(36).slice(2)}`);
	writeFileSync(path, pem, { mode: 0o600 });
	return execFileSync("ssh-keygen", ["-y", "-P", passphrase, "-f", path], {
		encoding: "utf8",
	}).trim();
}

describe("writeOpenSshPrivateKey", () => {
	it.each(vectors.valid)("reproduces ssh-keygen output byte for byte: $name", (v) => {
		const pem = writeOpenSshPrivateKey(fromHex(v.seed), {
			comment: v.comment,
			passphrase: v.passphrase,
			rounds: v.rounds,
			salt: v.salt === undefined ? undefined : fromHex(v.salt),
			checkint: v.checkint,
		});
		expect(pem).toBe(v.pem);
	});

	it.each([
		{ name: "unencrypted", passphrase: "" },
		{ name: "with passphrase", passphrase: "local secret" },
	])("round-trips a generated key through the parser and ssh-keygen: $name", ({ passphrase }) => {
		const key = generateDeviceKey("phone");
		const pem = writeOpenSshPrivateKey(key.seed, { comment: "phone", passphrase });

		const parsed = parseOpenSshPrivateKey(pem, passphrase);
		expect(hex(parsed.seed)).toBe(hex(key.seed));
		expect(hex(parsed.publicKey)).toBe(hex(key.publicKey));
		expect(parsed.comment).toBe("phone");
		expect(parsed.encrypted).toBe(passphrase !== "");

		expect(sshKeygenPublic(pem, passphrase)).toBe(publicKeyText(key.publicKey, "phone"));
	});

	it("re-wraps an imported key under a new passphrase", () => {
		const v = vectors.valid.find((x) => x.passphrase !== "")!;
		const key = parseOpenSshPrivateKey(v.pem, v.passphrase);
		const pem = writeOpenSshPrivateKey(key.seed, { comment: key.comment, passphrase: "new" });
		expect(() => parseOpenSshPrivateKey(pem, v.passphrase)).toThrow(SshKeyError);
		expect(hex(parseOpenSshPrivateKey(pem, "new").seed)).toBe(v.seed);
	});

	it("generates distinct keys", () => {
		expect(hex(generateDeviceKey().seed)).not.toBe(hex(generateDeviceKey().seed));
	});

	it("rejects bad input", () => {
		expect(() => writeOpenSshPrivateKey(new Uint8Array(31))).toThrow();
		expect(() =>
			writeOpenSshPrivateKey(new Uint8Array(32), { passphrase: "x", rounds: 0 }),
		).toThrow();
	});
});
