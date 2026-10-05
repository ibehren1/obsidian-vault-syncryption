/// <reference types="node" />
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { hex } from "../src/crypto/bytes";
import {
	fingerprint,
	isEncryptedOpenSshKey,
	parseOpenSshPrivateKey,
	publicKeyText,
	SshKeyError,
} from "../src/crypto/openssh";

interface Valid {
	name: string;
	pem: string;
	passphrase: string;
	seed: string;
	publicKey: string;
	publicKeyText: string;
	comment: string;
	fingerprint: string;
}

interface Invalid {
	name: string;
	pem: string;
	passphrase: string;
	error: string;
}

const vectors = JSON.parse(
	readFileSync(new URL("../../testvectors/openssh-keys.json", import.meta.url), "utf8"),
) as { valid: Valid[]; invalid: Invalid[] };

describe("parseOpenSshPrivateKey", () => {
	it.each(vectors.valid)("parses $name", (v) => {
		const key = parseOpenSshPrivateKey(v.pem, v.passphrase);
		expect(hex(key.seed)).toBe(v.seed);
		expect(hex(key.publicKey)).toBe(v.publicKey);
		expect(key.comment).toBe(v.comment);
		expect(key.encrypted).toBe(v.passphrase !== "");
		expect(isEncryptedOpenSshKey(v.pem)).toBe(v.passphrase !== "");
		expect(publicKeyText(key.publicKey, key.comment)).toBe(v.publicKeyText);
		expect(fingerprint(key.publicKey)).toBe(v.fingerprint);
	});

	it.each(vectors.invalid)("rejects $name", (v) => {
		let error: unknown;
		try {
			parseOpenSshPrivateKey(v.pem, v.passphrase);
		} catch (e) {
			error = e;
		}
		expect(error).toBeInstanceOf(SshKeyError);
		expect((error as SshKeyError).code).toBe(v.error);
	});

	it("accepts CRLF line endings", () => {
		const v = vectors.valid[0]!;
		const key = parseOpenSshPrivateKey(v.pem.replace(/\n/g, "\r\n"));
		expect(hex(key.seed)).toBe(v.seed);
	});
});
