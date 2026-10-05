import { describe, expect, it } from "vitest";

import { fromHex, hex } from "../src/crypto/bytes";
import { signSshsig, verifySshsig } from "../src/crypto/sshsig";
import { loadVectors } from "./vectors";

interface Sig {
	name: string;
	namespace: string;
	message: string;
	signature: string;
}

const v = loadVectors<{ seed: string; publicKey: string; valid: Sig[]; invalid: Sig[] }>("sshsig.json");

describe("sshsig", () => {
	it.each(v.valid)("signs like ssh-keygen: $name", (s) => {
		expect(signSshsig(fromHex(v.seed), s.namespace, fromHex(s.message))).toBe(s.signature);
	});

	it.each(v.valid)("verifies: $name", (s) => {
		expect(hex(verifySshsig(s.signature, s.namespace, fromHex(s.message)))).toBe(v.publicKey);
	});

	it.each(v.invalid)("rejects: $name", (s) => {
		expect(() => verifySshsig(s.signature, s.namespace, fromHex(s.message))).toThrow();
	});
});
