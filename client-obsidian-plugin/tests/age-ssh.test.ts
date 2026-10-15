/// <reference types="node" />
import { readFileSync } from "node:fs";
import { Decrypter, Encrypter, Stanza } from "age-encryption";
import { describe, expect, it } from "vitest";

import {
	ed25519PublicToX25519,
	ed25519SeedToX25519,
	SshEd25519Identity,
	SshEd25519Recipient,
	wrapSshEd25519,
} from "../src/crypto/age-ssh";
import { fromHex, hex } from "../src/crypto/bytes";
import { generateDeviceKey, parsePublicKeyText } from "../src/crypto/openssh";

function load<T>(name: string): T {
	return JSON.parse(readFileSync(new URL(`../../testvectors/${name}`, import.meta.url), "utf8")) as T;
}

interface Key {
	seed: string;
	publicKey: string;
	publicKeyText: string;
}

const conversion = load<{
	cases: { seed: string; edPublicKey: string; xPublicKey: string; xSecretKey: string }[];
}>("ed25519-to-x25519.json");

const age = load<{
	alice: Key;
	bob: Key;
	wrap: { publicKey: string; ephemeral: string; fileKey: string; args: string[]; body: string }[];
	stanzas: { name: string; args: string[]; body: string; result?: string | null; error?: boolean }[];
	files: { name: string; file: string; plaintext: string | null }[];
}>("age-ssh-ed25519.json");

describe("Ed25519 to X25519", () => {
	it.each(conversion.cases)("converts $edPublicKey", (v) => {
		expect(hex(ed25519PublicToX25519(fromHex(v.edPublicKey)))).toBe(v.xPublicKey);
		expect(hex(ed25519SeedToX25519(fromHex(v.seed)))).toBe(v.xSecretKey);
	});
});

describe("age ssh-ed25519", () => {
	const alice = new SshEd25519Identity(fromHex(age.alice.seed));

	it("parses the public key text", () => {
		expect(hex(parsePublicKeyText(age.alice.publicKeyText))).toBe(age.alice.publicKey);
	});

	it.each(age.wrap)("wraps deterministically like the reference ($ephemeral)", (v) => {
		const stanza = wrapSshEd25519(fromHex(v.publicKey), fromHex(v.fileKey), fromHex(v.ephemeral));
		expect(stanza.args).toEqual(v.args);
		expect(hex(stanza.body)).toBe(v.body);
		expect(hex(alice.unwrapFileKey([stanza])!)).toBe(v.fileKey);
	});

	it.each(age.stanzas)("unwraps stanza: $name", (v) => {
		const stanza = new Stanza(v.args, fromHex(v.body));
		if (v.error) {
			expect(() => alice.unwrapFileKey([stanza])).toThrow();
		} else {
			const result = alice.unwrapFileKey([stanza]);
			expect(result === null ? null : hex(result)).toBe(v.result);
		}
	});

	it.each(age.files)("decrypts a rage file: $name", async (v) => {
		const d = new Decrypter();
		d.addIdentity(alice);
		const decrypt = d.decrypt(fromHex(v.file));
		if (v.plaintext === null) {
			await expect(decrypt).rejects.toThrow();
		} else {
			expect(hex(await decrypt)).toBe(v.plaintext);
		}
	});

	it("round-trips through Encrypter and Decrypter, skipping other recipients", async () => {
		const other = generateDeviceKey();
		const e = new Encrypter();
		e.addRecipient(new SshEd25519Recipient(other.publicKey));
		e.addRecipient(new SshEd25519Recipient(fromHex(age.alice.publicKey)));
		const file = await e.encrypt("vault key");

		const d = new Decrypter();
		d.addIdentity(alice);
		expect(await d.decrypt(file, "text")).toBe("vault key");

		const d2 = new Decrypter();
		d2.addIdentity(new SshEd25519Identity(other.seed));
		expect(await d2.decrypt(file, "text")).toBe("vault key");
	});

	it("rejects invalid public keys", () => {
		expect(() => new SshEd25519Recipient(new Uint8Array(31))).toThrow();
	});
});
