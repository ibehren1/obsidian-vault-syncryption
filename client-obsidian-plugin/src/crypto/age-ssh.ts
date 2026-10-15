/**
 * age `ssh-ed25519` recipient and identity (docs/crypto.md 3.4 and 4), as typage
 * `Recipient`/`Identity` implementations. Interoperable with Go `age` and `rage`.
 */
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { Stanza, type Identity, type Recipient } from "age-encryption";

import { concat, equal, fromBase64NoPad, toBase64NoPad, utf8 } from "./bytes";
import { publicKeyWire } from "./openssh";

const TYPE = "ssh-ed25519";
const LABEL = utf8("age-encryption.org/v1/ssh-ed25519");
const ZERO_NONCE = new Uint8Array(12);
const FILE_KEY_SIZE = 16;

/** Ed25519 public key to X25519 (the birational map u = (1 + y) / (1 - y)). */
export function ed25519PublicToX25519(publicKey: Uint8Array): Uint8Array {
	return ed25519.utils.toMontgomery(publicKey);
}

/** Ed25519 seed to X25519 secret: SHA-512(seed)[0:32]. X25519 clamps it. */
export function ed25519SeedToX25519(seed: Uint8Array): Uint8Array {
	return sha512(seed).slice(0, 32);
}

/** `b64std_nopad(SHA-256(pubWire)[0:4])`. */
function stanzaTag(wire: Uint8Array): string {
	return toBase64NoPad(sha256(wire).subarray(0, 4));
}

function tweak(wire: Uint8Array): Uint8Array {
	return hkdf(sha256, new Uint8Array(0), wire, LABEL, 32);
}

/**
 * Deterministic core of the wrap, with the ephemeral secret passed in. Only tests should
 * call this directly; `SshEd25519Recipient` uses a fresh random ephemeral every time.
 */
export function wrapSshEd25519(
	publicKey: Uint8Array,
	fileKey: Uint8Array,
	ephemeral: Uint8Array,
): Stanza {
	const wire = publicKeyWire(publicKey);
	const pkX = ed25519PublicToX25519(publicKey);
	const ePk = x25519.scalarMultBase(ephemeral);
	const shared = x25519.scalarMult(tweak(wire), x25519.scalarMult(ephemeral, pkX));
	const wrapKey = hkdf(sha256, shared, concat(ePk, pkX), LABEL, 32);
	const body = chacha20poly1305(wrapKey, ZERO_NONCE).encrypt(fileKey);
	return new Stanza([TYPE, stanzaTag(wire), toBase64NoPad(ePk)], body);
}

export class SshEd25519Recipient implements Recipient {
	constructor(private readonly publicKey: Uint8Array) {
		if (publicKey.length !== 32) throw new Error("invalid ssh-ed25519 public key");
		ed25519PublicToX25519(publicKey); // rejects keys that are not curve points
	}

	wrapFileKey(fileKey: Uint8Array): Stanza[] {
		const ephemeral = crypto.getRandomValues(new Uint8Array(32));
		try {
			return [wrapSshEd25519(this.publicKey, fileKey, ephemeral)];
		} finally {
			ephemeral.fill(0);
		}
	}
}

function invalid(): never {
	throw new Error("invalid ssh-ed25519 stanza");
}

export class SshEd25519Identity implements Identity {
	private readonly skX: Uint8Array;
	private readonly pkX: Uint8Array;
	private readonly tweak: Uint8Array;
	private readonly tag: string;

	constructor(seed: Uint8Array) {
		if (seed.length !== 32) throw new Error("invalid ssh-ed25519 seed");
		const publicKey = ed25519.getPublicKey(seed);
		const wire = publicKeyWire(publicKey);
		this.skX = ed25519SeedToX25519(seed);
		this.pkX = ed25519PublicToX25519(publicKey);
		this.tweak = tweak(wire);
		this.tag = stanzaTag(wire);
	}

	/**
	 * Returns the file key, or null if no stanza is for this key. Throws on a malformed
	 * stanza of our type, as Go age does.
	 */
	unwrapFileKey(stanzas: Stanza[]): Uint8Array | null {
		for (const s of stanzas) {
			const fileKey = this.unwrap(s);
			if (fileKey !== null) return fileKey;
		}
		return null;
	}

	private unwrap(s: Stanza): Uint8Array | null {
		if (s.args[0] !== TYPE) return null;
		if (s.args.length !== 3) invalid();
		let ePk: Uint8Array;
		try {
			ePk = fromBase64NoPad(s.args[2]!);
		} catch {
			invalid();
		}
		if (ePk.length !== 32) invalid();
		if (s.args[1] !== this.tag) return null;
		if (s.body.length !== FILE_KEY_SIZE + 16) invalid();

		let shared: Uint8Array;
		try {
			// Throws on low-order points, which would give an all-zero shared secret.
			shared = x25519.scalarMult(this.tweak, x25519.scalarMult(this.skX, ePk));
		} catch {
			invalid();
		}
		if (equal(shared, new Uint8Array(32))) invalid();
		const wrapKey = hkdf(sha256, shared, concat(ePk, this.pkX), LABEL, 32);
		try {
			return chacha20poly1305(wrapKey, ZERO_NONCE).decrypt(s.body);
		} catch {
			return null; // a failed open means the stanza is not for us
		}
	}
}
