/**
 * OpenSSH Ed25519 keys (docs/crypto.md 3.1 and 3.2).
 *
 * Parses and writes `openssh-key-v1` private keys, unencrypted or protected with
 * aes256-ctr + bcrypt. Only Ed25519 keys are accepted.
 */
import { ctr } from "@noble/ciphers/aes.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { pbkdf as bcryptPbkdf } from "bcrypt-pbkdf";

import {
	concat,
	equal,
	fromBase64,
	fromUtf8,
	latin1,
	SshReader,
	sshString,
	toBase64,
	u32be,
	utf8,
} from "./bytes";

export type SshKeyErrorCode =
	| "not-openssh"
	| "unsupported-key-type"
	| "unsupported-cipher"
	| "passphrase-required"
	| "wrong-passphrase"
	| "corrupt";

const MESSAGES: Record<SshKeyErrorCode, string> = {
	"not-openssh": "Not an OpenSSH private key.",
	"unsupported-key-type": "Only Ed25519 SSH keys are supported.",
	"unsupported-cipher":
		"Unsupported key cipher, re-encrypt with `ssh-keygen -p -Z aes256-ctr`.",
	"passphrase-required": "This key is protected with a passphrase.",
	"wrong-passphrase": "Wrong passphrase.",
	corrupt: "The private key is damaged.",
};

export class SshKeyError extends Error {
	constructor(readonly code: SshKeyErrorCode) {
		super(MESSAGES[code]);
		this.name = "SshKeyError";
	}
}

export interface OpenSshKey {
	/** The 32-byte Ed25519 seed. This is the only secret the plugin keeps. */
	seed: Uint8Array;
	publicKey: Uint8Array;
	comment: string;
	encrypted: boolean;
}

const MAGIC = utf8("openssh-key-v1\0");
const KEY_TYPE = "ssh-ed25519";
const PEM_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END = "-----END OPENSSH PRIVATE KEY-----";
const PEM_RE = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/;

function corrupt(): never {
	throw new SshKeyError("corrupt");
}

/** RFC 8709 public key wire format: string("ssh-ed25519") || string(pk32). */
export function publicKeyWire(publicKey: Uint8Array): Uint8Array {
	return concat(sshString(utf8(KEY_TYPE)), sshString(publicKey));
}

/** `ssh-ed25519 <base64> [comment]`, as in `authorized_keys`. */
export function publicKeyText(publicKey: Uint8Array, comment = ""): string {
	const text = `${KEY_TYPE} ${toBase64(publicKeyWire(publicKey))}`;
	return comment ? `${text} ${comment}` : text;
}

/** Parse `ssh-ed25519 <base64> [comment]` into the 32-byte public key. */
export function parsePublicKeyText(text: string): Uint8Array {
	const [type, b64] = text.trim().split(/\s+/);
	if (type !== KEY_TYPE) throw new SshKeyError("unsupported-key-type");
	let wire: Uint8Array;
	try {
		wire = fromBase64(b64 ?? "");
	} catch {
		corrupt();
	}
	const r = new SshReader(wire, corrupt);
	if (latin1(r.string()) !== KEY_TYPE) corrupt();
	const publicKey = r.string();
	if (publicKey.length !== 32 || r.remaining !== 0) corrupt();
	return publicKey.slice();
}

/** `SHA256:<base64>` without padding, as printed by `ssh-keygen -l`. */
export function fingerprint(publicKey: Uint8Array): string {
	return "SHA256:" + toBase64(sha256(publicKeyWire(publicKey))).replace(/=+$/, "");
}

interface Envelope {
	cipher: string;
	kdf: string;
	kdfOptions: Uint8Array;
	section: Uint8Array;
	publicKey: Uint8Array;
}

function decodeEnvelope(pem: string): Envelope {
	const body = PEM_RE.exec(pem)?.[1];
	if (body === undefined) throw new SshKeyError("not-openssh");
	let blob: Uint8Array;
	try {
		blob = fromBase64(body.replace(/\s+/g, ""));
	} catch {
		corrupt();
	}
	if (blob.length < MAGIC.length || !equal(blob.subarray(0, MAGIC.length), MAGIC)) {
		throw new SshKeyError("not-openssh");
	}
	const r = new SshReader(blob.subarray(MAGIC.length), corrupt);
	const cipher = latin1(r.string());
	const kdf = latin1(r.string());
	const kdfOptions = r.string();
	if (r.u32() !== 1) corrupt();
	const outerPub = r.string();
	const section = r.string();

	const pub = new SshReader(outerPub, corrupt);
	if (latin1(pub.string()) !== KEY_TYPE) throw new SshKeyError("unsupported-key-type");
	const publicKey = pub.string();
	if (publicKey.length !== 32 || pub.remaining !== 0) corrupt();

	// AEAD ciphers append a tag after the section, so reject them before the length check.
	if (cipher !== "none" && cipher !== "aes256-ctr") throw new SshKeyError("unsupported-cipher");
	if (r.remaining !== 0) corrupt();

	return { cipher, kdf, kdfOptions, section, publicKey };
}

/** Whether the key needs a passphrase. Throws `SshKeyError` like `parseOpenSshPrivateKey`. */
export function isEncryptedOpenSshKey(pem: string): boolean {
	return decodeEnvelope(pem).cipher !== "none";
}

/**
 * Parse an OpenSSH Ed25519 private key. Every check in crypto.md 3.2 is a hard error,
 * reported as an `SshKeyError`.
 */
export function parseOpenSshPrivateKey(pem: string, passphrase = ""): OpenSshKey {
	const env = decodeEnvelope(pem);
	let section: Uint8Array;
	let blockSize: number;
	if (env.cipher === "none") {
		if (env.kdf !== "none" || env.kdfOptions.length !== 0) corrupt();
		section = env.section.slice();
		blockSize = 8;
	} else if (env.cipher === "aes256-ctr") {
		if (env.kdf !== "bcrypt") throw new SshKeyError("unsupported-cipher");
		if (!passphrase) throw new SshKeyError("passphrase-required");
		const opts = new SshReader(env.kdfOptions, corrupt);
		const salt = opts.string();
		const rounds = opts.u32();
		if (opts.remaining !== 0 || salt.length === 0 || rounds < 1) corrupt();
		blockSize = 16;
		if (env.section.length % blockSize !== 0) corrupt();
		const kiv = new Uint8Array(48);
		const pass = utf8(passphrase);
		if (bcryptPbkdf(pass, pass.length, salt, salt.length, kiv, kiv.length, rounds) !== 0) {
			corrupt();
		}
		section = ctr(kiv.subarray(0, 32), kiv.subarray(32, 48)).decrypt(env.section);
		kiv.fill(0);
		pass.fill(0);
	} else {
		throw new SshKeyError("unsupported-cipher");
	}

	try {
		return parseSection(section, blockSize, env);
	} finally {
		section.fill(0);
	}
}

function parseSection(section: Uint8Array, blockSize: number, env: Envelope): OpenSshKey {
	const encrypted = env.cipher !== "none";
	if (section.length % blockSize !== 0) corrupt();
	const r = new SshReader(section, corrupt);
	const check = r.u32();
	if (check !== r.u32()) {
		// Unencrypted keys have no passphrase to get wrong, so a mismatch means damage.
		throw new SshKeyError(encrypted ? "wrong-passphrase" : "corrupt");
	}
	if (latin1(r.string()) !== KEY_TYPE) corrupt();
	const pk = r.string();
	const sk = r.string();
	const commentBytes = r.string();
	const padding = r.rest();

	if (pk.length !== 32 || sk.length !== 64) corrupt();
	if (padding.length >= blockSize) corrupt();
	padding.forEach((b, i) => {
		if (b !== i + 1) corrupt();
	});
	const seed = sk.slice(0, 32);
	if (
		!equal(sk.subarray(32), pk) ||
		!equal(pk, env.publicKey) ||
		!equal(ed25519.getPublicKey(seed), pk)
	) {
		seed.fill(0);
		corrupt();
	}

	let comment: string;
	try {
		comment = fromUtf8(commentBytes);
	} catch {
		seed.fill(0);
		corrupt();
	}
	return { seed, publicKey: pk.slice(), comment, encrypted };
}

export interface WriteOptions {
	comment?: string;
	/** Empty or missing: unencrypted (`none`/`none`). Otherwise aes256-ctr + bcrypt. */
	passphrase?: string;
	/** bcrypt rounds. Default 16, as in `ssh-keygen`. */
	rounds?: number;
	/** Fixed salt (16 bytes) and checkint, for test vectors only. Random by default. */
	salt?: Uint8Array;
	checkint?: number;
}

/** A new device key: `seed32 = RAND(32)` (crypto.md 3.3). */
export function generateDeviceKey(comment = ""): OpenSshKey {
	const seed = crypto.getRandomValues(new Uint8Array(32));
	return { seed, publicKey: ed25519.getPublicKey(seed), comment, encrypted: false };
}

/**
 * Write an Ed25519 key in `openssh-key-v1` format, byte for byte as `ssh-keygen` does,
 * so it can be exported and used with `ssh-keygen` and `age -d -i`.
 */
export function writeOpenSshPrivateKey(seed: Uint8Array, options: WriteOptions = {}): string {
	if (seed.length !== 32) throw new Error("seed must be 32 bytes");
	const { comment = "", passphrase = "", rounds = 16 } = options;
	const publicKey = ed25519.getPublicKey(seed);
	const encrypted = passphrase !== "";
	const blockSize = encrypted ? 16 : 8;
	const checkint =
		options.checkint ?? new DataView(crypto.getRandomValues(new Uint8Array(4)).buffer).getUint32(0);

	const sk = sshString(concat(seed, publicKey));
	const body = concat(
		u32be(checkint),
		u32be(checkint),
		sshString(utf8(KEY_TYPE)),
		sshString(publicKey),
		sk,
		sshString(utf8(comment)),
	);
	sk.fill(0);
	const padLength = (blockSize - (body.length % blockSize)) % blockSize;
	const section = concat(body, Uint8Array.from({ length: padLength }, (_, i) => i + 1));
	body.fill(0);

	let cipher = "none";
	let kdf = "none";
	let kdfOptions: Uint8Array = new Uint8Array(0);
	let encryptedSection = section;
	if (encrypted) {
		if (!Number.isInteger(rounds) || rounds < 1) throw new Error("rounds must be at least 1");
		const salt = options.salt ?? crypto.getRandomValues(new Uint8Array(16));
		cipher = "aes256-ctr";
		kdf = "bcrypt";
		kdfOptions = concat(sshString(salt), u32be(rounds));
		const kiv = new Uint8Array(48);
		const pass = utf8(passphrase);
		if (bcryptPbkdf(pass, pass.length, salt, salt.length, kiv, kiv.length, rounds) !== 0) {
			throw new Error("bcrypt_pbkdf failed");
		}
		encryptedSection = ctr(kiv.subarray(0, 32), kiv.subarray(32, 48)).encrypt(section);
		kiv.fill(0);
		pass.fill(0);
		section.fill(0);
	}

	const blob = concat(
		MAGIC,
		sshString(utf8(cipher)),
		sshString(utf8(kdf)),
		sshString(kdfOptions),
		u32be(1),
		sshString(publicKeyWire(publicKey)),
		sshString(encryptedSection),
	);
	const b64 = toBase64(blob);
	encryptedSection.fill(0);
	const lines = b64.match(/.{1,70}/g) ?? [];
	return [PEM_BEGIN, ...lines, PEM_END, ""].join("\n");
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Pairing code (crypto.md 6.5): the first 50 bits of SHA-256(pubWire) in Crockford
 * base32, grouped `XXXXX-XXXXX`.
 */
export function pairingCode(publicKey: Uint8Array): string {
	const digest = sha256(publicKeyWire(publicKey));
	let bits = 0n;
	for (let i = 0; i < 7; i++) bits = (bits << 8n) | BigInt(digest[i]!);
	bits >>= 6n; // 56 bits read, keep the first 50
	let code = "";
	for (let i = 9; i >= 0; i--) code += CROCKFORD[Number((bits >> BigInt(5 * i)) & 31n)];
	return `${code.slice(0, 5)}-${code.slice(5)}`;
}
