/**
 * OpenSSH signatures (`PROTOCOL.sshsig`, docs/crypto.md 7), Ed25519 and SHA-512 only.
 * Output is byte-identical to `ssh-keygen -Y sign`, since Ed25519 is deterministic.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";

import { concat, equal, fromBase64, latin1, SshReader, sshString, toBase64, u32be, utf8 } from "./bytes";
import { publicKeyWire } from "./openssh";

export const NAMESPACE_AUTH = "syncryption-auth@v1";
export const NAMESPACE_KEYRING = "syncryption-keyring@v1";

const MAGIC = utf8("SSHSIG");
const HASH = "sha512";
const KEY_TYPE = "ssh-ed25519";
const BEGIN = "-----BEGIN SSH SIGNATURE-----";
const END = "-----END SSH SIGNATURE-----";

export class SshSigError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SshSigError";
	}
}

function fail(): never {
	throw new SshSigError("invalid signature");
}

function signedData(namespace: string, message: Uint8Array): Uint8Array {
	return concat(
		MAGIC,
		sshString(utf8(namespace)),
		sshString(new Uint8Array(0)),
		sshString(utf8(HASH)),
		sshString(sha512(message)),
	);
}

export function signSshsig(seed: Uint8Array, namespace: string, message: Uint8Array): string {
	if (!namespace) throw new Error("namespace is required");
	const publicKey = ed25519.getPublicKey(seed);
	const signature = ed25519.sign(signedData(namespace, message), seed);
	const blob = concat(
		MAGIC,
		u32be(1),
		sshString(publicKeyWire(publicKey)),
		sshString(utf8(namespace)),
		sshString(new Uint8Array(0)),
		sshString(utf8(HASH)),
		sshString(concat(sshString(utf8(KEY_TYPE)), sshString(signature))),
	);
	const lines = toBase64(blob).match(/.{1,70}/g) ?? [];
	return [BEGIN, ...lines, END, ""].join("\n");
}

/**
 * Verify an armored sshsig over `message` in `namespace`. Returns the signer's 32-byte
 * Ed25519 public key. The caller decides whether that key is trusted.
 */
export function verifySshsig(armored: string, namespace: string, message: Uint8Array): Uint8Array {
	const text = armored.trim();
	if (!text.startsWith(BEGIN) || !text.endsWith(END)) fail();
	let blob: Uint8Array;
	try {
		blob = fromBase64(text.slice(BEGIN.length, -END.length).replace(/\s+/g, ""));
	} catch {
		fail();
	}
	const r = new SshReader(blob, fail);
	if (!equal(r.bytes(MAGIC.length), MAGIC) || r.u32() !== 1) fail();
	const pubWire = r.string();
	const ns = r.string();
	const reserved = r.string();
	const hash = r.string();
	const sigBlob = r.string();
	if (r.remaining !== 0) fail();

	const pub = new SshReader(pubWire, fail);
	if (latin1(pub.string()) !== KEY_TYPE) throw new SshSigError("only ssh-ed25519 signatures are supported");
	const publicKey = pub.string();
	if (publicKey.length !== 32 || pub.remaining !== 0) fail();
	if (latin1(ns) !== namespace) throw new SshSigError("wrong signature namespace");
	if (reserved.length !== 0 || latin1(hash) !== HASH) fail();

	const sig = new SshReader(sigBlob, fail);
	if (latin1(sig.string()) !== KEY_TYPE) fail();
	const signature = sig.string();
	if (signature.length !== 64 || sig.remaining !== 0) fail();

	let ok = false;
	try {
		ok = ed25519.verify(signature, signedData(namespace, message), publicKey, { zip215: false });
	} catch {
		ok = false;
	}
	if (!ok) fail();
	return publicKey.slice();
}
