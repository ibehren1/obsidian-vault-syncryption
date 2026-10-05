/** Vault keyring (docs/crypto.md 6, 8.4 and 9): plaintext, age encryption, signing, checks. */
import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32 } from "@scure/base";
import { Decrypter, Encrypter, generateX25519Identity, identityToRecipient } from "age-encryption";

import { SshEd25519Identity, SshEd25519Recipient } from "./age-ssh";
import { equal, fromB64u, fromUtf8, hex, toB64u, utf8 } from "./bytes";
import { deriveIndexKey } from "./kdf";
import { parsePublicKeyText, publicKeyText } from "./openssh";
import { NAMESPACE_KEYRING, signSshsig, verifySshsig } from "./sshsig";

export const MAX_KEYRING_SIZE = 1024 * 1024;

export interface KeyringDevice {
	id: string;
	name: string;
	/** `ssh-ed25519 AAAA...` */
	publicKey: string;
	added: string;
}

export interface KeyringEpoch {
	epoch: number;
	/** b64u, 32 bytes */
	vdk: string;
}

export interface Keyring {
	v: 1;
	vaultId: string;
	version: number;
	name: string;
	indexKey: string;
	currentEpoch: number;
	keys: KeyringEpoch[];
	devices: KeyringDevice[];
	/** Optional native age X25519 recipient (`age1...`), crypto.md 9. */
	recovery?: string;
	/** The Ed25519 key derived from the recovery key (`ssh-ed25519 AAAA...`), set with `recovery`. */
	recoverySigner?: string;
	/** The device that set the recovery key, set with `recovery`. */
	recoverySetBy?: string;
	updatedBy: string;
	updatedAt: string;
}

/** A keyring as stored on the server (protocol.md 7.3), with the age file as bytes. */
export interface KeyringBlob {
	version: number;
	keyring: Uint8Array;
	signature: string;
}

/** What the client pins locally after accepting a keyring. */
export interface KeyringPin {
	version: number;
	sha256: string;
}

export interface TrustedKeyring {
	keyring: Keyring;
	pin: KeyringPin;
}

export interface KeyringContext {
	/** This device's Ed25519 seed. */
	seed: Uint8Array;
	vaultId: string;
	name: string;
}

export type KeyringErrorCode =
	| "malformed"
	| "bad-signature"
	| "untrusted-signer"
	| "not-a-recipient"
	| "wrong-vault"
	| "version-mismatch"
	| "rollback"
	| "chain-gap"
	| "inconsistent";

export class KeyringError extends Error {
	constructor(
		readonly code: KeyringErrorCode,
		message: string,
	) {
		super(message);
		this.name = "KeyringError";
	}
}

function nowIso(): string {
	return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function randomKey(): string {
	return toB64u(crypto.getRandomValues(new Uint8Array(32)));
}

/** The genesis keyring (version 1, epoch 1) for a new vault. */
export function createKeyring(opts: {
	vaultId: string;
	name: string;
	device: Omit<KeyringDevice, "added">;
	recovery?: Pick<RecoveryKey, "recipient" | "signer">;
	now?: string;
}): Keyring {
	const now = opts.now ?? nowIso();
	const vdk = crypto.getRandomValues(new Uint8Array(32));
	const keyring: Keyring = {
		v: 1,
		vaultId: opts.vaultId,
		version: 1,
		name: opts.name,
		indexKey: toB64u(deriveIndexKey(vdk)),
		currentEpoch: 1,
		keys: [{ epoch: 1, vdk: toB64u(vdk) }],
		devices: [{ ...opts.device, added: now }],
		updatedBy: opts.device.id,
		updatedAt: now,
	};
	if (opts.recovery !== undefined) {
		keyring.recovery = opts.recovery.recipient;
		keyring.recoverySigner = opts.recovery.signer;
		keyring.recoverySetBy = opts.device.id;
	}
	vdk.fill(0);
	return keyring;
}

function next(prev: Keyring, updatedBy: string, now: string | undefined): Keyring {
	return structuredClone({ ...prev, version: prev.version + 1, updatedBy, updatedAt: now ?? nowIso() });
}

/** Pairing (crypto.md 6.5): the next version, with `device` added as a recipient. */
export function addKeyringDevice(
	prev: Keyring,
	device: Omit<KeyringDevice, "added">,
	updatedBy: string,
	now?: string,
): Keyring {
	const k = next(prev, updatedBy, now);
	if (k.devices.some((d) => d.id === device.id || d.publicKey === device.publicKey)) {
		throw new Error("device is already in the keyring");
	}
	k.devices.push({ ...device, added: k.updatedAt });
	return k;
}

/**
 * Revocation (crypto.md 8.4): the next version, without the device (or devices), with a new
 * epoch, and without the recovery key if a removed device set it.
 */
export function removeKeyringDeviceAndRotate(
	prev: Keyring,
	deviceId: string | string[],
	updatedBy: string,
	now?: string,
): Keyring {
	const ids = new Set(typeof deviceId === "string" ? [deviceId] : deviceId);
	const k = next(prev, updatedBy, now);
	const devices = k.devices.filter((d) => !ids.has(d.id));
	if (devices.length !== k.devices.length - ids.size) throw new Error("device is not in the keyring");
	if (devices.length === 0) throw new Error("can't remove the last device");
	k.devices = devices;
	// A removed device may have kept the recovery key it set.
	if (k.recoverySetBy !== undefined && ids.has(k.recoverySetBy)) clearRecovery(k);
	rotate(k);
	return k;
}

/** Start a new epoch with a random VDK. */
function rotate(k: Keyring): void {
	k.currentEpoch = Math.max(...k.keys.map((e) => e.epoch)) + 1;
	k.keys.push({ epoch: k.currentEpoch, vdk: randomKey() });
}

/**
 * Set (as `updatedBy`'s key) or clear the recovery key, as a new version (crypto.md 9).
 * Replacing or removing a key also starts a new epoch, since the old key can still open
 * the older keyring versions.
 */
export function setKeyringRecovery(
	prev: Keyring,
	recovery: Pick<RecoveryKey, "recipient" | "signer"> | undefined,
	updatedBy: string,
	now?: string,
): Keyring {
	const k = next(prev, updatedBy, now);
	if (prev.recovery !== undefined) rotate(k);
	clearRecovery(k);
	if (recovery !== undefined) {
		k.recovery = recovery.recipient;
		k.recoverySigner = recovery.signer;
		k.recoverySetBy = updatedBy;
	}
	return k;
}

function clearRecovery(k: Keyring): void {
	delete k.recovery;
	delete k.recoverySigner;
	delete k.recoverySetBy;
}

export interface RecoveryKey {
	/** `AGE-SECRET-KEY-1...`, shown once and never stored. */
	identity: string;
	/** `age1...` */
	recipient: string;
	/** `ssh-ed25519 AAAA...` of the derived signing key. */
	signer: string;
}

const RECOVERY_SIGNING = utf8("syncryption/v1/recovery-signing");

/**
 * The Ed25519 seed that signs recovery uploads, derived from a recovery identity
 * (crypto.md 9). Throws on anything that isn't an age X25519 identity.
 */
export function recoverySigningSeed(identity: string): Uint8Array {
	let decoded;
	try {
		decoded = bech32.decodeToBytes(identity.trim().toLowerCase());
	} catch {
		throw new Error("not a recovery key");
	}
	if (decoded.prefix !== "age-secret-key-" || decoded.bytes.length !== 32) throw new Error("not a recovery key");
	const seed = hkdf(sha256, decoded.bytes, new Uint8Array(0), RECOVERY_SIGNING, 32);
	decoded.bytes.fill(0);
	return seed;
}

/** The signer text of a recovery identity. */
export function recoverySigner(identity: string): string {
	const seed = recoverySigningSeed(identity);
	const signer = publicKeyText(ed25519.getPublicKey(seed));
	seed.fill(0);
	return signer;
}

/** A new recovery key (crypto.md 9). The identity is shown once and never stored. */
export async function generateRecoveryKey(): Promise<RecoveryKey> {
	const identity = await generateX25519Identity();
	return { identity, recipient: await identityToRecipient(identity), signer: recoverySigner(identity) };
}

/**
 * Encrypt to every device (and the recovery key), then sign with `seed`: a device in the
 * keyring, or the recovery signer.
 */
export async function sealKeyring(keyring: Keyring, seed: Uint8Array): Promise<KeyringBlob> {
	validate(keyring);
	const signer = publicKeyText(ed25519.getPublicKey(seed));
	if (!keyring.devices.some((d) => d.publicKey === signer) && keyring.recoverySigner !== signer) {
		throw new Error("the signing device must be in the keyring");
	}
	const e = new Encrypter();
	for (const d of keyring.devices) e.addRecipient(new SshEd25519Recipient(parsePublicKeyText(d.publicKey)));
	if (keyring.recovery !== undefined) e.addRecipient(keyring.recovery);
	const age = await e.encrypt(utf8(JSON.stringify(keyring)));
	if (age.length > MAX_KEYRING_SIZE) throw new Error("keyring too large");
	return {
		version: keyring.version,
		keyring: age,
		signature: signSshsig(seed, NAMESPACE_KEYRING, age),
	};
}

/**
 * Verify, decrypt and check a keyring (crypto.md 6.3, 6.4).
 *
 * - With `trusted`, the keyring must be the same version and bytes, or exactly the next
 *   version signed by a device in `trusted.keyring.devices` or its recovery signer. Further
 *   ahead is `chain-gap`: use `openKeyringChain`.
 * - Without `trusted` (first use), the signer must be in the keyring's own `devices` or be
 *   its own recovery signer.
 */
export async function openKeyring(
	blob: KeyringBlob,
	ctx: KeyringContext,
	trusted?: TrustedKeyring,
): Promise<TrustedKeyring> {
	return open(blob, ctx, new SshEd25519Identity(ctx.seed), trusted);
}

/**
 * Open the current keyring with a recovery identity instead of a device key (crypto.md 9),
 * on first use. The keyring's `recoverySigner` must be the one this identity derives.
 */
export async function openKeyringWithRecovery(
	blob: KeyringBlob,
	ctx: Omit<KeyringContext, "seed"> & { identity: string },
): Promise<TrustedKeyring> {
	const signer = recoverySigner(ctx.identity);
	const opened = await open(blob, ctx, ctx.identity.trim().toUpperCase());
	if (opened.keyring.recoverySigner !== signer) {
		throw new KeyringError("inconsistent", "keyring names another recovery signer");
	}
	return opened;
}

async function open(
	blob: KeyringBlob,
	ctx: Omit<KeyringContext, "seed">,
	identity: SshEd25519Identity | string,
	trusted?: TrustedKeyring,
): Promise<TrustedKeyring> {
	if (blob.keyring.length > MAX_KEYRING_SIZE) throw new KeyringError("malformed", "keyring too large");
	let signerKey: Uint8Array;
	try {
		signerKey = verifySshsig(blob.signature, NAMESPACE_KEYRING, blob.keyring);
	} catch {
		throw new KeyringError("bad-signature", "keyring signature is invalid");
	}
	const pin = { version: blob.version, sha256: hex(sha256(blob.keyring)) };

	if (trusted) {
		if (blob.version < trusted.pin.version) {
			throw new KeyringError("rollback", "server keyring is older than the pinned one");
		}
		if (blob.version === trusted.pin.version && pin.sha256 !== trusted.pin.sha256) {
			throw new KeyringError("rollback", "server keyring differs from the pinned one");
		}
		if (blob.version > trusted.pin.version + 1) {
			throw new KeyringError("chain-gap", "keyring versions must be checked one by one");
		}
	}

	const keyring = await decrypt(blob.keyring, identity);
	if (keyring.vaultId !== ctx.vaultId || keyring.name !== ctx.name) {
		throw new KeyringError("wrong-vault", "keyring belongs to another vault");
	}
	if (keyring.version !== blob.version) {
		throw new KeyringError("version-mismatch", "keyring version differs from the server's");
	}

	const authority = trusted && blob.version > trusted.pin.version ? trusted.keyring : keyring;
	const signer = authority.devices.find((d) => equal(parsePublicKeyText(d.publicKey), signerKey));
	const byRecovery =
		!signer &&
		authority.recoverySigner !== undefined &&
		equal(parsePublicKeyText(authority.recoverySigner), signerKey);
	if (!signer && !byRecovery) {
		throw new KeyringError("untrusted-signer", "keyring was signed by an unknown device");
	}
	if (trusted) checkConsistent(trusted.keyring, keyring, signer);
	return { keyring, pin };
}

/** Walk from `trusted` through each later version in order, checking every link. */
export async function openKeyringChain(
	blobs: KeyringBlob[],
	ctx: KeyringContext,
	trusted: TrustedKeyring,
): Promise<TrustedKeyring> {
	let current = trusted;
	for (const blob of [...blobs].sort((a, b) => a.version - b.version)) {
		if (blob.version <= current.pin.version) continue;
		current = await openKeyring(blob, ctx, current);
	}
	return current;
}

async function decrypt(age: Uint8Array, identity: SshEd25519Identity | string): Promise<Keyring> {
	const d = new Decrypter();
	d.addIdentity(identity);
	let plaintext: Uint8Array;
	try {
		plaintext = await d.decrypt(age);
	} catch (e) {
		const msg = e instanceof Error ? e.message : "";
		if (/no identity matched/i.test(msg)) {
			throw new KeyringError("not-a-recipient", "this device is not in the keyring");
		}
		throw new KeyringError("malformed", "keyring failed to decrypt");
	}
	let keyring: unknown;
	try {
		keyring = JSON.parse(fromUtf8(plaintext));
	} catch {
		throw new KeyringError("malformed", "keyring is not valid JSON");
	}
	validate(keyring);
	return keyring;
}

function malformed(why: string): never {
	throw new KeyringError("malformed", `keyring is malformed: ${why}`);
}

function isKey32(s: unknown): boolean {
	try {
		return typeof s === "string" && fromB64u(s).length === 32;
	} catch {
		return false;
	}
}

function validate(k: unknown): asserts k is Keyring {
	if (typeof k !== "object" || k === null) malformed("not an object");
	const o = k as Record<string, unknown>;
	const posInt = (x: unknown) => typeof x === "number" && Number.isSafeInteger(x) && x >= 1;
	if (o.v !== 1) malformed("unsupported format version");
	if (typeof o.vaultId !== "string" || typeof o.name !== "string") malformed("vaultId or name");
	if (!posInt(o.version) || !posInt(o.currentEpoch)) malformed("version or currentEpoch");
	if (!isKey32(o.indexKey)) malformed("indexKey");
	if (typeof o.updatedBy !== "string" || typeof o.updatedAt !== "string") malformed("updatedBy/At");
	const recovery = [o.recovery, o.recoverySigner, o.recoverySetBy];
	if (recovery.some((x) => x !== undefined)) {
		if (recovery.some((x) => typeof x !== "string")) malformed("recovery fields must be set together");
		if (!(o.recovery as string).startsWith("age1")) malformed("recovery");
		try {
			parsePublicKeyText(o.recoverySigner as string);
		} catch {
			malformed("recoverySigner");
		}
	}

	if (!Array.isArray(o.keys) || o.keys.length === 0) malformed("keys");
	const epochs = new Set<number>();
	for (const e of o.keys as unknown[]) {
		const ep = e as KeyringEpoch;
		if (typeof e !== "object" || e === null || !posInt(ep.epoch) || !isKey32(ep.vdk)) malformed("key epoch");
		if (epochs.has(ep.epoch)) malformed("duplicate epoch");
		epochs.add(ep.epoch);
	}
	if (!epochs.has(o.currentEpoch as number)) malformed("currentEpoch is not in keys");
	const first = (o.keys as KeyringEpoch[]).find((e) => e.epoch === 1);
	if (!first || !equal(deriveIndexKey(fromB64u(first.vdk)), fromB64u(o.indexKey as string))) {
		malformed("indexKey does not match epoch 1");
	}

	if (!Array.isArray(o.devices) || o.devices.length === 0) malformed("devices");
	const ids = new Set<string>();
	for (const d of o.devices as unknown[]) {
		const dev = d as KeyringDevice;
		if (
			typeof d !== "object" ||
			d === null ||
			typeof dev.id !== "string" ||
			typeof dev.name !== "string" ||
			typeof dev.added !== "string" ||
			typeof dev.publicKey !== "string"
		) {
			malformed("device");
		}
		try {
			parsePublicKeyText(dev.publicKey);
		} catch {
			malformed("device public key");
		}
		if (ids.has(dev.id)) malformed("duplicate device");
		ids.add(dev.id);
	}
}

/**
 * A newer keyring may add epochs and devices, but never change what was trusted. Only a
 * device (`signer`, from `prev`) may change the recovery key, in its own name.
 */
function checkConsistent(prev: Keyring, k: Keyring, signer: KeyringDevice | undefined): void {
	const fail = (why: string): never => {
		throw new KeyringError("inconsistent", `keyring changed ${why}`);
	};
	if (k.indexKey !== prev.indexKey) fail("its indexKey");
	for (const e of prev.keys) {
		if (k.keys.find((x) => x.epoch === e.epoch)?.vdk !== e.vdk) fail(`epoch ${e.epoch}`);
	}
	if (k.currentEpoch < prev.currentEpoch) fail("to an older epoch");
	const changed =
		k.recovery !== prev.recovery || k.recoverySigner !== prev.recoverySigner || k.recoverySetBy !== prev.recoverySetBy;
	if (changed) {
		if (!signer) return fail("its recovery key, signed by the recovery key");
		if (k.recovery !== undefined && k.recoverySetBy !== signer.id) fail("its recovery key in another device's name");
	}
}

/** Key material for an epoch, as bytes. */
export function epochKey(keyring: Keyring, epoch: number = keyring.currentEpoch): Uint8Array {
	const e = keyring.keys.find((x) => x.epoch === epoch);
	if (!e) throw new KeyringError("malformed", `keyring has no epoch ${epoch}`);
	return fromB64u(e.vdk);
}

export function indexKey(keyring: Keyring): Uint8Array {
	return fromB64u(keyring.indexKey);
}
