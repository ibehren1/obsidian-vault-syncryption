import { ed25519 } from "@noble/curves/ed25519.js";
import { Decrypter } from "age-encryption";
import { describe, expect, it } from "vitest";

import { fromHex, fromUtf8, hex } from "../src/crypto/bytes";
import {
	addKeyringDevice,
	createKeyring,
	epochKey,
	generateRecoveryKey,
	KeyringError,
	openKeyring,
	openKeyringChain,
	openKeyringWithRecovery,
	recoverySigner,
	recoverySigningSeed,
	removeKeyringDeviceAndRotate,
	sealKeyring,
	setKeyringRecovery,
	type KeyringBlob,
	type KeyringContext,
	type TrustedKeyring,
} from "../src/crypto/keyring";
import { publicKeyText } from "../src/crypto/openssh";
import { loadVectors } from "./vectors";

interface Device {
	id: string;
	seed: string;
	publicKeyText: string;
}

const v = loadVectors<{
	vault: { id: string; name: string };
	devices: Record<string, Device>;
	recovery: { identity: string; recipient: string; signerSeed: string; signerPublicKeyText: string };
	blobs: Record<string, { version: number; keyring: string; signature: string; plaintext: unknown }>;
	cases: { name: string; open: string; as: string; trustedChain: string[]; expect: string }[];
}>("keyring.json");

const blob = (name: string): KeyringBlob => {
	const b = v.blobs[name]!;
	return { version: b.version, keyring: fromHex(b.keyring), signature: b.signature };
};
const ctxFor = (who: string): KeyringContext => ({
	seed: fromHex(v.devices[who]!.seed),
	vaultId: v.vault.id,
	name: v.vault.name,
});

async function errorCode(p: Promise<unknown>): Promise<string> {
	try {
		await p;
		return "ok";
	} catch (e) {
		if (e instanceof KeyringError) return e.code;
		throw e;
	}
}

describe("keyring vectors", () => {
	it.each(v.cases)("$name: $expect", async (c) => {
		const ctx = ctxFor(c.as);
		let trusted: TrustedKeyring | undefined;
		for (const name of c.trustedChain) trusted = await openKeyring(blob(name), ctx, trusted);
		const result = openKeyring(blob(c.open), ctx, trusted);
		expect(await errorCode(result)).toBe(c.expect);
		if (c.expect === "ok") {
			const { keyring } = await result;
			expect(keyring).toEqual(v.blobs[c.open]!.plaintext);
		}
	});

	it("walks the chain from v2 to v4", async () => {
		const ctx = ctxFor("bob");
		const trusted = await openKeyring(blob("v2"), ctx);
		const latest = await openKeyringChain([blob("v4"), blob("v3")], ctx, trusted);
		expect(latest.pin.version).toBe(4);
	});

	it("opens with the recovery identity", async () => {
		const d = new Decrypter();
		d.addIdentity(v.recovery.identity);
		const plaintext = await d.decrypt(blob("v2").keyring);
		expect(JSON.parse(fromUtf8(plaintext)).version).toBe(2);
	});

	it("derives the recovery signer", () => {
		expect(hex(recoverySigningSeed(v.recovery.identity))).toBe(v.recovery.signerSeed);
		expect(recoverySigner(v.recovery.identity.toLowerCase())).toBe(v.recovery.signerPublicKeyText);
		expect(() => recoverySigner("AGE-SECRET-KEY-1QQQQ")).toThrow();
		expect(() => recoverySigner(v.recovery.recipient)).toThrow();
	});

	it("opens the current keyring with the recovery identity", async () => {
		const ctx = { identity: v.recovery.identity, vaultId: v.vault.id, name: v.vault.name };
		const opened = await openKeyringWithRecovery(blob("v4"), ctx);
		expect(opened.keyring).toEqual(v.blobs["v4"]!.plaintext);
		expect(await errorCode(openKeyringWithRecovery(blob("v1"), ctx))).toBe("not-a-recipient");
		// Encrypted to this recovery key, but naming another signer.
		expect(await errorCode(openKeyringWithRecovery(blob("v3-recovery-replaced"), ctx))).toBe("not-a-recipient");
		expect(await errorCode(openKeyringWithRecovery(blob("v4"), { ...ctx, name: "Work" }))).toBe("wrong-vault");
	});
});

describe("keyring round trip", () => {
	const seeds = ["a", "b", "c"].map(() => crypto.getRandomValues(new Uint8Array(32)));
	const [a, b, c] = seeds.map((seed, i) => ({
		seed,
		device: { id: `d_${i}`, name: `device ${i}`, publicKey: publicKeyText(ed25519.getPublicKey(seed)) },
	}));
	const ctx = (seed: Uint8Array): KeyringContext => ({ seed, vaultId: "vault-1", name: "Work" });

	it("creates, pairs, rotates and recovers", async () => {
		const recovery = await generateRecoveryKey();
		const k1 = createKeyring({ vaultId: "vault-1", name: "Work", device: a!.device, recovery });
		const t1 = await openKeyring(await sealKeyring(k1, a!.seed), ctx(a!.seed));

		const k2 = addKeyringDevice(t1.keyring, b!.device, a!.device.id);
		const b2 = await sealKeyring(k2, a!.seed);
		const t2 = await openKeyring(b2, ctx(a!.seed), t1);
		const bobView = await openKeyring(b2, ctx(b!.seed));
		expect(bobView.keyring).toEqual(t2.keyring);

		const k3 = addKeyringDevice(t2.keyring, c!.device, b!.device.id);
		const b3 = await sealKeyring(k3, b!.seed);
		const k4 = removeKeyringDeviceAndRotate(k3, a!.device.id, c!.device.id);
		const b4 = await sealKeyring(k4, c!.seed);
		const t4 = await openKeyringChain([b3, b4], ctx(b!.seed), bobView);
		expect(t4.keyring.currentEpoch).toBe(2);
		expect(epochKey(t4.keyring, 1)).toEqual(epochKey(t1.keyring, 1));
		expect(epochKey(t4.keyring)).not.toEqual(epochKey(t1.keyring));

		expect(await errorCode(openKeyring(b4, ctx(a!.seed), t2))).toBe("chain-gap");
		expect(await errorCode(openKeyring(b4, ctx(a!.seed)))).toBe("not-a-recipient");

		const d = new Decrypter();
		d.addIdentity(recovery.identity);
		expect(JSON.parse(fromUtf8(await d.decrypt(b3.keyring))).version).toBe(3);
		// a set the recovery key, so removing a removes it too.
		await expect(d.decrypt(b4.keyring)).rejects.toThrow();
	});

	it("adds a device with the recovery key", async () => {
		const recovery = await generateRecoveryKey();
		const k1 = setKeyringRecovery(createKeyring({ vaultId: "vault-1", name: "Work", device: a!.device }), recovery, "d_0");
		const k1Blob = await sealKeyring({ ...k1, version: 1 }, a!.seed);
		const t1 = await openKeyring(k1Blob, ctx(a!.seed));
		expect(t1.keyring.recoverySetBy).toBe("d_0");

		// Every device is lost: c recovers with the recovery key.
		const opened = await openKeyringWithRecovery(k1Blob, { identity: recovery.identity, vaultId: "vault-1", name: "Work" });
		const k2 = addKeyringDevice(opened.keyring, c!.device, c!.device.id);
		const b2 = await sealKeyring(k2, recoverySigningSeed(recovery.identity));
		expect((await openKeyring(b2, ctx(c!.seed))).keyring.devices.map((d) => d.id)).toEqual(["d_0", "d_2"]);
		expect((await openKeyring(b2, ctx(a!.seed), t1)).pin.version).toBe(2);

		// The recovery key can't replace itself.
		const other = await generateRecoveryKey();
		const k3 = setKeyringRecovery(k2, other, c!.device.id);
		expect(k3.currentEpoch).toBe(2);
		const b3 = await sealKeyring({ ...k3, recoverySigner: recovery.signer }, recoverySigningSeed(recovery.identity));
		const t2 = await openKeyring(b2, ctx(c!.seed));
		expect(await errorCode(openKeyring(b3, ctx(c!.seed), t2))).toBe("inconsistent");
		// A device can, in its own name.
		const t3 = await openKeyring(await sealKeyring(k3, c!.seed), ctx(c!.seed), t2);
		expect(t3.keyring.recoverySetBy).toBe("d_2");
	});

	it("revoking the device that set the recovery key removes it", async () => {
		const recovery = await generateRecoveryKey();
		const k1 = createKeyring({ vaultId: "vault-1", name: "Work", device: a!.device, recovery });
		const k2 = addKeyringDevice(k1, b!.device, a!.device.id);
		const k3 = removeKeyringDeviceAndRotate(k2, a!.device.id, b!.device.id);
		expect(k3.recovery ?? k3.recoverySigner ?? k3.recoverySetBy).toBeUndefined();
		const t2 = await openKeyring(await sealKeyring(k2, a!.seed), ctx(b!.seed));
		expect((await openKeyring(await sealKeyring(k3, b!.seed), ctx(b!.seed), t2)).keyring.recovery).toBeUndefined();
		// Revoking another device keeps it.
		const k4 = addKeyringDevice(k3, c!.device, b!.device.id);
		const k5 = setKeyringRecovery(k4, recovery, b!.device.id);
		expect(removeKeyringDeviceAndRotate(k5, c!.device.id, b!.device.id).recovery).toBe(recovery.recipient);
	});

	it("refuses to sign with a device outside the keyring", async () => {
		const k1 = createKeyring({ vaultId: "vault-1", name: "Work", device: a!.device });
		await expect(sealKeyring(k1, b!.seed)).rejects.toThrow();
	});
});
