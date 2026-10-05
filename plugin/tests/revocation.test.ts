import { describe, expect, it } from "vitest";

import { fromB64u } from "../src/crypto/bytes";
import { generateRecoveryKey } from "../src/crypto/keyring";
import { objectEpoch } from "../src/crypto/objects";
import { VaultCipher } from "../src/sync/cipher";
import { LiveLoop } from "../src/sync/live";
import { newSeed, noBackend, uniqueName } from "./harness";
import { device, pairedDevice, type Device } from "./sync-fixture";

async function headEpoch(d: Device, path: string): Promise<number> {
	const fileId = new VaultCipher(() => d.session.keyring).fileId(path);
	const head = await d.session.api.head(d.session.vault.id, fileId);
	return objectEpoch(fromB64u(head.meta));
}

async function threeDevices(): Promise<[Device, Device, Device]> {
	const username = uniqueName("revoke");
	const vaultName = uniqueName("Vault ");
	const a = await device(username, vaultName, "Laptop");
	const b = await pairedDevice(a, username, vaultName, "Phone");
	const c = await pairedDevice(a, username, vaultName, "Tablet");
	await b.session.refreshKeyring();
	return [a, b, c];
}

describe.skipIf(noBackend)("revocation", () => {
	it("removes a device, rotates the key and re-encrypts every file", async () => {
		const [a, b, c] = await threeDevices();
		a.fs.set("one.md", "one\n");
		a.fs.set("two.md", "two\n");
		await a.engine.sync();
		await b.engine.sync();
		await c.engine.sync();

		await a.session.removeDevice(c.session.deviceId);
		expect(a.session.keyring.currentEpoch).toBe(2);
		expect(a.session.keyring.devices.map((d) => d.name)).toEqual(["Laptop", "Phone"]);
		await expect(c.engine.sync()).rejects.toMatchObject({ status: 403 });

		// b writes before it knows about the rotation: the feed tells it to refresh first.
		b.fs.set("three.md", "three\n");
		const report = await b.engine.sync();
		expect(b.session.keyring.currentEpoch).toBe(2);
		expect(report.reencrypted).toBe(2);
		expect(await headEpoch(b, "three.md")).toBe(2);
		expect(await headEpoch(b, "one.md")).toBe(2);

		// a pulls the re-encrypted revisions without writing them again.
		const pulled = await a.engine.sync();
		expect(pulled.reencrypted).toBe(0);
		expect(a.fs.text("three.md")).toBe("three\n");
		expect((await b.engine.sync()).reencrypted).toBe(0);
		expect([...a.warnings, ...b.warnings]).toEqual([]);
	});

	it("leaves files with local changes to the outbox", async () => {
		const [a, b] = await threeDevices();
		a.fs.set("note.md", "first\n");
		await a.engine.sync();
		await b.engine.sync();
		b.fs.set("note.md", "edited\n");
		const tablet = a.session.keyring.devices.find((d) => d.name === "Tablet")!;
		await a.session.removeDevice(tablet.id);
		const report = await b.engine.sync();
		expect(report).toMatchObject({ pushed: 1, reencrypted: 0 });
		expect(await headEpoch(b, "note.md")).toBe(2);
		await a.engine.sync();
		expect(a.fs.text("note.md")).toBe("edited\n");
	});

	it("removes the recovery key with the device that set it", async () => {
		const [a, b, c] = await threeDevices();
		await c.session.setRecovery(await generateRecoveryKey());
		await a.session.removeDevice(c.session.deviceId);
		expect(a.session.keyring.recovery).toBeUndefined();
		await b.session.refreshKeyring();
		expect(b.session.keyring.recoverySetBy).toBeUndefined();
	});

	it("finishes a revocation done for the whole account in another vault", async () => {
		const username = uniqueName("stale");
		const first = uniqueName("Vault ");
		const second = uniqueName("Vault ");
		const [laptop, phone] = [newSeed(), newSeed()];
		const a = await device(username, first, "Laptop", laptop);
		const b = await pairedDevice(a, username, first, "Phone", phone);
		const a2 = await device(username, second, "Laptop", laptop);
		await pairedDevice(a2, username, second, "Phone", phone);
		expect(a2.session.keyring.devices).toHaveLength(2);

		await a.session.removeDevice(b.session.deviceId, true);
		expect(await a.session.removeStaleDevices()).toEqual([]);
		expect(await a2.session.removeStaleDevices()).toEqual(["Phone"]);
		expect(a2.session.keyring).toMatchObject({ currentEpoch: 2, version: 3 });
	});

	it("wakes the live loop of the other devices on a new keyring", async () => {
		const [a, b, c] = await threeDevices();
		await b.engine.sync();
		let refreshed = (): void => {};
		const gotKeyring = new Promise<void>((r) => (refreshed = r));
		const loop = new LiveLoop({
			api: b.session.api,
			vaultId: b.session.vault.id,
			cursor: async () => (await b.store.getMeta<number>("cursor")) ?? 0,
			keyringVersion: () => b.session.keyring.version,
			onChanges: async () => {
				await b.engine.sync();
				if (b.session.keyring.currentEpoch === 2) refreshed();
			},
			onLocks: async () => {},
			timeout: 5,
		});
		loop.start();
		await a.session.removeDevice(c.session.deviceId);
		await gotKeyring;
		const stopped = loop.stop();
		a.fs.set("wake.md", "x\n");
		await a.engine.sync();
		await stopped;
	});

	it("can't remove this device", async () => {
		const [a] = await threeDevices();
		await expect(a.session.removeDevice(a.session.deviceId)).rejects.toThrow("can't remove itself");
	});
});
