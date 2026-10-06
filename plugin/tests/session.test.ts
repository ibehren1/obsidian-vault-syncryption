import { describe, expect, it } from "vitest";

import { ApiError } from "../src/api/http";
import { generateRecoveryKey } from "../src/crypto/keyring";
import { secretId } from "../src/keys";
import { MemoryStore } from "../src/store/state";
import { connect, handOver, PIN, REPLACED, SetupCancelled, VAULT_ID } from "../src/sync/session";
import { backendUrl, client, newSeed, noBackend, SHARED_SECRET, uniqueName } from "./harness";
import { device, engineFor, pairedDevice } from "./sync-fixture";

describe.skipIf(noBackend)("connect", () => {
	it("creates the vault on first use and pins its keyring", async () => {
		const username = uniqueName("create");
		const vaultName = uniqueName("Notes ");
		const a = await device(username, ` ${vaultName} `, "Laptop");
		expect(a.session.vault.name).toBe(vaultName);
		expect(a.session.keyring.devices.map((d) => d.id)).toEqual([a.session.deviceId]);
		expect(await a.store.getMeta(VAULT_ID)).toBe(a.session.vault.id);
		expect(await a.store.getMeta(PIN)).toMatchObject({ version: 1 });
	});

	it("stops when the user doesn't give the shared secret", async () => {
		const seed = newSeed();
		const result = connect({
			api: client(uniqueName("cancel"), "Vault", seed),
			deviceName: "Laptop",
			seed,
			openStore: async () => new MemoryStore(),
			callbacks: { askSharedSecret: async () => null, showPairing: () => {} },
		});
		await expect(result).rejects.toBeInstanceOf(SetupCancelled);
	});

	it("pairs a second device after the codes are compared", async () => {
		const username = uniqueName("pair");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const b = await pairedDevice(a, username, vaultName, "Phone");
		expect(b.session.vault.id).toBe(a.session.vault.id);
		expect(b.session.keyring.version).toBe(2);
		expect(b.session.keyring.devices.map((d) => d.name).sort()).toEqual(["Laptop", "Phone"]);
		expect(await a.session.pendingDevices()).toEqual([]);
		const keys = await a.session.devices();
		expect(keys.map((k) => [k.name, k.status]).sort()).toEqual([
			["Laptop", "active"],
			["Phone", "active"],
		]);
		await a.session.refreshKeyring();
		expect(a.session.keyring.version).toBe(2);
	});

	it("shows this device's pairing code and stops waiting when aborted", async () => {
		const username = uniqueName("wait");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const seed = newSeed();
		const controller = new AbortController();
		const codes: string[] = [];
		const waiting = connect({
			api: client(username, vaultName, seed, "Tablet"),
			deviceName: "Tablet",
			seed,
			openStore: async () => new MemoryStore(),
			callbacks: {
				askSharedSecret: async () => SHARED_SECRET,
				showPairing: (code) => {
					codes.push(code);
					controller.abort();
				},
			},
			signal: controller.signal,
			pollMs: 20,
		});
		await expect(waiting).rejects.toBeInstanceOf(SetupCancelled);
		const [pending] = await a.session.pendingDevices();
		expect(codes).toEqual([pending!.code]);
	});

	it("lets a new key of an existing vault wait for approval without the shared secret", async () => {
		const username = uniqueName("nosecret");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const seed = newSeed();
		const controller = new AbortController();
		let asked = false;
		const waiting = connect({
			api: client(username, ` ${vaultName} `, seed, "Phone"),
			deviceName: "Phone",
			seed,
			openStore: async () => new MemoryStore(),
			callbacks: {
				askSharedSecret: async () => {
					asked = true;
					return null;
				},
				showPairing: () => controller.abort(),
			},
			signal: controller.signal,
			pollMs: 20,
		});
		await expect(waiting).rejects.toBeInstanceOf(SetupCancelled);
		expect(asked).toBe(false);
		expect(await a.session.pendingDevices()).toHaveLength(1);
	});

	it("catches up on keyring versions it missed", async () => {
		const username = uniqueName("chain");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const first = await a.store.getMeta(PIN);
		await pairedDevice(a, username, vaultName, "Phone");
		await pairedDevice(a, username, vaultName, "Tablet");
		// A reconnects with its store still pinned at version 1.
		await a.store.setMeta(PIN, first);
		const again = await connect({
			api: a.session.api,
			deviceName: "Laptop",
			seed: (a.session as unknown as { seed: Uint8Array }).seed,
			openStore: async () => a.store,
			callbacks: { askSharedSecret: async () => null, showPairing: () => {} },
		});
		expect(again.keyring.version).toBe(3);
		expect(await a.store.getMeta(PIN)).toMatchObject({ version: 3 });
	});

	it("refuses a server that swapped the pinned keyring", async () => {
		const a = await device(uniqueName("swap"), uniqueName("Vault "), "Laptop");
		await a.store.setMeta(PIN, { version: 1, sha256: "0".repeat(64) });
		const again = connect({
			api: a.session.api,
			deviceName: "Laptop",
			seed: (a.session as unknown as { seed: Uint8Array }).seed,
			openStore: async () => a.store,
			callbacks: { askSharedSecret: async () => null, showPairing: () => {} },
		});
		await expect(again).rejects.toMatchObject({ code: "rollback" });
	});

	it("recovers the vault with the recovery key when no device can approve", async () => {
		const username = uniqueName("recover");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const recovery = await generateRecoveryKey();
		await a.session.setRecovery(recovery);
		expect(a.session.keyring).toMatchObject({ version: 2, recoverySetBy: a.session.deviceId });

		const seed = newSeed();
		const errors: unknown[] = [];
		const store = new MemoryStore();
		const recovered = await connect({
			api: client(username, vaultName, seed, "New laptop"),
			deviceName: "New laptop",
			seed,
			openStore: async () => store,
			callbacks: {
				askSharedSecret: async () => SHARED_SECRET,
				showPairing: (_code, recover) => {
					// A wrong key first, then the right one.
					void generateRecoveryKey()
						.then((other) => recover!(other.identity))
						.catch((e: unknown) => errors.push(e))
						.then(() => recover!(recovery.identity));
				},
			},
			pollMs: 20,
		});
		expect(errors).toHaveLength(1);
		expect(recovered.keyring.version).toBe(3);
		expect(recovered.keyring.devices.map((d) => d.name)).toEqual(["Laptop", "New laptop"]);
		expect(await store.getMeta(PIN)).toMatchObject({ version: 3 });
		// The old device accepts the recovery-signed version.
		await a.session.refreshKeyring();
		expect(a.session.keyring.version).toBe(3);
	});

	it("keeps the recovery key in other uploads and removes it on request", async () => {
		const username = uniqueName("recovery");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const recovery = await generateRecoveryKey();
		await a.session.setRecovery(recovery);
		const b = await pairedDevice(a, username, vaultName, "Phone");
		expect(b.session.keyring.recoverySigner).toBe(recovery.signer);
		expect((await a.session.api.keyring(a.session.vault.id)).recoverySigner).toBe(recovery.signer);
		await b.session.setRecovery(undefined);
		await a.session.refreshKeyring();
		expect(a.session.keyring.recovery).toBeUndefined();
		await expect(a.session.api.recoveryKeyring(a.session.vault.id)).rejects.toMatchObject({ code: "no_recovery" });
	});

	it("uses one key per vault: two vaults on one device are two keys", async () => {
		const username = uniqueName("twovaults");
		const [notes, work] = [uniqueName("Notes "), uniqueName("Work ")];
		const a = await device(username, notes, "Laptop");
		const b = await device(username, work, "Laptop");
		expect(b.session.vault.id).not.toBe(a.session.vault.id);
		expect(b.session.api.publicKey).not.toEqual(a.session.api.publicKey);
		expect(await a.session.api.selfDevice()).toMatchObject({ vaultId: a.session.vault.id, vaultName: notes });
		expect(await b.session.api.selfDevice()).toMatchObject({ vaultId: b.session.vault.id, vaultName: work });
		expect(secretId(backendUrl, username, notes)).not.toBe(secretId(backendUrl, username, work));
	});

	it("refuses the key of one vault for a second vault", async () => {
		const username = uniqueName("reuse");
		const seed = newSeed();
		await device(username, uniqueName("Notes "), "Laptop", seed);
		const second = connect({
			api: client(username, uniqueName("Work "), seed, "Laptop"),
			deviceName: "Laptop",
			seed,
			openStore: async () => new MemoryStore(),
			callbacks: { askSharedSecret: async () => SHARED_SECRET, showPairing: () => {} },
		});
		await expect(second).rejects.toBeInstanceOf(ApiError);
	});

	it("replaces this device's key: the old key approves the new one, which removes it", async () => {
		const username = uniqueName("replace");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const b = await pairedDevice(a, username, vaultName, "Phone");
		a.fs.set("note.md", "hello\n");
		await a.engine.sync();
		const oldId = a.session.deviceId;

		const seed = newSeed();
		const api = client(username, vaultName, seed, "Laptop");
		await handOver(a.session, api, "Laptop");
		// Not saved yet: the old key still works, and reconnecting with it removes nothing.
		await a.engine.sync();
		expect(a.session.keyring.devices).toHaveLength(3);

		// Saved: the new key connects with the same local state and removes the old key.
		const replaced = await connect({
			api,
			deviceName: "Laptop",
			seed,
			openStore: async () => a.store,
			callbacks: { askSharedSecret: async () => null, showPairing: () => expect.fail("asked to pair") },
		});
		expect(await replaced.finishReplace()).toBe(true);
		expect(await replaced.finishReplace()).toBe(false);
		expect(replaced.keyring.devices.map((d) => d.id).sort()).toEqual([b.session.deviceId, replaced.deviceId].sort());
		expect(replaced.keyring.currentEpoch).toBe(2);
		await expect(a.engine.sync()).rejects.toMatchObject({ status: 403 });
		const status = new Map((await replaced.devices()).map((d) => [d.id, d.status]));
		expect(status.get(oldId)).toBe("revoked");
		expect(status.get(replaced.deviceId)).toBe("active");

		const engine = engineFor(replaced, a.fs, "Laptop", []);
		expect((await engine.sync()).reencrypted).toBe(1);
		await b.session.refreshKeyring();
		expect(b.session.keyring.currentEpoch).toBe(2);
	});

	it("keeps the old key when a replace stops before the new key is saved", async () => {
		const username = uniqueName("replacefail");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		await handOver(a.session, client(username, vaultName, newSeed(), "Laptop"), "Laptop");
		// The new key was lost: the old key connects again and doesn't remove itself.
		const again = await connect({
			api: client(username, vaultName, (a.session as unknown as { seed: Uint8Array }).seed, "Laptop"),
			deviceName: "Laptop",
			seed: (a.session as unknown as { seed: Uint8Array }).seed,
			openStore: async () => a.store,
			callbacks: { askSharedSecret: async () => null, showPairing: () => {} },
		});
		expect(await again.finishReplace()).toBe(false);
		expect(await a.store.getMeta(REPLACED)).toBeNull();
		// The unused key is in the vault, and this device can remove it.
		const extra = again.keyring.devices.find((d) => d.id !== again.deviceId)!;
		await again.removeDevice(extra.id);
		expect(again.keyring.devices.map((d) => d.id)).toEqual([again.deviceId]);
	});
});
