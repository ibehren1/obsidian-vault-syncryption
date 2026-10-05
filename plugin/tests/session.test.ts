import { describe, expect, it } from "vitest";

import { generateRecoveryKey } from "../src/crypto/keyring";
import { MemoryStore } from "../src/store/state";
import { connect, PIN, SetupCancelled, VAULT_ID } from "../src/sync/session";
import { client, newSeed, noBackend, SHARED_SECRET, uniqueName } from "./harness";
import { device, pairedDevice } from "./sync-fixture";

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
			api: client(uniqueName("cancel"), seed),
			vaultName: "Vault",
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
		expect(await a.session.pendingMembers()).toEqual([]);
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
			api: client(username, seed, "Tablet"),
			vaultName,
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
		const [pending] = await a.session.pendingMembers();
		expect(codes).toEqual([pending!.code]);
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
			vaultName,
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
			vaultName: a.session.vault.name,
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
			api: client(username, seed, "New laptop"),
			vaultName,
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
});
