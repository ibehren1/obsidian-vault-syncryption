import { describe, expect, it } from "vitest";

import { VaultCipher } from "../src/sync/cipher";
import { LiveLoop } from "../src/sync/live";
import { LockManager, newClientId } from "../src/sync/locks";
import { noBackend } from "./harness";
import { twoDevices, type Device } from "./sync-fixture";

function locks(d: Device, opts: { clientId?: string; now?: () => number } = {}): LockManager {
	return new LockManager({
		api: d.session.api,
		vaultId: d.session.vault.id,
		cipher: new VaultCipher(() => d.session.keyring),
		deviceId: d.session.deviceId,
		clientId: opts.clientId ?? newClientId(),
		...(opts.now ? { now: opts.now } : {}),
	});
}

describe("newClientId", () => {
	it("is 22 base64url characters", () => {
		expect(newClientId()).toMatch(/^[A-Za-z0-9_-]{22}$/);
		expect(newClientId()).not.toBe(newClientId());
	});
});

describe.skipIf(noBackend)("LockManager", () => {
	it("holds the open file and reports another device's lock", async () => {
		const [a, b] = await twoDevices();
		const laptop = locks(a);
		const phone = locks(b);
		expect(await laptop.hold("Note.md")).toBeNull();
		expect(laptop.held).toBe("Note.md");

		const other = await phone.hold("Note.md");
		expect(other?.deviceName).toBe("Laptop");
		expect(phone.heldByOther("Note.md")?.device).toBe(a.session.deviceId);
		// Renewing your own lock is fine.
		expect(await laptop.renew()).toBeNull();

		expect(await phone.refresh()).toBe(true);
		expect(phone.heldByOther("Note.md")?.deviceName).toBe("Laptop");
		expect(phone.heldByOther("Other.md")).toBeNull();
		// Your own locks aren't someone else's.
		await laptop.refresh();
		expect(laptop.heldByOther("Note.md")).toBeNull();

		// Moving to another file releases the first.
		await laptop.hold("Other.md");
		await phone.refresh();
		expect(phone.heldByOther("Note.md")).toBeNull();
		expect(phone.heldByOther("Other.md")?.deviceName).toBe("Laptop");
		expect(await phone.hold("Note.md")).toBeNull();

		await laptop.releaseAll();
		expect(laptop.held).toBeNull();
		await phone.refresh();
		expect(phone.heldByOther("Other.md")).toBeNull();
	});

	it("treats another installation with the same device as another holder", async () => {
		const [a] = await twoDevices();
		const first = locks(a);
		await first.hold("Note.md");
		const clientId = newClientId();
		const other = await locks(a, { clientId }).hold("Note.md");
		expect(other?.device).toBe(a.session.deviceId);
		expect(other?.clientId).not.toBe(clientId);
	});

	it("ignores locks past their expiry", async () => {
		const [a, b] = await twoDevices();
		let now = Date.now();
		const phone = locks(b, { now: () => now });
		await locks(a).hold("Note.md");
		await phone.refresh();
		expect(phone.heldByOther("Note.md")).not.toBeNull();
		now += 121_000;
		expect(phone.heldByOther("Note.md")).toBeNull();
	});
});

describe.skipIf(noBackend)("LiveLoop", () => {
	it("syncs when another device pushes and refreshes when locks change", async () => {
		const [a, b] = await twoDevices();
		await b.engine.sync();
		const events: string[] = [];
		let changed = (): void => {};
		let locked = (): void => {};
		const loop = new LiveLoop({
			api: b.session.api,
			vaultId: b.session.vault.id,
			cursor: async () => (await b.store.getMeta<number>("cursor")) ?? 0,
			onChanges: async () => {
				await b.engine.sync();
				events.push("changes");
				changed();
			},
			onLocks: async () => {
				events.push("locks");
				locked();
			},
			timeout: 5,
		});
		loop.start();

		const gotChanges = new Promise<void>((r) => (changed = r));
		a.fs.set("Note.md", "hello\n");
		await a.engine.sync();
		await gotChanges;
		expect(b.fs.text("Note.md")).toBe("hello\n");

		const gotLocks = new Promise<void>((r) => (locked = r));
		await locks(a).hold("Note.md");
		await gotLocks;
		expect(events).toEqual(["changes", "locks"]);

		const stopped = loop.stop();
		await locks(a).hold("Other.md");
		await stopped;
	});

	it("backs off after failed waits", async () => {
		const [, b] = await twoDevices();
		const sleeps: number[] = [];
		let done = (): void => {};
		const finished = new Promise<void>((r) => (done = r));
		const loop: LiveLoop = new LiveLoop({
			api: b.session.api,
			// Not a vault of this device, so every wait fails.
			vaultId: "AAAAAAAAAAAAAAAAAAAAAA",
			cursor: async () => 0,
			onChanges: async () => {},
			onLocks: async () => {},
			sleep: async (ms) => {
				sleeps.push(ms);
				if (sleeps.length === 8) void loop.stop().then(done);
			},
		});
		loop.start();
		await finished;
		expect(sleeps).toEqual([1000, 2000, 4000, 8000, 16_000, 32_000, 60_000, 60_000]);
	});
});
