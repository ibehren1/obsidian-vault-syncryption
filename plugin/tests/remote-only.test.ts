import { describe, expect, it } from "vitest";

import { complianceReport, duration, type ComplianceFacts } from "../src/remote/compliance";
import { RemoteStatFs } from "../src/remote/stat-fs";
import { MemoryEntryStore, StubAdapter, type WrappedAdapter } from "../src/remote/stub-adapter";
import { MemoryFs, type FileStat, type ListedFile, type VaultFs } from "../src/sync/fs";
import { DeviceMismatchError } from "../src/api/client";
import { isLocked } from "../src/api/http";
import { MemoryStore } from "../src/store/state";
import { connect } from "../src/sync/session";
import { FakeDisk } from "./fake-disk";
import { noBackend, uniqueName } from "./harness";
import { device, engineFor, pairedDevice } from "./sync-fixture";

const NOW = 1_790_000_000_000;

/** A remote-only device's files as the engine sees them: through the wrapped adapter. */
class StubFs implements VaultFs {
	constructor(
		private readonly disk: FakeDisk,
		private readonly adapter: WrappedAdapter,
	) {}
	async list(): Promise<ListedFile[]> {
		return Promise.all([...this.disk.files.keys()].map(async (path) => ({ path, ...(await this.stat(path))! })));
	}
	async stat(path: string): Promise<FileStat | null> {
		const s = await this.adapter.stat(path);
		return s && { mtime: s.mtime, ctime: s.ctime, size: s.size };
	}
	async read(path: string): Promise<Uint8Array> {
		return new Uint8Array(await this.adapter.readBinary(path));
	}
	write(path: string, data: Uint8Array, times: { mtime: number; ctime?: number }): Promise<void> {
		return this.adapter.writeBinary(path, data.slice().buffer, times);
	}
	remove(path: string): Promise<void> {
		return this.adapter.remove(path);
	}
}

function wrap(disk: FakeDisk, store = new MemoryEntryStore()) {
	const stub = new StubAdapter({ isRemote: (p) => !p.startsWith("."), store, urls: { create: () => "", revoke: () => {} } });
	const uninstall = stub.install(disk);
	stub.unlock(new Uint8Array(32).fill(3));
	return { stub, uninstall };
}

function facts(over: Partial<ComplianceFacts> = {}): ComplianceFacts {
	return {
		keyringRemoteOnly: true,
		flag: { vaultId: "v1" },
		installed: true,
		locked: false,
		lease: { at: NOW - 3_600_000, graceSeconds: 86_400 },
		now: NOW,
		remoteFiles: 3,
		plaintext: [],
		storeEntries: 3,
		orphans: 0,
		missing: 0,
		fileRecovery: false,
		plainHashes: 0,
		...over,
	};
}

describe("compliance report", () => {
	it("passes a remote-only device that follows every rule", () => {
		const report = complianceReport(facts());
		expect(report).toMatchObject({ remoteOnly: true, source: "keyring", compliant: true });
		expect(report.checks.find((c) => c.name === "Lease")?.detail).toBe("Valid for 23 h.");
	});

	it("fails on plaintext on disk, File Recovery, plaintext hashes and an expired lease", () => {
		const paths = ["a.md", "b.md", "c.md", "d.md", "e.md", "f.md", "g.md"];
		const report = complianceReport(
			facts({ plaintext: paths, fileRecovery: true, plainHashes: 2, lease: { at: NOW - 90_000_000, graceSeconds: 86_400 } }),
		);
		expect(report.compliant).toBe(false);
		const failed = report.checks.filter((c) => !c.ok).map((c) => c.name);
		expect(failed).toEqual(["No plaintext on disk", "File Recovery core plugin", "Content hashes sealed", "Lease"]);
		expect(report.checks[2]!.detail).toBe("Not empty on disk: a.md, b.md, c.md, d.md, e.md and 2 more.");
	});

	it("counts a locked device's lease as kept", () => {
		const report = complianceReport(facts({ locked: true, lease: null, keyringRemoteOnly: null, plainHashes: null }));
		expect(report).toMatchObject({ source: "this device", compliant: true });
		expect(report.checks.map((c) => c.name)).not.toContain("Content hashes sealed");
	});

	it("reports a full device, and one still holding stubs", () => {
		expect(complianceReport(facts({ keyringRemoteOnly: false, flag: null }))).toMatchObject({ remoteOnly: false, compliant: true });
		expect(complianceReport(facts({ keyringRemoteOnly: false })).compliant).toBe(false);
	});

	it("formats durations", () => {
		expect(duration(90_000)).toBe("2 min");
		expect(duration(5_400_000)).toBe("1 h 30 min");
		expect(duration(-5)).toBe("0 min");
	});
});

describe("RemoteStatFs", () => {
	it("reports the stored size and times of remote-only files", async () => {
		const store = new MemoryEntryStore();
		await store.put("R/a.md", { nonce: new Uint8Array(24), data: new Uint8Array(1), size: 42, mtime: 7, ctime: 3 });
		const stub = new StubAdapter({ isRemote: (p) => p.startsWith("R/"), store });
		await stub.load();
		const inner = new MemoryFs();
		inner.set("R/a.md", "");
		inner.set("b.md", "plain");
		const fs = new RemoteStatFs(inner, () => stub);
		const listed = new Map((await fs.list()).map((f) => [f.path, f]));
		expect(listed.get("R/a.md")).toMatchObject({ size: 42, mtime: 7, ctime: 3 });
		expect(listed.get("b.md")).toMatchObject({ size: 5 });
		expect(await fs.stat("R/a.md")).toMatchObject({ size: 42 });
		expect(await new RemoteStatFs(inner, () => null).stat("R/a.md")).toMatchObject({ size: 0 });
	});
});

describe.skipIf(noBackend)("remote-only approval", () => {
	it("receives a large file into the store chunk by chunk, and doesn't read it back", async () => {
		const username = uniqueName("remote");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const b = await pairedDevice(a, username, vaultName, "Phone", undefined, { remoteOnly: true });
		// Two server chunks of 4 MiB.
		const data = new Uint8Array(5 * 1024 * 1024).map((_, i) => (i * 7) & 0xff);
		a.fs.set("Decks/big.pdf", data);
		await a.engine.sync();

		const disk = new FakeDisk();
		const store = new MemoryEntryStore();
		const { stub } = wrap(disk, store);
		const fs = new RemoteStatFs(new StubFs(disk, disk), () => stub);
		let reads = 0;
		const read = fs.read.bind(fs);
		fs.read = async (path) => {
			reads++;
			return read(path);
		};
		const warnings: string[] = [];
		const engine = engineFor(b.session, fs, "Phone", warnings);
		await engine.sync();
		expect(store.chunks.size).toBe(2);
		expect(disk.files.get("Decks/big.pdf")!.data.length).toBe(0);
		expect(stub.info("Decks/big.pdf")!.size).toBe(data.length);
		expect(new Uint8Array(await disk.readBinary("Decks/big.pdf"))).toEqual(data);

		// Queued by Obsidian's events for the write: skipped without reading the file.
		await b.session.store.enqueue("Decks/big.pdf");
		reads = 0;
		expect((await engine.sync()).pushed).toBe(0);
		expect(reads).toBe(0);
		expect(warnings).toEqual([]);
	}, 60_000);

	it("puts the policy in the keyring and the server refuses management", async () => {
		const username = uniqueName("remote");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const b = await pairedDevice(a, username, vaultName, "Phone", undefined, { remoteOnly: true });
		expect(b.session.remoteOnly).toBe(true);
		expect(a.session.remoteOnly).toBe(false);
		expect(a.session.keyring.devices.map((d) => d.policy)).toEqual([undefined, "remote-only"]);
		await b.session.api.login();
		expect(b.session.api.lastLogin).toMatchObject({ remoteOnly: true });
		expect(b.session.api.lastLogin!.graceSeconds).toBeGreaterThan(0);

		// It syncs, but can't approve keys.
		a.fs.set("note.md", "hello\n");
		await a.engine.sync();
		await b.engine.sync();
		expect(b.fs.text("note.md")).toBe("hello\n");
		await expect(b.session.api.approveDevice(b.session.vault.id, a.session.deviceId)).rejects.toMatchObject({
			status: 403,
			code: "remote_only",
		});
	});

	it("follows its own keyring entry, not the device id the server returns", async () => {
		const username = uniqueName("swapid");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const b = await pairedDevice(a, username, vaultName, "Phone", undefined, { remoteOnly: true });
		const api = a.session.api;
		const own = api.deviceId;
		// A server that names the full device with the remote-only device's id.
		api.deviceId = b.session.deviceId;
		await expect(api.login()).rejects.toBeInstanceOf(DeviceMismatchError);
		await expect(a.session.refreshKeyring()).rejects.toBeInstanceOf(DeviceMismatchError);
		expect(() => a.session.remoteOnly).toThrow(DeviceMismatchError);
		const again = connect({
			api,
			deviceName: "Laptop",
			seed: (a.session as unknown as { seed: Uint8Array }).seed,
			openStore: async () => new MemoryStore(),
			callbacks: { askSharedSecret: async () => null, showPairing: () => {} },
		});
		await expect(again).rejects.toBeInstanceOf(DeviceMismatchError);

		api.deviceId = own;
		await a.session.refreshKeyring();
		expect(a.session.remoteOnly).toBe(false);
	});
});

describe.skipIf(noBackend)("stubs without their content", () => {
	it("are downloaded again, never committed as empty notes", async () => {
		const username = uniqueName("stubs");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const b = await pairedDevice(a, username, vaultName, "Phone", undefined, { remoteOnly: true });
		a.fs.set("note.md", "hello\n");
		a.fs.set("empty.md", "");
		await a.engine.sync();

		const disk = new FakeDisk();
		let { uninstall } = wrap(disk);
		const warnings: string[] = [];
		await engineFor(b.session, new StubFs(disk, disk), "Phone", warnings).sync();
		expect(disk.text("note.md")).toBe("");
		expect(await disk.read("note.md")).toBe("hello\n");

		// The sealed content is lost (a new, empty store): only the stubs are left.
		uninstall();
		({ uninstall } = wrap(disk));
		const engine = engineFor(b.session, new StubFs(disk, disk), "Phone", warnings);
		await engine.sync();
		expect(await disk.read("note.md")).toBe("hello\n");
		expect(warnings).toEqual(["Downloaded 1 file again: the content was missing on this device."]);
		await a.engine.sync();
		expect(a.fs.text("note.md")).toBe("hello\n");
		expect((await a.engine.history("note.md")).entries).toHaveLength(1);
	});

	it("aren't committed by a sync still running when the engine closes", async () => {
		const [a, b] = await (async () => {
			const username = uniqueName("close");
			const vaultName = uniqueName("Vault ");
			const first = await device(username, vaultName, "Laptop");
			return [first, await pairedDevice(first, username, vaultName, "Phone")] as const;
		})();
		a.fs.set("note.md", "one\n");
		await a.engine.sync();
		a.fs.set("note.md", "two\n");
		a.engine.close();
		await expect(a.engine.sync()).rejects.toThrow("Sync stopped.");
		await b.engine.sync();
		expect(b.fs.text("note.md")).toBe("one\n");
	});
});

describe.skipIf(noBackend)("changing another device", () => {
	it("makes a device remote-only and back, and locks and unlocks it", async () => {
		const username = uniqueName("policy");
		const vaultName = uniqueName("Vault ");
		const a = await device(username, vaultName, "Laptop");
		const b = await pairedDevice(a, username, vaultName, "Phone");
		expect(b.session.remoteOnly).toBe(false);

		await a.session.setPolicy(b.session.deviceId, true);
		await b.session.refreshKeyring();
		expect(b.session.remoteOnly).toBe(true);
		await b.session.api.login();
		expect(b.session.api.lastLogin).toMatchObject({ remoteOnly: true });

		await a.session.setLocked(b.session.deviceId, true);
		const devices = await a.session.devices();
		expect(devices.find((d) => d.id === b.session.deviceId)).toMatchObject({ locked: true });
		const err = await b.session.api.login().catch((e: unknown) => e);
		expect(isLocked(err)).toBe(true);
		await a.session.setLocked(b.session.deviceId, false);
		await b.session.api.login();

		await a.session.setPolicy(b.session.deviceId, false);
		await b.session.refreshKeyring();
		expect(b.session.remoteOnly).toBe(false);
		await expect(a.session.setPolicy(a.session.deviceId, true)).rejects.toThrow();
	});
});
