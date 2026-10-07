import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";

import { IndexedDbStore } from "../src/store/idb";
import { countFiles, MemoryStore, type SyncStore } from "../src/store/state";
import { openLastVault, VAULT_ID } from "../src/sync/session";

const file = { fileId: "f", rev: 3, deleted: false, sha256: "ab", size: 2, mtime: 5 };

describe.each([
	["MemoryStore", async () => new MemoryStore() as SyncStore],
	["IndexedDbStore", async () => IndexedDbStore.open("test", new IDBFactory())],
])("%s", (_name, open) => {
	it("keeps metadata and file state", async () => {
		const store = await open();
		expect(await store.getMeta("cursor")).toBeUndefined();
		await store.setMeta("cursor", 7);
		await store.setMeta("pin", { version: 1, sha256: "x" });
		expect(await store.getMeta("cursor")).toBe(7);
		expect(await store.getMeta("pin")).toEqual({ version: 1, sha256: "x" });

		await store.putFile("a.md", file);
		await store.putFile("b.md", { ...file, rev: 4 });
		expect(await store.getFile("a.md")).toEqual(file);
		await store.removeFile("a.md");
		expect([...(await store.files()).keys()]).toEqual(["b.md"]);
		await store.putFile("gone.md", { ...file, deleted: true });
		expect(await countFiles(store)).toBe(1);
		store.close();
	});

	it("queues each path once, oldest first", async () => {
		const store = await open();
		await store.enqueue("a.md");
		await new Promise((r) => setTimeout(r, 2));
		await store.enqueue("b.md");
		const [first] = await store.outbox();
		await store.enqueue("a.md");
		const entries = await store.outbox();
		expect(entries.map((e) => e.path)).toEqual(["a.md", "b.md"]);
		expect(entries[0]!.queuedAt).toBe(first!.queuedAt);
		expect(entries[0]!.id).not.toBe(first!.id);
		store.close();
	});

	it("keeps an entry that was queued again while it was pushed", async () => {
		const store = await open();
		await store.enqueue("a.md");
		const [taken] = await store.outbox();
		await store.enqueue("a.md");
		await store.dequeue(taken!);
		expect((await store.outbox()).map((e) => e.path)).toEqual(["a.md"]);
		const [again] = await store.outbox();
		await store.dequeue(again!);
		expect(await store.outbox()).toEqual([]);
		store.close();
	});

	it("clears everything", async () => {
		const store = await open();
		await store.setMeta("cursor", 1);
		await store.putFile("a.md", file);
		await store.enqueue("a.md");
		await store.clear();
		expect(await store.getMeta("cursor")).toBeUndefined();
		expect((await store.files()).size).toBe(0);
		expect(await store.outbox()).toEqual([]);
		store.close();
	});
});

describe("openLastVault", () => {
	it("opens the last vault's local state only for the same key slot and vault", async () => {
		const factory = new IDBFactory();
		const opened: string[] = [];
		const openStore = async (vaultId: string) => {
			opened.push(vaultId);
			return IndexedDbStore.open(`test-${vaultId}`, factory);
		};
		const synced = await openStore("v1");
		await synced.setMeta(VAULT_ID, "v1");
		await synced.enqueue("a.md");
		synced.close();
		opened.length = 0;

		expect(await openLastVault(null, "slot", openStore)).toBeNull();
		expect(await openLastVault({ slot: "other", vaultId: "v1" }, "slot", openStore)).toBeNull();
		expect(opened).toEqual([]);
		// A store that isn't that vault's (never synced, or cleared) isn't used.
		expect(await openLastVault({ slot: "slot", vaultId: "v2" }, "slot", openStore)).toBeNull();

		const store = await openLastVault({ slot: "slot", vaultId: "v1" }, "slot", openStore);
		expect((await store!.outbox()).map((e) => e.path)).toEqual(["a.md"]);
		store!.close();
	});
});
