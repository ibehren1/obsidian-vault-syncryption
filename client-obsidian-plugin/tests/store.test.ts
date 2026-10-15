import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";

import { deleteDatabase, IndexedDbEntryStore } from "../src/store/entries";
import { IndexedDbStore } from "../src/store/idb";
import { SealedHashStore, type HashMode } from "../src/store/sealed";
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

describe("SealedHashStore", () => {
	const key = new Uint8Array(32).fill(3);
	const sha = "ab".repeat(32);

	it("seals hashes while remote-only and opens them on read", async () => {
		const inner = new MemoryStore();
		let mode: HashMode = "plain";
		const store = new SealedHashStore(inner, () => mode);
		await store.putFile("a.md", { ...file, sha256: sha });
		expect((await inner.getFile("a.md"))!.sha256).toBe(sha);
		mode = key;
		expect(await store.sealAll(key)).toBe(1);
		expect(await store.plainHashes()).toBe(0);
		expect((await inner.getFile("a.md"))!.sha256).toMatch(/^s1:/);
		expect((await store.getFile("a.md"))!.sha256).toBe(sha);
		await store.putFile("b.md", { ...file, sha256: sha });
		expect((await inner.getFile("b.md"))!.sha256).toMatch(/^s1:/);
		await store.putFile("c.md", { ...file, deleted: true, sha256: "" });
		expect([...(await store.files()).values()].map((f) => f.sha256)).toEqual([sha, sha, ""]);

		mode = "locked";
		expect((await store.getFile("a.md"))!.sha256).toMatch(/^s1:/);
		await expect(store.putFile("d.md", { ...file, sha256: sha })).rejects.toThrow();

		expect(await store.openAll(key)).toBe(2);
		mode = "plain";
		expect((await inner.getFile("b.md"))!.sha256).toBe(sha);
	});
});

describe("IndexedDbEntryStore", () => {
	it("keeps sealed entries and their info apart", async () => {
		const factory = new IDBFactory();
		const store = await IndexedDbEntryStore.open("entries", factory);
		const entry = { nonce: new Uint8Array(24), data: new Uint8Array([1, 2]), size: 1, mtime: 2, ctime: 3 };
		await store.put("a.md", entry);
		expect(await store.get("a.md")).toEqual(entry);
		expect(await store.infos()).toEqual(new Map([["a.md", { size: 1, mtime: 2, ctime: 3 }]]));
		await store.delete("a.md");
		expect((await store.infos()).size).toBe(0);
		store.close();
		await deleteDatabase("entries", factory);
	});

	it("keeps chunks per entry and drops them with the entry", async () => {
		const factory = new IDBFactory();
		const store = await IndexedDbEntryStore.open("chunks", factory);
		const piece = (n: number) => ({ nonce: new Uint8Array(24), data: new Uint8Array([n]) });
		const one = new Uint8Array(16).fill(1);
		const two = new Uint8Array(16).fill(2);
		await store.putChunk(one, 0, piece(10));
		await store.putChunk(one, 1, piece(11));
		await store.put("a.pdf", { id: one, count: 2, size: 2, mtime: 1, ctime: 1 });
		expect(await store.getChunk(one, 1)).toEqual(piece(11));
		expect(await store.infos()).toEqual(new Map([["a.pdf", { size: 2, mtime: 1, ctime: 1, id: "01".repeat(16) }]]));

		// A new version: the old chunks go with the entry that replaces them.
		await store.putChunk(two, 0, piece(20));
		await store.put("a.pdf", { id: two, count: 1, size: 1, mtime: 2, ctime: 1 });
		expect(await store.getChunk(one, 0)).toBeUndefined();
		expect(await store.chunkIds()).toEqual(new Set(["02".repeat(16)]));

		await store.putChunk(one, 0, piece(30));
		await store.deleteChunks(one);
		await store.delete("a.pdf");
		expect(await store.chunkIds()).toEqual(new Set());
		expect((await store.infos()).size).toBe(0);
		store.close();
		await deleteDatabase("chunks", factory);
	});

	it("opens a store from before chunks and keeps its entries", async () => {
		const factory = new IDBFactory();
		const old = factory.open("v1", 1);
		old.onupgradeneeded = () => {
			old.result.createObjectStore("entries");
			old.result.createObjectStore("info");
		};
		await new Promise((resolve) => (old.onsuccess = resolve));
		const entry = { nonce: new Uint8Array(24), data: new Uint8Array([1]), size: 1, mtime: 2, ctime: 3 };
		const tx = old.result.transaction(["entries", "info"], "readwrite");
		tx.objectStore("entries").put(entry, "a.md");
		tx.objectStore("info").put({ size: 1, mtime: 2, ctime: 3 }, "a.md");
		await new Promise((resolve) => (tx.oncomplete = resolve));
		old.result.close();

		const store = await IndexedDbEntryStore.open("v1", factory);
		expect(await store.get("a.md")).toEqual(entry);
		expect(await store.chunkIds()).toEqual(new Set());
		store.close();
		await deleteDatabase("v1", factory);
	});
});
