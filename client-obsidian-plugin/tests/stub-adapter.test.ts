import { describe, expect, it } from "vitest";

import { sha256 } from "@noble/hashes/sha2.js";

import { hex } from "../src/crypto/bytes";
import { sealLocal } from "../src/crypto/local";
import { LockedError, MemoryEntryStore, replaceStubUrl, StubAdapter, type WrappedAdapter } from "../src/remote/stub-adapter";
import { isMissingContent } from "../src/sync/fs";
import { FakeDisk } from "./fake-disk";

const dec = new TextDecoder();
const KEY = new Uint8Array(32).fill(7);

function setup(chunkSize?: number) {
	const disk = new FakeDisk();
	const store = new MemoryEntryStore();
	const created: string[] = [];
	const revoked: string[] = [];
	const ready: string[] = [];
	const stub = new StubAdapter({
		isRemote: (p) => p.startsWith("R/"),
		store,
		chunkSize,
		onResource: (p) => ready.push(p),
		urls: {
			create: () => {
				created.push(`blob:${created.length}`);
				return created[created.length - 1]!;
			},
			revoke: (u) => revoked.push(u),
		},
	});
	const adapter = disk as WrappedAdapter;
	const uninstall = stub.install(adapter);
	stub.unlock(KEY);
	return { disk, store, stub, adapter, uninstall, created, revoked, ready };
}

function storedBytes(store: MemoryEntryStore): string {
	return [...store.chunks.values()].map((c) => dec.decode(c.data)).join("|");
}

describe("StubAdapter", () => {
	it("keeps remote-only content only in the store, as ciphertext, and leaves empty stubs", async () => {
		const { disk, store, adapter } = setup();
		await adapter.write("R/note.md", "secret plan", { mtime: 2000 });
		expect(disk.text("R/note.md")).toBe("");
		expect(disk.files.get("R/note.md")!.mtime).toBe(2000);
		expect(storedBytes(store)).not.toContain("secret");
		expect(await adapter.read("R/note.md")).toBe("secret plan");
		expect(await adapter.stat("R/note.md")).toMatchObject({ size: 11, mtime: 2000 });
	});

	it("passes other paths through", async () => {
		const { disk, store, adapter } = setup();
		await adapter.write("plain.md", "hello");
		expect(disk.text("plain.md")).toBe("hello");
		expect(store.entries.size).toBe(0);
	});

	it("converts and restores files on disk", async () => {
		const { disk, store, stub, adapter } = setup();
		disk.put("R/a.md", "alpha", 1234);
		expect(await stub.convert("R/a.md")).toBe(true);
		expect(disk.text("R/a.md")).toBe("");
		expect(await stub.convert("R/a.md")).toBe(false);
		expect(await adapter.read("R/a.md")).toBe("alpha");
		expect(await stub.restore("R/a.md")).toBe(true);
		expect(disk.text("R/a.md")).toBe("alpha");
		expect(disk.files.get("R/a.md")!.mtime).toBe(1234);
		expect(store.entries.size).toBe(0);
	});

	it("restores every file, even when Obsidian's modify events would convert them back", async () => {
		const { disk, store, stub, adapter } = setup();
		await adapter.write("R/a.md", "alpha");
		await adapter.write("R/b.md", "beta");
		// Obsidian's modify event for a restored file: the plugin converts files written outside the wrapper.
		const converts: Promise<boolean>[] = [];
		disk.onWrite = (path) => converts.push(stub.convert(path));
		expect(await stub.restoreAll()).toEqual([]);
		expect(await Promise.all(converts)).toEqual([false, false]);
		expect(disk.text("R/a.md")).toBe("alpha");
		expect(disk.text("R/b.md")).toBe("beta");
		expect(store.entries.size).toBe(0);
	});

	it("appends and processes through the store", async () => {
		const { disk, adapter } = setup();
		await adapter.write("R/a.md", "one");
		await adapter.append("R/a.md", " two");
		expect(await adapter.process("R/a.md", (s) => s.toUpperCase())).toBe("ONE TWO");
		expect(await adapter.read("R/a.md")).toBe("ONE TWO");
		expect(disk.text("R/a.md")).toBe("");
	});

	it("never reads an empty stub without its content as empty content", async () => {
		const { disk, store, stub, adapter } = setup();
		disk.put("R/lost.md", "");
		disk.put("R/new.md", "fresh");
		await expect(adapter.read("R/lost.md")).rejects.toSatisfy(isMissingContent);
		expect(await adapter.read("R/new.md")).toBe("fresh");
		// Only a full device's empty files are converted as empty notes.
		expect(await stub.convert("R/lost.md")).toBe(false);
		expect(store.entries.size).toBe(0);
		expect(await stub.convert("R/lost.md", true)).toBe(true);
		expect(await adapter.read("R/lost.md")).toBe("");
	});

	it("fails reads and writes while locked, and serves them again after unlock", async () => {
		const { stub, adapter } = setup();
		await adapter.write("R/a.md", "x");
		stub.lock();
		await expect(adapter.read("R/a.md")).rejects.toBeInstanceOf(LockedError);
		await expect(adapter.write("R/a.md", "y")).rejects.toBeInstanceOf(LockedError);
		stub.unlock(KEY);
		expect(await adapter.read("R/a.md")).toBe("x");
	});

	it("can't open the store with another key", async () => {
		const { stub, adapter } = setup();
		await adapter.write("R/a.md", "x");
		stub.unlock(new Uint8Array(32).fill(8));
		await expect(adapter.read("R/a.md")).rejects.toThrow();
	});

	it("renames files and folders within, into and out of the folder", async () => {
		const { disk, store, adapter } = setup();
		await adapter.write("R/a.md", "a");
		await adapter.rename("R/a.md", "R/b.md");
		expect(await adapter.read("R/b.md")).toBe("a");
		expect(await store.get("R/a.md")).toBeUndefined();

		disk.folders.add("R/sub");
		await adapter.write("R/sub/c.md", "c");
		await adapter.rename("R/sub", "R/moved");
		expect(await adapter.read("R/moved/c.md")).toBe("c");
		expect(disk.text("R/moved/c.md")).toBe("");

		await adapter.rename("R/b.md", "out.md");
		expect(disk.text("out.md")).toBe("a");
		expect(await store.get("R/b.md")).toBeUndefined();

		disk.put("in.md", "inbound marker");
		await adapter.rename("in.md", "R/in.md");
		expect(disk.text("R/in.md")).toBe("");
		expect(await adapter.read("R/in.md")).toBe("inbound marker");
		expect(storedBytes(store)).not.toContain("inbound");
	});

	it("copies into the store and out of it", async () => {
		const { disk, adapter } = setup();
		await adapter.write("R/a.md", "a");
		await adapter.copy("R/a.md", "R/b.md");
		await adapter.copy("R/a.md", "c.md");
		expect(await adapter.read("R/b.md")).toBe("a");
		expect(disk.text("R/b.md")).toBe("");
		expect(disk.text("c.md")).toBe("a");
	});

	it("drops store entries on remove, rmdir and trash", async () => {
		const { store, adapter } = setup();
		await adapter.write("R/a.md", "a");
		await adapter.write("R/f/b.md", "b");
		await adapter.write("R/g/c.md", "c");
		await adapter.remove("R/a.md");
		await adapter.rmdir("R/f", true);
		await adapter.trashLocal("R/g");
		expect(store.entries.size).toBe(0);
	});

	it("serves resources as blob URLs once decrypted, and drops them on write and lock", async () => {
		const { stub, adapter, created, revoked, ready } = setup();
		await adapter.writeBinary("R/pic.png", new Uint8Array([1, 2, 3]).buffer);
		expect(adapter.getResourcePath("R/pic.png")).toBe("app://disk/R/pic.png");
		await new Promise((r) => setTimeout(r, 0));
		expect(ready).toEqual(["R/pic.png"]);
		expect(adapter.getResourcePath("R/pic.png")).toBe("blob:0");
		await adapter.writeBinary("R/pic.png", new Uint8Array([4]).buffer);
		expect(revoked).toEqual(["blob:0"]);
		expect(await stub.warm("R/pic.png")).toBe(true);
		stub.lock();
		expect(revoked).toEqual(["blob:0", "blob:1"]);
		expect(created).toHaveLength(2);
		expect(adapter.getResourcePath("plain.png")).toBe("app://disk/plain.png");
	});

	it("renders a resource asked for while it is already being decrypted", async () => {
		const { stub, adapter, ready } = setup();
		await adapter.writeBinary("R/pic.png", new Uint8Array([1, 2, 3]).buffer);
		// The opened note's embeds are decrypted first, and the view renders meanwhile.
		const warming = stub.warm("R/pic.png");
		expect(adapter.getResourcePath("R/pic.png")).toBe("app://disk/R/pic.png");
		expect(await warming).toBe(true);
		expect(ready).toEqual(["R/pic.png"]);
		expect(adapter.getResourcePath("R/pic.png")).toBe("blob:0");
	});

	it("renders a resource asked for before the sync brought it, once it is written", async () => {
		const { adapter, disk, ready } = setup();
		disk.put("R/pic.png", "", 1000); // a stub whose content isn't downloaded yet
		expect(adapter.getResourcePath("R/pic.png")).toBe("app://disk/R/pic.png");
		await new Promise((r) => setTimeout(r, 0));
		expect(ready).toEqual([]);
		await adapter.writeBinary("R/pic.png", new Uint8Array([1, 2, 3]).buffer);
		await new Promise((r) => setTimeout(r, 0));
		expect(ready).toEqual(["R/pic.png"]);
		expect(adapter.getResourcePath("R/pic.png")).toBe("blob:0");
	});

	it("doesn't keep a resource decrypted before the file was written again", async () => {
		const { stub, adapter, created, revoked } = setup();
		await adapter.writeBinary("R/pic.png", new Uint8Array([1]).buffer);
		const warming = stub.warm("R/pic.png");
		await adapter.writeBinary("R/pic.png", new Uint8Array([2]).buffer);
		await warming;
		// Whichever finished first, no URL of the old content is still served.
		expect(created.filter((u) => !revoked.includes(u))).toEqual([]);
		expect(adapter.getResourcePath("R/pic.png")).toBe("app://disk/R/pic.png");
	});

	it("loads the index from the store and reports the real sizes", async () => {
		const { store, adapter } = setup();
		await adapter.write("R/a.md", "hello");
		const again = new StubAdapter({ isRemote: (p) => p.startsWith("R/"), store });
		const disk = new FakeDisk();
		disk.put("R/a.md", "", 3000);
		again.install(disk);
		await again.load();
		again.unlock(KEY);
		expect(again.paths()).toEqual(["R/a.md"]);
		expect(again.info("R/a.md")).toMatchObject({ size: 5 });
		expect(await disk.read("R/a.md")).toBe("hello");
	});

	it("puts the original methods back on uninstall", async () => {
		const { disk, adapter, uninstall } = setup();
		uninstall();
		await adapter.write("R/a.md", "plain");
		expect(disk.text("R/a.md")).toBe("plain");
	});
});

describe("StubAdapter chunks", () => {
	// Small chunks, so the tests stay fast: the size is an option.
	const CHUNK = 1000;
	const BIG = CHUNK * 2 + 123;

	function bytes(n: number, seed = 1): Uint8Array {
		const out = new Uint8Array(n);
		for (let i = 0; i < n; i++) out[i] = (i * 31 + seed) & 0xff;
		return out;
	}

	async function* pieces(data: Uint8Array, size = CHUNK): AsyncGenerator<Uint8Array> {
		for (let off = 0; off < data.length; off += size) yield data.subarray(off, off + size);
	}

	it("stores a large file as chunks and reads and hashes it back", async () => {
		const { store, stub, adapter } = setup(CHUNK);
		const data = bytes(BIG);
		await adapter.writeBinary("R/video.mp4", data.slice().buffer, { mtime: 5000 });
		expect(store.chunks.size).toBe(3);
		expect(new Uint8Array(await adapter.readBinary("R/video.mp4"))).toEqual(data);
		expect(await stub.hash("R/video.mp4")).toBe(hex(sha256(data)));
		expect((await adapter.stat("R/video.mp4"))!.size).toBe(BIG);

		// Replacing it drops the old chunks.
		await adapter.write("R/video.mp4", "small");
		expect(store.chunks.size).toBe(1);
		await adapter.remove("R/video.mp4");
		expect(store.chunks.size).toBe(0);
	});

	it("still reads an entry stored whole before chunks, and chunks it on the next write", async () => {
		const { store, stub, adapter, disk } = setup(CHUNK);
		const { nonce, data } = sealLocal(KEY, "local-content", "R/old.md", new TextEncoder().encode("old note"));
		await store.put("R/old.md", { nonce, data, size: 8, mtime: 1, ctime: 1 });
		disk.files.set("R/old.md", { data: new Uint8Array(0), mtime: 1, ctime: 1 });
		await stub.load();
		expect(await adapter.read("R/old.md")).toBe("old note");
		expect(await stub.hash("R/old.md")).toBe(hex(sha256(new TextEncoder().encode("old note"))));
		await adapter.write("R/old.md", "new note");
		expect("id" in store.entries.get("R/old.md")!).toBe(true);
		expect(await adapter.read("R/old.md")).toBe("new note");
	});

	it("commits a staged download with the next empty write, and keeps nothing of a failed one", async () => {
		const { store, stub, adapter, disk } = setup(CHUNK);
		const data = bytes(BIG, 9);
		await stub.stage("R/big.pdf", 3, pieces(data));
		expect(stub.info("R/big.pdf")).toBeUndefined();
		await adapter.writeBinary("R/big.pdf", new ArrayBuffer(0), { mtime: 7000, ctime: 6000 });
		expect(disk.files.get("R/big.pdf")!.data.length).toBe(0);
		expect(stub.info("R/big.pdf")).toEqual({ size: BIG, mtime: 7000, ctime: 6000 });
		expect(new Uint8Array(await adapter.readBinary("R/big.pdf"))).toEqual(data);

		async function* broken(): AsyncGenerator<Uint8Array> {
			yield data.subarray(0, 10);
			throw new Error("hash does not match");
		}
		await expect(stub.stage("R/bad.pdf", 2, broken())).rejects.toThrow("hash does not match");
		await expect(stub.stage("R/short.pdf", 3, pieces(data.subarray(0, 10)))).rejects.toThrow("Fewer chunks");
		expect(store.chunks.size).toBe(3);
		await stub.stage("R/never.pdf", 1, pieces(data.subarray(0, 10)));
		await stub.unstage("R/never.pdf");
		expect(store.chunks.size).toBe(3);
	});

	it("drops the chunks of writes that never got their entry, at load", async () => {
		const { store, stub, adapter } = setup(CHUNK);
		await adapter.write("R/kept.md", "kept");
		await stub.stage("R/crashed.pdf", 1, pieces(bytes(10)));
		expect(store.chunks.size).toBe(2);
		await stub.load();
		expect(store.chunks.size).toBe(1);
		expect(await adapter.read("R/kept.md")).toBe("kept");
	});

	it("treats a lost chunk as missing content, not as the file", async () => {
		const { store, adapter } = setup(CHUNK);
		await adapter.writeBinary("R/video.mp4", bytes(BIG).buffer as ArrayBuffer);
		store.chunks.delete([...store.chunks.keys()][1]!);
		const err = await adapter.readBinary("R/video.mp4").catch((e: unknown) => e);
		expect(isMissingContent(err)).toBe(true);
	});

	it("builds a large resource's Blob from its chunks", async () => {
		const { stub, adapter } = setup(CHUNK);
		await adapter.writeBinary("R/video.mp4", bytes(BIG).buffer as ArrayBuffer);
		expect(await stub.warm("R/video.mp4")).toBe(true);
	});
});

describe("replaceStubUrl", () => {
	function element(src: string | null) {
		const attrs = new Map<string, string>();
		if (src !== null) attrs.set("src", src);
		return { getAttribute: (n: string) => attrs.get(n) ?? null, setAttribute: (n: string, v: string) => void attrs.set(n, v), attrs };
	}

	it("points elements still showing the stub's URL, with Obsidian's ?mtime, at the decrypted one", () => {
		const shown = element("app://disk/R/pic.png?1700000000000");
		const other = element("app://disk/R/other.png?1");
		const none = element(null);
		expect(replaceStubUrl([shown, other, none], "app://disk/R/pic.png", "blob:7")).toBe(1);
		expect(shown.attrs.get("src")).toBe("blob:7");
		expect(other.attrs.get("src")).toBe("app://disk/R/other.png?1");
	});
});
