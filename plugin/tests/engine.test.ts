import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { ApiError } from "../src/api/http";
import { MemoryStore } from "../src/store/state";
import { CURSOR, DEFERRED, FAILED } from "../src/sync/engine";
import { MemoryFs } from "../src/sync/fs";
import { backendDataDir, noBackend } from "./harness";
import { engineFor, twoDevices, type Device } from "./sync-fixture";

async function syncAll(...devices: Device[]): Promise<void> {
	for (const d of devices) await d.engine.sync();
	for (const d of devices) await d.engine.sync();
}

function texts(fs: MemoryFs): Record<string, string> {
	return Object.fromEntries([...fs.files.keys()].sort().map((p) => [p, fs.text(p)!]));
}

function allFiles(dir: string): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
		e.isDirectory() ? allFiles(join(dir, e.name)) : [join(dir, e.name)],
	);
}

describe.skipIf(noBackend)("SyncEngine", () => {
	it("copies new files, edits and deletions to the other device", async () => {
		const [a, b] = await twoDevices();
		a.fs.set("Note.md", "hello\n");
		a.fs.set("Folder/Deep/photo.png", new Uint8Array([0, 1, 2, 255]));
		const first = await a.engine.sync();
		expect(first.pushed).toBe(2);
		const pulled = await b.engine.sync();
		expect(pulled.pulled).toBe(2);
		expect(b.fs.text("Note.md")).toBe("hello\n");
		expect([...b.fs.files.get("Folder/Deep/photo.png")!.data]).toEqual([0, 1, 2, 255]);
		// The remote mtime is kept.
		expect(b.fs.files.get("Note.md")!.mtime).toBe(a.fs.files.get("Note.md")!.mtime);

		b.fs.set("Note.md", "hello again\n");
		await syncAll(b, a);
		expect(a.fs.text("Note.md")).toBe("hello again\n");

		a.fs.delete("Note.md");
		await syncAll(a, b);
		expect(b.fs.files.has("Note.md")).toBe(false);
		expect(texts(a.fs)).toEqual(texts(b.fs));
		expect(await a.engine.fileCount()).toBe(1);
		expect(await b.engine.fileCount()).toBe(1);
		expect(a.warnings).toEqual([]);
		expect(b.warnings).toEqual([]);
	});

	it("doesn't push files that were only touched", async () => {
		const [a] = await twoDevices();
		a.fs.set("a.md", "same");
		await a.engine.sync();
		a.fs.set("a.md", "same");
		expect((await a.engine.sync()).pushed).toBe(0);
		expect((await a.store.files()).get("a.md")!.mtime).toBe(a.fs.files.get("a.md")!.mtime);
	});

	it("merges edits to different lines of the same note", async () => {
		const [a, b] = await twoDevices();
		a.fs.set("Plan.md", "one\ntwo\nthree\n");
		await syncAll(a, b);
		a.fs.set("Plan.md", "ONE\ntwo\nthree\n");
		b.fs.set("Plan.md", "one\ntwo\nTHREE\n");
		await a.engine.sync();
		const report = await b.engine.sync();
		expect(report.merged).toBe(1);
		expect(report.conflicts).toEqual([]);
		await a.engine.sync();
		expect(a.fs.text("Plan.md")).toBe("ONE\ntwo\nTHREE\n");
		expect(b.fs.text("Plan.md")).toBe("ONE\ntwo\nTHREE\n");
	});

	it("keeps both versions when the edits conflict", async () => {
		const [a, b] = await twoDevices();
		a.fs.set("Plan.md", "draft\n");
		await syncAll(a, b);
		a.fs.set("Plan.md", "laptop version\n");
		b.fs.set("Plan.md", "phone version\n");
		await a.engine.sync();
		const report = await b.engine.sync();
		expect(report.conflicts).toHaveLength(1);
		const copy = report.conflicts[0]!;
		expect(copy).toMatch(/^Plan \(conflict Phone \d{4}-\d{2}-\d{2} \d{4}\)\.md$/);
		await a.engine.sync();
		for (const d of [a, b]) {
			expect(d.fs.text("Plan.md")).toBe("laptop version\n");
			expect(d.fs.text(copy)).toBe("phone version\n");
		}
	});

	it("keeps a binary file from the server and the local one as a copy", async () => {
		const [a, b] = await twoDevices();
		a.fs.set("img.png", new Uint8Array([1]));
		await syncAll(a, b);
		a.fs.set("img.png", new Uint8Array([2]));
		b.fs.set("img.png", new Uint8Array([3]));
		await a.engine.sync();
		const report = await b.engine.sync();
		expect(report.conflicts).toHaveLength(1);
		expect([...b.fs.files.get("img.png")!.data]).toEqual([2]);
		expect([...b.fs.files.get(report.conflicts[0]!)!.data]).toEqual([3]);
	});

	it("keeps an edit over a deletion from the other device", async () => {
		const [a, b] = await twoDevices();
		a.fs.set("a.md", "v1\n");
		await syncAll(a, b);
		a.fs.delete("a.md");
		b.fs.set("a.md", "v2\n");
		await a.engine.sync();
		await syncAll(b, a);
		expect(a.fs.text("a.md")).toBe("v2\n");
		expect(b.fs.text("a.md")).toBe("v2\n");

		// And the other way round: deleted here, edited there.
		b.fs.delete("a.md");
		a.fs.set("a.md", "v3\n");
		await a.engine.sync();
		await syncAll(b, a);
		expect(a.fs.text("a.md")).toBe("v3\n");
		expect(b.fs.text("a.md")).toBe("v3\n");
	});

	it("adopts the same file created on both devices without a conflict", async () => {
		const [a, b] = await twoDevices();
		a.fs.set("same.md", "identical\n");
		b.fs.set("same.md", "identical\n");
		await a.engine.sync();
		const report = await b.engine.sync();
		expect(report.conflicts).toEqual([]);
		expect(report.pushed).toBe(0);
		expect([...b.fs.files.keys()]).toEqual(["same.md"]);
	});

	it("converges after many offline edits on both sides", async () => {
		const [a, b] = await twoDevices();
		for (let i = 0; i < 10; i++) a.fs.set(`a/${i}.md`, `a ${i}\n`);
		for (let i = 0; i < 10; i++) b.fs.set(`b/${i}.md`, `b ${i}\n`);
		a.fs.set("shared.md", "x\ny\nz\n");
		await syncAll(a, b);
		a.fs.set("shared.md", "X\ny\nz\n");
		b.fs.set("shared.md", "x\ny\nZ\n");
		a.fs.delete("b/3.md");
		b.fs.set("a/5.md", "edited on b\n");
		await syncAll(a, b, a);
		expect(texts(a.fs)).toEqual(texts(b.fs));
		expect(a.fs.text("shared.md")).toBe("X\ny\nZ\n");
		expect(a.fs.files.has("b/3.md")).toBe(false);
		expect(a.fs.text("a/5.md")).toBe("edited on b\n");
		expect(await a.store.outbox()).toEqual([]);
		expect(await b.store.outbox()).toEqual([]);
	});

	it("skips excluded paths", async () => {
		const [a, b] = await twoDevices();
		a.fs.set(".obsidian/workspace.json", "{}");
		a.fs.set(".trash/old.md", "old");
		a.fs.set("a/.hidden.md", "hidden");
		a.fs.set("kept.md", "kept");
		await syncAll(a, b);
		expect([...b.fs.files.keys()]).toEqual(["kept.md"]);
	});

	it("pushes changes noted from vault events", async () => {
		const [a, b] = await twoDevices();
		a.fs.set("a.md", "1");
		await a.engine.noteChange("a.md");
		await a.engine.noteChange(".obsidian/workspace.json");
		expect((await a.store.outbox()).map((e) => e.path)).toEqual(["a.md"]);
		await a.engine.push();
		await b.engine.pull();
		expect(b.fs.text("a.md")).toBe("1");
	});

	it("runs one sync at a time and runs again for calls made meanwhile", async () => {
		const [a] = await twoDevices();
		a.fs.set("a.md", "1");
		const first = a.engine.sync();
		a.fs.set("b.md", "2");
		const second = a.engine.sync();
		expect(second).toBe(first);
		expect((await first).pushed).toBe(2);
	});

	it("starts over from an empty state on a new device without duplicates", async () => {
		const [a, b] = await twoDevices();
		a.fs.set("a.md", "1");
		await syncAll(a, b);
		// B loses its state (reinstall): the scan finds a.md as new, equal to the server's.
		const fresh = new MemoryStore();
		const session = Object.create(b.session, { store: { value: fresh } });
		const engine = engineFor(session, b.fs, "Phone", b.warnings);
		const report = await engine.sync();
		expect(report.pushed).toBe(0);
		expect(report.conflicts).toEqual([]);
		expect(await fresh.getMeta(CURSOR)).toBeGreaterThan(0);
	});

	it("stores only ciphertext on the server", async () => {
		const [a] = await twoDevices();
		const marker = "plaintext-marker-7f3a9c";
		a.fs.set(`Secret ${marker}/${marker}.md`, `${marker}\n`.repeat(100));
		await a.engine.sync();
		const files = allFiles(backendDataDir);
		expect(files.length).toBeGreaterThan(0);
		for (const file of files) expect(readFileSync(file).includes(marker), file).toBe(false);
	});
	it("brings the config folder to a new device, turning plugins on last", async () => {
		const [a, b] = await twoDevices();
		a.fs.set(".obsidian/community-plugins.json", '["dataview"]');
		a.fs.set(".obsidian/plugins/dataview/main.js", "plugin code");
		a.fs.set(".obsidian/plugins/dataview/manifest.json", '{"id":"dataview"}');
		a.fs.set(".obsidian/themes/Minimal/theme.css", "body {}");
		a.fs.set(".obsidian/hotkeys.json", '{"editor:toggle-bold":[]}');
		a.fs.set(".obsidian/app.json", '{"vimMode":true}');
		a.fs.set(".obsidian/workspace.json", '{"laptop":true}');
		a.fs.set(".obsidian/plugins/vault-syncryption/data.json", '{"username":"laptop"}');
		a.fs.set(".obsidian-phone/app.json", '{"phone":true}');
		expect((await a.engine.sync()).configChanged).toBe(false);

		// The new device starts with Obsidian's defaults and its own workspace.
		b.fs.set(".obsidian/app.json", "{}");
		b.fs.set(".obsidian/workspace.json", '{"phone":true}');
		const written: string[] = [];
		const write = b.fs.write.bind(b.fs);
		b.fs.write = (path, data, times) => {
			written.push(path);
			return write(path, data, times);
		};
		const report = await b.engine.sync();
		expect(report.configChanged).toBe(true);
		expect(report.conflicts).toEqual([]);
		expect(written.at(-1)).toBe(".obsidian/community-plugins.json");
		expect(written).toContain(".obsidian/plugins/dataview/main.js");
		expect(b.fs.text(".obsidian/app.json")).toBe('{"vimMode":true}');
		expect(b.fs.text(".obsidian/hotkeys.json")).toBe('{"editor:toggle-bold":[]}');
		expect(b.fs.text(".obsidian/themes/Minimal/theme.css")).toBe("body {}");
		expect(b.fs.text(".obsidian-phone/app.json")).toBe('{"phone":true}');
		expect(b.fs.text(".obsidian/workspace.json")).toBe('{"phone":true}');
		expect(b.fs.files.has(".obsidian/plugins/vault-syncryption/data.json")).toBe(false);
		expect(await b.store.getMeta(DEFERRED)).toEqual([]);

		// Later config edits merge like notes, and notes don't ask for a reload.
		b.fs.set("Note.md", "hi");
		a.fs.set(".obsidian/app.json", '{"vimMode":false}');
		await a.engine.sync();
		const next = await b.engine.sync();
		expect(next.configChanged).toBe(true);
		expect(b.fs.text(".obsidian/app.json")).toBe('{"vimMode":false}');
		expect((await a.engine.sync()).configChanged).toBe(false);
		expect(a.fs.text("Note.md")).toBe("hi");
	});

	it("keeps a held-back revision it couldn't write", async () => {
		const [a, b] = await twoDevices();
		a.fs.set(".obsidian/community-plugins.json", '["dataview"]');
		a.fs.set(".obsidian/plugins/dataview/main.js", "plugin code");
		await a.engine.sync();
		const write = b.fs.write.bind(b.fs);
		b.fs.write = (path, data, times) => {
			if (path.endsWith("community-plugins.json")) throw new Error("disk full");
			return write(path, data, times);
		};
		await b.engine.sync();
		expect(b.warnings[0]).toContain("disk full");
		expect(await b.store.getMeta(DEFERRED)).toEqual([]);
		expect(await b.store.getMeta<unknown[]>(FAILED)).toHaveLength(1);
		expect(b.fs.text(".obsidian/plugins/dataview/main.js")).toBe("plugin code");
		b.fs.write = write;
		await b.engine.sync();
		expect(b.fs.text(".obsidian/community-plugins.json")).toBe('["dataview"]');
		expect(await b.store.getMeta(FAILED)).toEqual([]);
	});

	it("lists a file's history and restores an old version on every device", async () => {
		const [a, b] = await twoDevices();
		a.fs.set("Note.md", "first\n");
		await syncAll(a, b);
		b.fs.set("Note.md", "second\n");
		await syncAll(b, a);
		a.fs.set("Note.md", "third, not synced yet\n");

		const history = await a.engine.history("Note.md");
		expect(history.next).toBeUndefined();
		expect(history.rejected).toBe(0);
		expect(history.entries.map((e) => [e.deleted, e.size, e.device])).toEqual([
			[false, 7, b.session.deviceId],
			[false, 6, a.session.deviceId],
		]);
		const oldest = history.entries[1]!;
		expect(new TextDecoder().decode((await a.engine.readRevision("Note.md", oldest.rev))!)).toBe("first\n");

		await a.engine.restore("Note.md", oldest.rev);
		expect(a.fs.text("Note.md")).toBe("first\n");
		await b.engine.sync();
		expect(b.fs.text("Note.md")).toBe("first\n");
		// The local edit was pushed before the restore, so it is in the history too.
		const after = await b.engine.history("Note.md");
		expect(after.entries).toHaveLength(4);
		expect(new TextDecoder().decode((await b.engine.readRevision("Note.md", after.entries[1]!.rev))!)).toBe(
			"third, not synced yet\n",
		);
	});

	it("pages through a long history", async () => {
		const [a] = await twoDevices();
		for (let i = 0; i < 53; i++) {
			a.fs.set("Busy.md", `version ${i}\n`);
			await a.engine.sync();
		}
		const first = await a.engine.history("Busy.md");
		expect(first.entries).toHaveLength(50);
		expect(first.next).toBe(first.entries.at(-1)!.rev);
		const second = await a.engine.history("Busy.md", first.next);
		expect(second.entries).toHaveLength(3);
		expect(second.next).toBeUndefined();
		const oldest = second.entries.at(-1)!;
		expect(new TextDecoder().decode((await a.engine.readRevision("Busy.md", oldest.rev))!)).toBe("version 0\n");
	});

	it("restores a deleted file", async () => {
		const [a, b] = await twoDevices();
		a.fs.set("Gone.md", "keep me");
		a.fs.set("Folder/photo.png", new Uint8Array([1, 2, 3]));
		await syncAll(a, b);
		a.fs.delete("Gone.md");
		a.fs.delete("Folder/photo.png");
		await syncAll(a, b);
		expect(await b.engine.deletedPaths()).toEqual(["Folder/photo.png", "Gone.md"]);

		const history = await b.engine.history("Folder/photo.png");
		expect(history.entries[0]!.deleted).toBe(true);
		expect(await b.engine.readRevision("Folder/photo.png", history.entries[0]!.rev)).toBeNull();
		await expect(b.engine.restore("Folder/photo.png", history.entries[0]!.rev)).rejects.toThrow("deletion");
		await b.engine.restore("Folder/photo.png", history.entries[1]!.rev);
		await a.engine.sync();
		expect([...a.fs.files.get("Folder/photo.png")!.data]).toEqual([1, 2, 3]);
		expect(await a.engine.deletedPaths()).toEqual(["Gone.md"]);
	});

	it("leaves out revisions that fail their integrity check", async () => {
		const [a] = await twoDevices();
		a.fs.set("Note.md", "one");
		await a.engine.sync();
		a.fs.set("Note.md", "two");
		await a.engine.sync();
		const revisions = a.session.api.revisions.bind(a.session.api);
		a.session.api.revisions = async (...args) => {
			const page = await revisions(...args);
			page.revisions[1]!.meta = page.revisions[0]!.meta.slice(0, -4) + "AAAA";
			return page;
		};
		const history = await a.engine.history("Note.md");
		expect(history.entries).toHaveLength(1);
		expect(history.rejected).toBe(1);
	});
	it("applies the head when a pulled revision was pruned on the server", async () => {
		const [a, b] = await twoDevices();
		a.fs.set("Note.md", "one");
		await a.engine.sync();
		a.fs.set("Note.md", "two");
		await a.engine.sync();
		// The first revision's blob is gone (pruned) by the time b downloads it.
		const getBlob = b.session.api.getBlob.bind(b.session.api);
		let pruned = 0;
		b.session.api.getBlob = async (...args) => {
			if (pruned++ === 0) throw new ApiError(404, "not_found", "Not found.");
			return getBlob(...args);
		};
		await b.engine.sync();
		expect(pruned).toBeGreaterThan(1);
		expect(b.fs.text("Note.md")).toBe("two");
		expect(b.warnings).toEqual([]);
		expect(await b.store.getMeta(FAILED)).toEqual([]);

		const old = (await a.engine.history("Note.md")).entries[1]!.rev;
		a.session.api.revision = async () => {
			throw new ApiError(404, "not_found", "Not found.");
		};
		await expect(a.engine.readRevision("Note.md", old)).rejects.toThrow("This version is no longer kept on the server.");
		await expect(a.engine.restore("Note.md", old)).rejects.toThrow("no longer kept");
	});
	it("keeps going when a remote change can't be written, and writes it later", async () => {
		const [a, b] = await twoDevices();
		const write = b.fs.write.bind(b.fs);
		let refuse = true;
		b.fs.write = async (path, data, times) => {
			if (refuse && path === "Bad.md") throw new Error("A file with this name already exists.");
			return write(path, data, times);
		};
		a.fs.set("Bad.md", "bad\n");
		a.fs.set("Good.md", "good\n");
		await a.engine.sync();
		await b.engine.sync();
		expect(texts(b.fs)).toEqual({ "Good.md": "good\n" });
		expect(b.warnings).toHaveLength(1);
		expect(await b.store.getMeta(FAILED)).toHaveLength(1);

		await b.engine.sync();
		expect(b.warnings).toHaveLength(1); // warned once
		refuse = false;
		await b.engine.sync();
		expect(texts(b.fs)).toEqual({ "Bad.md": "bad\n", "Good.md": "good\n" });
		expect(await b.store.getMeta(FAILED)).toEqual([]);
	});
});
