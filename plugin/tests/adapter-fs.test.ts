import { describe, expect, it } from "vitest";

import { AdapterFs, SplitFs, type Adapter } from "../src/sync/adapter-fs";
import { pathFilter } from "../src/sync/filter";
import { MemoryFs } from "../src/sync/fs";

/** A file tree like `DataAdapter` sees it: folders exist on their own, the root lists with `/`. */
class FakeAdapter implements Adapter {
	readonly files = new Map<string, { data: Uint8Array; mtime: number; ctime: number }>();
	readonly folders = new Set<string>();
	rootListing = true;

	put(path: string, text: string, mtime = 1000): void {
		const parts = path.split("/");
		for (let i = 1; i < parts.length; i++) this.folders.add(parts.slice(0, i).join("/"));
		this.files.set(path, { data: new TextEncoder().encode(text), mtime, ctime: mtime });
	}

	private children(folder: string) {
		const prefix = folder === "/" ? "" : `${folder}/`;
		const direct = (p: string) => p.startsWith(prefix) && !p.slice(prefix.length).includes("/");
		return {
			files: [...this.files.keys()].filter(direct).map((p) => (folder === "/" ? `/${p}` : p)),
			folders: [...this.folders].filter(direct).map((p) => (folder === "/" ? `/${p}` : p)),
		};
	}

	async list(path: string) {
		if (path === "/" && !this.rootListing) throw new Error("can't list the root");
		return this.children(path);
	}
	async stat(path: string) {
		const f = this.files.get(path);
		if (f) return { type: "file" as const, mtime: f.mtime, ctime: f.ctime, size: f.data.length };
		return this.folders.has(path) ? { type: "folder" as const, mtime: 0, ctime: 0, size: 0 } : null;
	}
	async exists(path: string) {
		return this.files.has(path) || this.folders.has(path);
	}
	async readBinary(path: string) {
		const f = this.files.get(path)!;
		return f.data.buffer.slice(0) as ArrayBuffer;
	}
	async writeBinary(path: string, data: ArrayBuffer, options?: { mtime?: number; ctime?: number }) {
		const parent = path.slice(0, Math.max(0, path.lastIndexOf("/")));
		if (parent && !this.folders.has(parent)) throw new Error(`no folder ${parent}`);
		const mtime = options?.mtime ?? 1;
		this.files.set(path, { data: new Uint8Array(data), mtime, ctime: options?.ctime ?? mtime });
	}
	async mkdir(path: string) {
		const parent = path.slice(0, Math.max(0, path.lastIndexOf("/")));
		if (parent && !this.folders.has(parent)) throw new Error(`no folder ${parent}`);
		this.folders.add(path);
	}
	async remove(path: string) {
		this.files.delete(path);
	}
}

function vault(): FakeAdapter {
	const a = new FakeAdapter();
	a.put("Note.md", "note");
	a.put(".obsidian/app.json", "{}", 5000);
	a.put(".obsidian/plugins/dataview/main.js", "js");
	a.put(".obsidian/plugins/dataview/node_modules/x.js", "x");
	a.put(".obsidian/plugins/vault-syncryption/data.json", "{}");
	a.put(".obsidian-mobile/hotkeys.json", "[]");
	a.put(".git/HEAD", "ref");
	return a;
}

describe("AdapterFs", () => {
	it("lists every config folder and skips excluded folders", async () => {
		const include = pathFilter({ configDir: ".obsidian" });
		const fs = new AdapterFs(vault(), { configDir: ".obsidian", skipsFolder: include.skipsFolder });
		const files = await fs.list();
		expect(files.map((f) => f.path).sort()).toEqual([
			".obsidian-mobile/hotkeys.json",
			".obsidian/app.json",
			".obsidian/plugins/dataview/main.js",
		]);
		expect(files.find((f) => f.path === ".obsidian/app.json")).toEqual({
			path: ".obsidian/app.json",
			mtime: 5000,
			ctime: 5000,
			size: 2,
		});
	});

	it("falls back to the active config folder if the root can't be listed", async () => {
		const adapter = vault();
		adapter.rootListing = false;
		const fs = new AdapterFs(adapter, { configDir: ".obsidian" });
		const paths = (await fs.list()).map((f) => f.path);
		expect(paths).toContain(".obsidian/app.json");
		expect(paths.some((p) => p.startsWith(".obsidian-mobile/"))).toBe(false);
	});

	it("writes with times, creating folders, and removes files", async () => {
		const adapter = vault();
		const fs = new AdapterFs(adapter, { configDir: ".obsidian" });
		await fs.write(".obsidian/themes/Minimal/theme.css", new TextEncoder().encode("body{}"), { mtime: 7000, ctime: 6000 });
		expect(await fs.stat(".obsidian/themes/Minimal/theme.css")).toEqual({ mtime: 7000, ctime: 6000, size: 6 });
		expect(new TextDecoder().decode(await fs.read(".obsidian/themes/Minimal/theme.css"))).toBe("body{}");
		expect(await fs.stat(".obsidian/themes")).toBeNull();
		await fs.remove(".obsidian/app.json");
		await fs.remove(".obsidian/missing.json");
		expect(adapter.files.has(".obsidian/app.json")).toBe(false);
	});
});

describe("SplitFs", () => {
	it("sends hidden paths to the adapter and the rest to the Vault API", async () => {
		const visible = new MemoryFs();
		visible.set("Note.md", "note");
		const adapter = vault();
		const fs = new SplitFs(visible, new AdapterFs(adapter, { configDir: ".obsidian" }));
		expect((await fs.list()).map((f) => f.path)).toContain("Note.md");
		await fs.write(".obsidian/hotkeys.json", new TextEncoder().encode("[]"), { mtime: 1 });
		await fs.write("New.md", new TextEncoder().encode("new"), { mtime: 1 });
		expect(adapter.files.has(".obsidian/hotkeys.json")).toBe(true);
		expect(adapter.files.has("New.md")).toBe(false);
		expect(visible.text("New.md")).toBe("new");
	});
});
