/**
 * The config folders, read and written through `app.vault.adapter` (docs/PLAN.md, Sync
 * Scope): Obsidian doesn't index hidden folders, so the Vault API can't see them.
 */
import { isConfigFolder } from "./filter";
import type { FileStat, ListedFile, VaultFs } from "./fs";

/** The part of Obsidian's `DataAdapter` used here, so tests can fake it. */
export interface Adapter {
	list(path: string): Promise<{ files: string[]; folders: string[] }>;
	stat(path: string): Promise<{ type: "file" | "folder"; mtime: number; ctime: number; size: number } | null>;
	exists(path: string): Promise<boolean>;
	readBinary(path: string): Promise<ArrayBuffer>;
	writeBinary(path: string, data: ArrayBuffer, options?: { mtime?: number; ctime?: number }): Promise<void>;
	mkdir(path: string): Promise<void>;
	remove(path: string): Promise<void>;
}

export interface AdapterFsOptions {
	/** `app.vault.configDir`. Listed even if the vault root can't be. */
	configDir: string;
	/** Folders a scan doesn't descend into, such as `node_modules`. */
	skipsFolder?: (folder: string) => boolean;
}

function buffer(data: Uint8Array): ArrayBuffer {
	return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

/** Adapters may return paths with a leading `/` when listing the root. */
function clean(path: string): string {
	return path.replace(/^\/+/, "");
}

export class AdapterFs implements VaultFs {
	constructor(
		private readonly adapter: Adapter,
		private readonly opts: AdapterFsOptions,
	) {}

	/** Every file in every config folder at the vault root. */
	async list(): Promise<ListedFile[]> {
		const out: ListedFile[] = [];
		for (const folder of await this.configFolders()) await this.walk(folder, out);
		return out;
	}

	async stat(path: string): Promise<FileStat | null> {
		const s = await this.adapter.stat(path);
		return s && s.type === "file" ? { mtime: s.mtime, ctime: s.ctime, size: s.size } : null;
	}

	async read(path: string): Promise<Uint8Array> {
		return new Uint8Array(await this.adapter.readBinary(path));
	}

	async write(path: string, data: Uint8Array, times: { mtime: number; ctime?: number }): Promise<void> {
		await this.ensureFolder(path.slice(0, Math.max(0, path.lastIndexOf("/"))));
		const options = { mtime: times.mtime, ...(times.ctime !== undefined ? { ctime: times.ctime } : {}) };
		await this.adapter.writeBinary(path, buffer(data), options);
	}

	async remove(path: string): Promise<void> {
		if (await this.stat(path)) await this.adapter.remove(path);
	}

	private async configFolders(): Promise<string[]> {
		const folders = new Set<string>();
		try {
			for (const f of (await this.adapter.list("/")).folders) {
				const name = clean(f);
				if (isConfigFolder(name, this.opts.configDir)) folders.add(name);
			}
		} catch {
			// Some adapters can't list the root: sync the active config folder only.
		}
		if (await this.adapter.exists(this.opts.configDir)) folders.add(this.opts.configDir);
		return [...folders].sort();
	}

	private async walk(folder: string, out: ListedFile[]): Promise<void> {
		if (this.opts.skipsFolder?.(folder)) return;
		const listed = await this.adapter.list(folder);
		const stats = await Promise.all(listed.files.map(async (f) => [clean(f), await this.adapter.stat(clean(f))] as const));
		for (const [path, s] of stats) {
			if (s?.type === "file") out.push({ path, mtime: s.mtime, ctime: s.ctime, size: s.size });
		}
		for (const sub of listed.folders) await this.walk(clean(sub), out);
	}

	private async ensureFolder(folder: string): Promise<void> {
		if (folder === "" || (await this.adapter.exists(folder))) return;
		await this.ensureFolder(folder.slice(0, Math.max(0, folder.lastIndexOf("/"))));
		await this.adapter.mkdir(folder);
	}
}

/** True for paths under a hidden folder, which only the adapter can reach. */
export function isHiddenPath(path: string): boolean {
	return path.split("/").some((s) => s.startsWith("."));
}

/** Notes and attachments through one `VaultFs`, hidden paths through another. */
export class SplitFs implements VaultFs {
	constructor(
		private readonly visible: VaultFs,
		private readonly hidden: VaultFs,
	) {}

	private fs(path: string): VaultFs {
		return isHiddenPath(path) ? this.hidden : this.visible;
	}

	async list(): Promise<ListedFile[]> {
		const [visible, hidden] = await Promise.all([this.visible.list(), this.hidden.list()]);
		return [...visible.filter((f) => !isHiddenPath(f.path)), ...hidden];
	}
	stat(path: string): Promise<FileStat | null> {
		return this.fs(path).stat(path);
	}
	read(path: string): Promise<Uint8Array> {
		return this.fs(path).read(path);
	}
	write(path: string, data: Uint8Array, times: { mtime: number; ctime?: number }): Promise<void> {
		return this.fs(path).write(path, data, times);
	}
	remove(path: string): Promise<void> {
		return this.fs(path).remove(path);
	}
}
