/**
 * `VaultFs` over the Vault API, for the notes and attachments Obsidian indexes. The hidden
 * config folders go through `AdapterFs` instead.
 */
import { normalizePath, TFile, TFolder, type App } from "obsidian";

import type { FileStat, ListedFile, VaultFs } from "../sync/fs";

function buffer(data: Uint8Array): ArrayBuffer {
	return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

export class ObsidianFs implements VaultFs {
	constructor(private readonly app: App) {}

	private file(path: string): TFile | null {
		return this.app.vault.getFileByPath(normalizePath(path));
	}

	async list(): Promise<ListedFile[]> {
		return this.app.vault.getFiles().map((f) => ({ path: f.path, mtime: f.stat.mtime, ctime: f.stat.ctime, size: f.stat.size }));
	}

	async stat(path: string): Promise<FileStat | null> {
		const file = this.file(path);
		return file ? { mtime: file.stat.mtime, ctime: file.stat.ctime, size: file.stat.size } : null;
	}

	async read(path: string): Promise<Uint8Array> {
		const file = this.file(path);
		if (!file) throw new Error("The file no longer exists.");
		return new Uint8Array(await this.app.vault.readBinary(file));
	}

	async write(path: string, data: Uint8Array, times: { mtime: number; ctime?: number }): Promise<void> {
		const options = { mtime: times.mtime, ...(times.ctime !== undefined ? { ctime: times.ctime } : {}) };
		const file = this.file(path);
		if (file) {
			await this.app.vault.modifyBinary(file, buffer(data), options);
			return;
		}
		await this.ensureFolder(path.slice(0, Math.max(0, path.lastIndexOf("/"))));
		await this.app.vault.createBinary(normalizePath(path), buffer(data), options);
	}

	async remove(path: string): Promise<void> {
		const file = this.file(path);
		// Into the trash the user chose in Obsidian's settings, so a deletion can be undone.
		if (file) await this.app.fileManager.trashFile(file);
	}

	private async ensureFolder(folder: string): Promise<void> {
		if (folder === "") return;
		const existing = this.app.vault.getAbstractFileByPath(normalizePath(folder));
		if (existing instanceof TFolder) return;
		await this.ensureFolder(folder.slice(0, Math.max(0, folder.lastIndexOf("/"))));
		await this.app.vault.createFolder(normalizePath(folder));
	}
}
