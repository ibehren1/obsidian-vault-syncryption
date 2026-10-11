import type { WrappedAdapter } from "../src/remote/stub-adapter";

const enc = new TextEncoder();
const dec = new TextDecoder();

/** A disk like `DataAdapter` sees it, with only the methods the wrapper replaces. */
export class FakeDisk implements WrappedAdapter {
	readonly files = new Map<string, { data: Uint8Array; mtime: number; ctime: number }>();
	readonly folders = new Set<string>();
	/** Called after every write, like Obsidian's `modify` event. */
	onWrite?: (path: string) => void;

	put(path: string, text: string, mtime = 1000): void {
		this.files.set(path, { data: enc.encode(text), mtime, ctime: mtime });
	}
	text(path: string): string | undefined {
		const f = this.files.get(path);
		return f && dec.decode(f.data);
	}

	async read(path: string) {
		return dec.decode(new Uint8Array(await this.readBinary(path)));
	}
	async readBinary(path: string) {
		const f = this.files.get(path);
		if (!f) throw new Error(`ENOENT ${path}`);
		return f.data.slice().buffer;
	}
	async write(path: string, data: string, options?: { mtime?: number; ctime?: number }) {
		await this.writeBinary(path, enc.encode(data).buffer, options);
	}
	async writeBinary(path: string, data: ArrayBuffer, options?: { mtime?: number; ctime?: number }) {
		const mtime = options?.mtime ?? 5000;
		this.files.set(path, { data: new Uint8Array(data.slice(0)), mtime, ctime: options?.ctime ?? mtime });
		this.onWrite?.(path);
	}
	async append(path: string, data: string) {
		await this.write(path, (this.text(path) ?? "") + data);
	}
	async appendBinary(path: string, data: ArrayBuffer) {
		await this.append(path, dec.decode(data));
	}
	async process(path: string, fn: (data: string) => string) {
		const out = fn(this.text(path) ?? "");
		await this.write(path, out);
		return out;
	}
	async stat(path: string) {
		const f = this.files.get(path);
		if (f) return { type: "file" as const, mtime: f.mtime, ctime: f.ctime, size: f.data.length };
		return this.folders.has(path) ? { type: "folder" as const, mtime: 0, ctime: 0, size: 0 } : null;
	}
	async copy(from: string, to: string) {
		this.files.set(to, { ...this.files.get(from)! });
	}
	async rename(from: string, to: string) {
		for (const [p, f] of [...this.files]) {
			if (p === from || p.startsWith(`${from}/`)) {
				this.files.delete(p);
				this.files.set(to + p.slice(from.length), f);
			}
		}
		if (this.folders.delete(from)) this.folders.add(to);
	}
	async remove(path: string) {
		this.files.delete(path);
	}
	async rmdir(path: string) {
		for (const p of [...this.files.keys()]) if (p.startsWith(`${path}/`)) this.files.delete(p);
		this.folders.delete(path);
	}
	async trashSystem(path: string) {
		await this.rmdir(path);
		this.files.delete(path);
		return true;
	}
	async trashLocal(path: string) {
		await this.trashSystem(path);
	}
	getResourcePath(path: string) {
		return `app://disk/${path}`;
	}
}
