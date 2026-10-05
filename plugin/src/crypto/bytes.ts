/** Byte helpers that work without Node's Buffer. */

export function utf8(s: string): Uint8Array {
	return new TextEncoder().encode(s);
}

export function fromUtf8(b: Uint8Array): string {
	return new TextDecoder("utf-8", { fatal: true }).decode(b);
}

/** Bytes as a Latin-1 string, for ASCII protocol identifiers. */
export function latin1(b: Uint8Array): string {
	return String.fromCharCode(...b);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
	return diff === 0;
}

export function u32be(n: number): Uint8Array {
	const out = new Uint8Array(4);
	new DataView(out.buffer).setUint32(0, n);
	return out;
}

/** SSH wire `string`: u32be(length) || bytes. */
export function sshString(x: Uint8Array): Uint8Array {
	return concat(u32be(x.length), x);
}

/** Standard base64 with padding. Throws on invalid input. */
export function fromBase64(s: string): Uint8Array {
	const bin = atob(s);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

export function toBase64(b: Uint8Array): string {
	let bin = "";
	for (const byte of b) bin += String.fromCharCode(byte);
	return btoa(bin);
}

/** Standard base64 without padding, as used in age headers. */
export function toBase64NoPad(b: Uint8Array): string {
	return toBase64(b).replace(/=+$/, "");
}

/** Strict unpadded base64: rejects padding, whitespace and non-canonical encodings. */
export function fromBase64NoPad(s: string): Uint8Array {
	if (!/^[A-Za-z0-9+/]*$/.test(s) || s.length % 4 === 1) throw new Error("invalid base64");
	const out = fromBase64(s + "=".repeat((4 - (s.length % 4)) % 4));
	if (toBase64NoPad(out) !== s) throw new Error("invalid base64");
	return out;
}

/** base64url without padding (`b64u` in the specs). Strict on decode. */
export function toB64u(b: Uint8Array): string {
	return toBase64NoPad(b).replace(/\+/g, "-").replace(/\//g, "_");
}

export function fromB64u(s: string): Uint8Array {
	if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("invalid base64url");
	return fromBase64NoPad(s.replace(/-/g, "+").replace(/_/g, "/"));
}

export function hex(b: Uint8Array): string {
	return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function fromHex(s: string): Uint8Array {
	if (s.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(s)) throw new Error("invalid hex");
	const out = new Uint8Array(s.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
	return out;
}

/** Bounds-checked reader for the SSH wire format. Calls `fail` on any overrun. */
export class SshReader {
	private off = 0;

	constructor(
		private readonly buf: Uint8Array,
		private readonly fail: () => never,
	) {}

	get remaining(): number {
		return this.buf.length - this.off;
	}

	bytes(n: number): Uint8Array {
		if (n < 0 || n > this.remaining) this.fail();
		const out = this.buf.subarray(this.off, this.off + n);
		this.off += n;
		return out;
	}

	u32(): number {
		const b = this.bytes(4);
		return new DataView(b.buffer, b.byteOffset, 4).getUint32(0);
	}

	string(): Uint8Array {
		return this.bytes(this.u32());
	}

	rest(): Uint8Array {
		return this.bytes(this.remaining);
	}
}
