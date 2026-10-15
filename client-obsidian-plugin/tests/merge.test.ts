import { describe, expect, it } from "vitest";

import { conflictPath, isMergeable, mergeText } from "../src/sync/merge";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array | null) => (b === null ? null : new TextDecoder().decode(b));

describe("mergeText", () => {
	it("merges edits to different lines", () => {
		const base = "one\ntwo\nthree\n";
		const merged = mergeText("a.md", enc(base), enc("ONE\ntwo\nthree\n"), enc("one\ntwo\nTHREE\n"));
		expect(dec(merged)).toBe("ONE\ntwo\nTHREE\n");
	});

	it("keeps the exact line endings and a missing final newline", () => {
		const base = "a\r\nb\r\nc";
		const merged = mergeText("a.md", enc(base), enc("A\r\nb\r\nc"), enc("a\r\nb\r\nC"));
		expect(dec(merged)).toBe("A\r\nb\r\nC");
	});

	it("accepts the same change on both sides", () => {
		const merged = mergeText("a.md", enc("x\n"), enc("y\n"), enc("y\n"));
		expect(dec(merged)).toBe("y\n");
	});

	it("returns null for conflicting edits", () => {
		expect(mergeText("a.md", enc("x\n"), enc("local\n"), enc("remote\n"))).toBeNull();
	});

	it("merges files that didn't exist at the base when the changes don't overlap", () => {
		expect(dec(mergeText("a.md", null, enc("same\n"), enc("same\n")))).toBe("same\n");
		expect(mergeText("a.md", null, enc("one\n"), enc("two\n"))).toBeNull();
	});

	it("refuses binary and non-UTF-8 files", () => {
		expect(mergeText("a.png", enc("x"), enc("y"), enc("x"))).toBeNull();
		expect(mergeText("a.md", enc("x"), new Uint8Array([0xff, 0xfe]), enc("x"))).toBeNull();
	});

	it("refuses a JSON merge that isn't valid JSON", () => {
		const base = '{\n"a": 1\n}\n';
		const local = '{\n"a": 1,\n"b": 2\n}\n';
		const remote = '{\n"a": 1\n}\n,\n';
		expect(mergeText("data.json", enc(base), enc(local), enc(remote))).toBeNull();
		const canvas = (a: number, z: number) => enc(`{\n"a": ${a},\n"m": 0,\n"z": ${z}\n}\n`);
		const ok = mergeText("x.canvas", canvas(1, 0), canvas(2, 0), canvas(1, 9));
		expect(JSON.parse(dec(ok)!)).toEqual({ a: 2, m: 0, z: 9 });
	});

	it("knows which files are text", () => {
		expect(isMergeable("Notes/x.MD")).toBe(true);
		expect(isMergeable("x.canvas")).toBe(true);
		expect(isMergeable(".md")).toBe(false);
		expect(isMergeable("dir.md/file")).toBe(false);
		expect(isMergeable("photo.jpg")).toBe(false);
	});
});

describe("conflictPath", () => {
	const date = new Date(2026, 9, 2, 15, 3);

	it("names the copy after the device and the time", () => {
		expect(conflictPath("Notes/Plan.md", "MacBook", date, () => false)).toBe(
			"Notes/Plan (conflict MacBook 2026-10-02 1503).md",
		);
		expect(conflictPath("README", "Phone", date, () => false)).toBe("README (conflict Phone 2026-10-02 1503)");
		expect(conflictPath(".hidden", "Phone", date, () => false)).toBe(".hidden (conflict Phone 2026-10-02 1503)");
	});

	it("numbers a second copy and cleans the device name", () => {
		const taken = new Set(["a (conflict device 2026-10-02 1503).md"]);
		expect(conflictPath("a.md", "  /:*  ", date, (p) => taken.has(p))).toBe("a (conflict device 2026-10-02 1503 2).md");
	});
});
