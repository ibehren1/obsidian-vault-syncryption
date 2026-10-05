/** Three-way merge of text files and conflict-copy names (docs/architecture.md 4.2). */
import { diff3Merge } from "node-diff3";

const TEXT_EXTENSIONS = new Set([
	"md",
	"txt",
	"canvas",
	"base",
	"json",
	"css",
	"js",
	"csv",
	"tsv",
	"yaml",
	"yml",
	"html",
	"xml",
	"svg",
]);
const JSON_EXTENSIONS = new Set(["json", "canvas"]);

function extension(path: string): string {
	const name = path.slice(path.lastIndexOf("/") + 1);
	const dot = name.lastIndexOf(".");
	return dot > 0 ? name.slice(dot + 1).toLowerCase() : "";
}

export function isMergeable(path: string): boolean {
	return TEXT_EXTENSIONS.has(extension(path));
}

function decode(data: Uint8Array): string | null {
	try {
		return new TextDecoder("utf-8", { fatal: true }).decode(data);
	} catch {
		return null;
	}
}

/** Lines with their line endings, so joining them gives back the exact text. */
function lines(text: string): string[] {
	return text.match(/[^\n]*\n|[^\n]+$/g) ?? [];
}

/**
 * Merge `local` and `remote`, both changed from `base` (null if the file didn't exist
 * there). Returns the merged bytes, or null if the changes conflict or the file isn't text.
 */
export function mergeText(path: string, base: Uint8Array | null, local: Uint8Array, remote: Uint8Array): Uint8Array | null {
	if (!isMergeable(path)) return null;
	const [b, l, r] = [base === null ? "" : decode(base), decode(local), decode(remote)];
	if (b === null || l === null || r === null) return null;
	const regions = diff3Merge(lines(l), lines(b), lines(r), { excludeFalseConflicts: true });
	if (regions.some((region) => region.conflict)) return null;
	const merged = regions.flatMap((region) => region.ok ?? []).join("");
	if (JSON_EXTENSIONS.has(extension(path))) {
		try {
			JSON.parse(merged);
		} catch {
			return null;
		}
	}
	return new TextEncoder().encode(merged);
}

function pad(n: number): string {
	return String(n).padStart(2, "0");
}

/**
 * `Notes/Plan (conflict MacBook 2026-10-02 1530).md`. `taken` says whether a path is in
 * use, so a second conflict in the same minute gets a number.
 */
export function conflictPath(path: string, device: string, date: Date, taken: (path: string) => boolean): string {
	const slash = path.lastIndexOf("/");
	const dir = path.slice(0, slash + 1);
	const name = path.slice(slash + 1);
	const dot = name.lastIndexOf(".");
	const [stem, ext] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, ""];
	const safeDevice = device.replace(/[\\/:*?"<>|#^[\]]/g, "").trim() || "device";
	const stamp =
		`${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
		`${pad(date.getHours())}${pad(date.getMinutes())}`;
	for (let i = 1; ; i++) {
		const suffix = i === 1 ? "" : ` ${i}`;
		const candidate = `${dir}${stem} (conflict ${safeDevice} ${stamp}${suffix})${ext}`;
		if (!taken(candidate)) return candidate;
	}
}
