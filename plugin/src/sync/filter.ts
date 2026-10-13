/** Which paths are synced (docs/architecture.md 4.4). */
import { isVaultPath } from "../crypto/kdf";

/** Folders that are never synced, at any depth. */
const EXCLUDED_FOLDERS = new Set([".trash", ".git", "node_modules"]);
/** Files that are never synced, at any depth: per-device state and OS clutter. */
const EXCLUDED_FILES = new Set([".DS_Store", "Thumbs.db", "desktop.ini"]);
const WORKSPACE_FILES = new Set(["workspace.json", "workspace-mobile.json", "workspaces.json"]);

export interface FilterOptions {
	/** `app.vault.configDir`: the only hidden folder that is synced. */
	configDir: string;
	/** The name of this plugin's folder under `plugins/`. */
	pluginFolder?: string;
	/** The user's exclude list: one pattern per entry (see `parseExcludes`). */
	exclude?: string[];
}

export interface PathFilter {
	/** True for files that are synced. */
	(path: string): boolean;
	/** True for folders whose whole content is excluded, so a scan can skip them. */
	skipsFolder(folder: string): boolean;
}

/** The exclude list from the settings: one pattern per line, blank lines and `#` comments ignored. */
export function parseExcludes(text: string): string[] {
	return text
		.split("\n")
		.map((line) => line.trim())
		.filter((line) => line !== "" && !line.startsWith("#"));
}

/**
 * A vault-relative pattern. `*` matches within one path segment and `**` across segments. It
 * matches the path itself or anything inside it, so `Private` excludes the whole folder.
 */
function compile(pattern: string): RegExp {
	const clean = pattern.replace(/^\/+|\/+$/g, "");
	let source = "";
	for (let i = 0; i < clean.length; i++) {
		const c = clean[i]!;
		if (c === "*" && clean[i + 1] === "*") {
			source += ".*";
			i++;
		} else if (c === "*") {
			source += "[^/]*";
		} else if (c === "?") {
			source += "[^/]";
		} else {
			source += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
		}
	}
	return new RegExp(`^${source}(?:/.*)?$`);
}

export function pathFilter(opts: FilterOptions): PathFilter {
	const pluginFolder = opts.pluginFolder ?? "vault-syncryption";
	const patterns = (opts.exclude ?? []).map(compile);
	const userExcluded = (path: string) => patterns.some((p) => p.test(path));

	/** Rules for a folder's own segments, shared by files and folders. */
	const folderExcluded = (segments: string[]): boolean => {
		if (segments.some((s) => EXCLUDED_FOLDERS.has(s))) return true;
		const [top, second, third] = segments;
		if (top === undefined) return false;
		if (top === opts.configDir) {
			// Never this plugin's own folder: its settings and code are per device.
			return second === "plugins" && third === pluginFolder;
		}
		// Other hidden files and folders aren't in Obsidian's index and aren't synced.
		return segments.some((s) => s.startsWith("."));
	};

	const include = ((path: string) => {
		// A name no vault path may have (crypto.md 5.2), e.g. with `\` on Linux: never synced.
		if (!isVaultPath(path)) return false;
		const segments = path.split("/");
		const name = segments.pop()!;
		if (folderExcluded(segments) || EXCLUDED_FILES.has(name)) return false;
		const inConfig = segments.length > 0 && segments[0] === opts.configDir;
		if (name.startsWith(".") && !inConfig) return false;
		if (inConfig && segments.length === 1 && WORKSPACE_FILES.has(name)) return false;
		return !userExcluded(path);
	}) as PathFilter;
	include.skipsFolder = (folder) => folderExcluded(folder.split("/")) || userExcluded(folder);
	return include;
}
