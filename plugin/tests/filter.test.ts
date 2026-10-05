import { describe, expect, it } from "vitest";

import { isConfigFolder, parseExcludes, pathFilter } from "../src/sync/filter";

describe("pathFilter", () => {
	it("syncs notes and attachments", () => {
		const include = pathFilter({ configDir: ".obsidian" });
		expect(include("Note.md")).toBe(true);
		expect(include("a/b/photo.png")).toBe(true);
		expect(include("a/trash.md")).toBe(true);
	});

	it("skips trash, git, node_modules and OS clutter at any depth", () => {
		const include = pathFilter({ configDir: ".obsidian" });
		expect(include(".trash/old.md")).toBe(false);
		expect(include("project/.git/HEAD")).toBe(false);
		expect(include("a/node_modules/x/index.js")).toBe(false);
		expect(include(".obsidian/plugins/x/node_modules/y.js")).toBe(false);
		expect(include("a/.DS_Store")).toBe(false);
		expect(include(".obsidian/.DS_Store")).toBe(false);
	});

	it("skips hidden files and folders outside the config folders", () => {
		const include = pathFilter({ configDir: ".obsidian" });
		expect(include(".hidden.md")).toBe(false);
		expect(include("a/.hidden.md")).toBe(false);
		expect(include(".stfolder/x")).toBe(false);
		expect(include("a/.cache/x.md")).toBe(false);
		expect(include(".obsidian/plugins/x/.hotreload")).toBe(true);
	});

	it("syncs every config folder except workspaces and this plugin", () => {
		const include = pathFilter({ configDir: ".config" });
		expect(include(".config/app.json")).toBe(true);
		expect(include(".config/workspace.json")).toBe(false);
		expect(include(".config/workspace-mobile.json")).toBe(false);
		expect(include(".config/workspaces.json")).toBe(false);
		expect(include(".config/plugins/vault-syncryption/data.json")).toBe(false);
		expect(include(".config/plugins/other/data.json")).toBe(true);
		expect(include(".config/themes/x/workspace.json")).toBe(true);
		// Profiles for other devices.
		expect(include(".obsidian/app.json")).toBe(true);
		expect(include(".obsidian-mobile/hotkeys.json")).toBe(true);
		expect(include(".obsidian-mobile/workspace-mobile.json")).toBe(false);
		expect(include(".obsidian-mobile/plugins/vault-syncryption/main.js")).toBe(false);
	});

	it("uses the plugin's folder name", () => {
		const include = pathFilter({ configDir: ".obsidian", pluginFolder: "sync-beta" });
		expect(include(".obsidian/plugins/sync-beta/data.json")).toBe(false);
		expect(include(".obsidian/plugins/vault-syncryption/data.json")).toBe(true);
	});

	it("applies the user's exclude list", () => {
		const include = pathFilter({
			configDir: ".obsidian",
			exclude: parseExcludes("# comment\n\nPrivate\n/Archive/2020/\n*.mp4\n**/*.tmp\n.obsidian/plugins/big\nfile?.md\n"),
		});
		expect(include("Private")).toBe(false);
		expect(include("Private/a.md")).toBe(false);
		expect(include("Private notes.md")).toBe(true);
		expect(include("Archive/2020/x.md")).toBe(false);
		expect(include("Archive/2021/x.md")).toBe(true);
		expect(include("clip.mp4")).toBe(false);
		expect(include("a/clip.mp4")).toBe(true);
		expect(include("a/b/c.tmp")).toBe(false);
		expect(include(".obsidian/plugins/big/main.js")).toBe(false);
		expect(include("file1.md")).toBe(false);
		expect(include("file10.md")).toBe(true);
		expect(include("comment")).toBe(true);
	});

	it("tells a scan which folders to skip", () => {
		const include = pathFilter({ configDir: ".obsidian", exclude: ["Private"] });
		expect(include.skipsFolder(".obsidian")).toBe(false);
		expect(include.skipsFolder(".obsidian/plugins")).toBe(false);
		expect(include.skipsFolder(".obsidian/plugins/vault-syncryption")).toBe(true);
		expect(include.skipsFolder(".obsidian/plugins/x/node_modules")).toBe(true);
		expect(include.skipsFolder("Private")).toBe(true);
		expect(include.skipsFolder("a/.git")).toBe(true);
	});

	it("knows the config folders", () => {
		expect(isConfigFolder(".obsidian", ".obsidian")).toBe(true);
		expect(isConfigFolder(".obsidian-phone", ".config")).toBe(true);
		expect(isConfigFolder(".config", ".config")).toBe(true);
		expect(isConfigFolder(".git", ".obsidian")).toBe(false);
		expect(isConfigFolder("obsidian", ".obsidian")).toBe(false);
	});
});
