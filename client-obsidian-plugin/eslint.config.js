import js from "@eslint/js";
import { builtinModules as builtins } from "node:module";
import obsidianmd from "eslint-plugin-obsidianmd";
import globals from "globals";
import tseslint from "typescript-eslint";

// Shared plugin code must run on mobile: no Node built-ins, and no sshpk (needs Node crypto).
const bareBuiltins = builtins.map((name) => name.replace(/^node:/, ""));
const forbiddenImports = [
	...new Set([...bareBuiltins, ...bareBuiltins.map((name) => `node:${name}`)]),
	"electron",
	"sshpk",
];

// The review bot's config (eslint-plugin-obsidianmd), limited to `src/` and package.json: the
// tests and build scripts aren't part of the plugin. Its JavaScript-only blocks are dropped.
function obsidianReviewRules() {
	const flat = (files) => (files ?? []).flat();
	return obsidianmd.configs.recommended
		.filter((config) => !flat(config.files).length || flat(config.files).some((f) => f.includes("ts") || f === "package.json"))
		.map((config) => (flat(config.files).includes("package.json") ? config : { ...config, files: ["src/**/*.ts"] }));
}

export default tseslint.config(
	{ ignores: ["main.js", "node_modules/"] },
	js.configs.recommended,
	...tseslint.configs.recommended,
	// The rules the community plugin review bot runs, on the plugin code it reviews.
	...obsidianReviewRules(),
	{
		files: ["src/**/*.ts"],
		languageOptions: { parserOptions: { projectService: true } },
	},
	{
		files: ["src/**/*.ts"],
		languageOptions: { globals: globals.browser },
		rules: {
			"no-restricted-imports": [
				"error",
				{
					paths: forbiddenImports.map((name) => ({
						name,
						message: "Plugin code must run on mobile. Use WebCrypto, @noble/* or requestUrl.",
					})),
				},
			],
		},
	},
	{
		files: ["*.mjs", "*.js", "scripts/**/*.mjs"],
		languageOptions: { globals: globals.node },
	},
);
