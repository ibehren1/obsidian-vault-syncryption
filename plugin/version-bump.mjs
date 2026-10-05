// `npm version <x>` hook: copy the new version from package.json into both manifests (the
// repo root copy is what Obsidian reads for updates) and record it in both versions.json files.
import { readFileSync, writeFileSync } from "node:fs";
import process from "node:process";

const version = process.env.npm_package_version;
if (!version) throw new Error("Run this through `npm version`.");

const read = (path) => JSON.parse(readFileSync(path, "utf8"));
const write = (path, value) => writeFileSync(path, JSON.stringify(value, null, "\t") + "\n");

const manifest = read("manifest.json");
manifest.version = version;
const versions = read("versions.json");
versions[version] = manifest.minAppVersion;

for (const dir of [".", ".."]) {
	write(`${dir}/manifest.json`, manifest);
	write(`${dir}/versions.json`, versions);
}
