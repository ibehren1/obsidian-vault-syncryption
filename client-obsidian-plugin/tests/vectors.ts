/// <reference types="node" />
import { readFileSync } from "node:fs";

/** Load a JSON file from the shared `testvectors/` folder. */
export function loadVectors<T>(name: string): T {
	return JSON.parse(readFileSync(new URL(`../../testvectors/${name}`, import.meta.url), "utf8")) as T;
}
