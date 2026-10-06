/**
 * Vitest global setup: start the real backend (`uv run uvicorn ...`) on a free port, so the
 * API and sync tests run against the server itself. Without uv those tests are skipped,
 * unless REQUIRE_BACKEND=1 (as in CI), which makes a missing backend an error.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { TestProject } from "vitest/node";

declare module "vitest" {
	export interface ProvidedContext {
		backendUrl: string;
		/** The server's data folder, to check that it holds no plaintext. */
		backendDataDir: string;
	}
}

export const SHARED_SECRET = "test-shared-secret";

export default async function setup(project: TestProject): Promise<() => void> {
	const required = process.env["REQUIRE_BACKEND"] === "1";
	if (spawnSync("uv", ["--version"]).status !== 0) {
		if (required) throw new Error("REQUIRE_BACKEND=1 but uv is not installed");
		project.provide("backendUrl", "");
		project.provide("backendDataDir", "");
		return () => {};
	}
	const dataDir = mkdtempSync(join(tmpdir(), "syncryption-test-"));
	const server: ChildProcess = spawn(
		"uv",
		[
			"run",
			"--project",
			"../backend",
			"--quiet",
			"uvicorn",
			"--factory",
			"syncryption_server.app:create_app",
			"--host",
			"127.0.0.1",
			"--port",
			"0",
			"--no-proxy-headers",
		],
		{
			env: {
				...process.env,
				SHARED_SECRET,
				ADMIN_TOKEN: "test-admin-token-0123456789abcdef",
				BEHIND_PROXY: "TRUE",
				SYNCRYPTION_DATA_DIR: dataDir,
			},
			stdio: ["ignore", "ignore", "pipe"],
		},
	);
	const url = await new Promise<string>((resolve, reject) => {
		let log = "";
		const timer = setTimeout(() => reject(new Error(`backend didn't start:\n${log}`)), 60_000);
		server.stderr!.on("data", (chunk: Buffer) => {
			log += chunk.toString();
			const match = /Uvicorn running on (http:\/\/127\.0\.0\.1:\d+)/.exec(log);
			if (match) {
				clearTimeout(timer);
				resolve(match[1]!);
			}
		});
		server.on("exit", (code) => {
			clearTimeout(timer);
			reject(new Error(`backend exited with ${code}:\n${log}`));
		});
	});
	server.stderr!.resume();
	project.provide("backendUrl", url);
	project.provide("backendDataDir", dataDir);
	return () => {
		server.kill("SIGTERM");
		rmSync(dataDir, { recursive: true, force: true });
	};
}
