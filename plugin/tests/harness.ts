/** Helpers for tests that talk to the real backend started by `backend-setup.ts`. */
import { inject } from "vitest";

import { ApiClient } from "../src/api/client";
import type { Transport } from "../src/api/http";

export { SHARED_SECRET } from "./backend-setup";

export const backendUrl = inject("backendUrl");
export const backendDataDir = inject("backendDataDir");
/** Use as `describe.skipIf(noBackend)`. */
export const noBackend = backendUrl === "";

let counter = 0;

export function uniqueName(prefix: string): string {
	return `${prefix}${Date.now().toString(36)}${(counter++).toString(36)}`;
}

/**
 * Each client looks like it comes from its own address (the server trusts the last
 * X-Forwarded-For entry), so the per-IP auth rate limit doesn't slow the tests down.
 */
export function testTransport(): Transport {
	const ip = `10.${rand()}.${rand()}.${rand()}`;
	const inner = fetchTransport();
	return (request) => inner({ ...request, headers: { ...request.headers, "X-Forwarded-For": ip } });
}

/** A transport over `fetch`. The plugin uses `requestUrl` (src/obsidian/transport.ts). */
export function fetchTransport(fetchImpl: typeof fetch = fetch): Transport {
	return async (request) => {
		const response = await fetchImpl(request.url, {
			method: request.method,
			headers: request.headers,
			body: request.body,
		});
		const headers: Record<string, string> = {};
		response.headers.forEach((value, name) => (headers[name.toLowerCase()] = value));
		return { status: response.status, headers, body: await response.arrayBuffer() };
	};
}

function rand(): number {
	return Math.floor(Math.random() * 254) + 1;
}

export function newSeed(): Uint8Array {
	return crypto.getRandomValues(new Uint8Array(32));
}

export function client(username: string, seed: Uint8Array, deviceName = "Test device"): ApiClient {
	return new ApiClient({
		endpoint: backendUrl,
		identity: { username, seed },
		deviceName,
		transport: testTransport(),
	});
}
