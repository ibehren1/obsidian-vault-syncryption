import { describe, expect, it } from "vitest";

import type { ApiClient } from "../src/api/client";
import { ApiError } from "../src/api/http";
import { LiveLoop } from "../src/sync/live";

describe("LiveLoop.wake", () => {
	it("ends a backoff early and starts again from the shortest one", async () => {
		const api = { wait: () => Promise.reject(new Error("offline")) } as unknown as ApiClient;
		const sleeps: number[] = [];
		let slept = (): void => {};
		const loop: LiveLoop = new LiveLoop({
			api,
			vaultId: "v",
			cursor: async () => 0,
			onChanges: async () => {},
			onLocks: async () => {},
			// Sleeps never end by themselves: only wake() moves the loop on.
			sleep: (ms) => {
				sleeps.push(ms);
				slept();
				return new Promise(() => {});
			},
		});
		const nextSleep = () => new Promise<void>((r) => (slept = r));
		let asleep = nextSleep();
		loop.start();
		await asleep;
		asleep = nextSleep();
		loop.wake();
		await asleep;
		expect(sleeps).toEqual([1000, 1000]);
		const stopped = loop.stop();
		loop.wake();
		await stopped;
	});
});

describe("LiveLoop backoff", () => {
	it("waits at least the server's Retry-After, as during maintenance", async () => {
		const maintenance = new ApiError(503, "maintenance", "In maintenance.", {}, 60);
		const api = { wait: () => Promise.reject(maintenance) } as unknown as ApiClient;
		const sleeps: number[] = [];
		const errors: unknown[] = [];
		let done = (): void => {};
		const twice = new Promise<void>((r) => (done = r));
		const loop: LiveLoop = new LiveLoop({
			api,
			vaultId: "v",
			cursor: async () => 0,
			onChanges: async () => {},
			onLocks: async () => {},
			onError: (e) => errors.push(e),
			sleep: async (ms) => {
				sleeps.push(ms);
				if (sleeps.length === 2) {
					void loop.stop();
					done();
				}
			},
		});
		loop.start();
		await twice;
		await loop.stop();
		expect(sleeps).toEqual([60_000, 60_000]);
		expect(errors[0]).toBe(maintenance);
	});
});
