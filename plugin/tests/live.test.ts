import { describe, expect, it } from "vitest";

import type { ApiClient } from "../src/api/client";
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
