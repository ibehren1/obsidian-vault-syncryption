import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";

import { ApiClient, checkChallenge, normalizeEndpoint } from "../src/api/client";
import { ApiError, NetworkError, type HttpResponse, type Transport } from "../src/api/http";
import { fingerprint } from "../src/crypto/openssh";
import { client, newSeed, noBackend, SHARED_SECRET, uniqueName } from "./harness";

const json = (status: number, body: unknown, version = "0.1.0"): HttpResponse => ({
	status,
	headers: { "content-type": "application/json", ...(version ? { "x-syncryption-version": version } : {}) },
	body: new TextEncoder().encode(JSON.stringify(body)).buffer as ArrayBuffer,
});

function fake(handler: (url: string) => HttpResponse): ApiClient {
	const transport: Transport = async (request) => handler(request.url);
	return new ApiClient({
		endpoint: "https://sync.example.com",
		identity: { username: "alice", seed: newSeed() },
		deviceName: "Test",
		transport,
	});
}

describe("normalizeEndpoint", () => {
	it("keeps only the origin", () => {
		expect(normalizeEndpoint("https://sync.example.com/")).toBe("https://sync.example.com");
		expect(normalizeEndpoint("http://localhost:8080")).toBe("http://localhost:8080");
	});

	it("rejects paths and other schemes", () => {
		expect(() => normalizeEndpoint("https://example.com/sync")).toThrow();
		expect(() => normalizeEndpoint("ftp://example.com")).toThrow();
		expect(() => normalizeEndpoint("not a url")).toThrow();
	});
});

describe("checkChallenge", () => {
	const seed = newSeed();
	const key = ed25519.getPublicKey(seed);
	const message = (overrides: Partial<Record<string, string>> = {}) =>
		[
			overrides.first ?? "syncryption-auth@v1",
			`origin: ${overrides.origin ?? "https://sync.example.com"}`,
			`username: ${overrides.username ?? "alice"}`,
			`key: ${overrides.key ?? fingerprint(key)}`,
			`nonce: ${overrides.nonce ?? "A".repeat(43)}`,
			`expires: ${overrides.expires ?? "2026-10-02T12:00:00Z"}`,
			"",
		].join("\n");

	it("accepts a challenge for this server, user and key", () => {
		expect(() => checkChallenge(message(), "https://sync.example.com", "alice", key)).not.toThrow();
	});

	it.each([
		["first", "other-namespace"],
		["origin", "https://evil.example.com"],
		["username", "bob"],
		["key", "SHA256:AAAA"],
		["nonce", "short"],
	])("rejects a wrong %s", (field, value) => {
		expect(() => checkChallenge(message({ [field]: value }), "https://sync.example.com", "alice", key)).toThrow(
			expect.objectContaining({ code: "bad_challenge" }),
		);
	});

	it("rejects a message with extra lines", () => {
		const extra = message() + "sign: this too\n";
		expect(() => checkChallenge(extra, "https://sync.example.com", "alice", key)).toThrow(ApiError);
	});
});

describe("ApiClient without a server", () => {
	it("doesn't sign a challenge for another server", async () => {
		const api = fake((url) =>
			url.endsWith("/challenge")
				? json(200, {
						challengeId: "c",
						message: "syncryption-auth@v1\norigin: https://evil.example.com\n",
						expiresAt: "2026-10-02T12:00:00Z",
					})
				: json(500, {}),
		);
		await expect(api.login()).rejects.toMatchObject({ code: "bad_challenge" });
	});

	it("checks the server version", async () => {
		await expect(fake(() => json(200, {}, "1.0.0")).login()).rejects.toMatchObject({ code: "version_mismatch" });
		await expect(fake(() => json(200, {}, "")).login()).rejects.toBeInstanceOf(NetworkError);
	});

	it("turns error bodies and Retry-After into ApiError", async () => {
		const api = fake(() => {
			const r = json(429, { error: "rate_limited", message: "Slow down.", details: { a: 1 } });
			r.headers["retry-after"] = "12";
			return r;
		});
		await expect(api.login()).rejects.toMatchObject({
			status: 429,
			code: "rate_limited",
			message: "Slow down.",
			details: { a: 1 },
			retryAfter: 12,
		});
	});

	it("reports an unreachable server as a NetworkError", async () => {
		const api = new ApiClient({
			endpoint: "https://sync.example.com",
			identity: { username: "alice", seed: newSeed() },
			deviceName: "Test",
			transport: () => Promise.reject(new Error("offline")),
		});
		await expect(api.login()).rejects.toBeInstanceOf(NetworkError);
	});

	it("gives up on a request that never answers", async () => {
		const api = new ApiClient({
			endpoint: "https://sync.example.com",
			identity: { username: "alice", seed: newSeed() },
			deviceName: "Test",
			transport: () => new Promise(() => {}),
			timeoutMs: 20,
		});
		await expect(api.login()).rejects.toBeInstanceOf(NetworkError);
	});
});

describe.skipIf(noBackend)("ApiClient against the backend", () => {
	it("joins with the shared secret, then logs in without it", async () => {
		const username = uniqueName("join");
		const seed = newSeed();
		const api = client(username, seed);
		await expect(api.login()).rejects.toMatchObject({ status: 403, code: "join_required" });
		await expect(api.login("wrong")).rejects.toBeInstanceOf(ApiError);
		const joined = await api.login(SHARED_SECRET);
		expect(joined.status).toBe("active");
		expect((await api.selfDevice()).id).toBe(joined.deviceId);

		const again = client(username, seed);
		const result = await again.login();
		expect(result.deviceId).toBe(joined.deviceId);
	});

	it("makes a second key of the same user wait for approval", async () => {
		const username = uniqueName("second");
		const first = client(username, newSeed());
		await first.login(SHARED_SECRET);
		const second = client(username, newSeed(), "Phone");
		const pending = await second.login(SHARED_SECRET);
		expect(pending.status).toBe("pending");
		await expect(second.devices()).rejects.toMatchObject({ code: "device_pending" });

		const devices = await first.devices();
		expect(devices.find((d) => d.id === pending.deviceId)?.status).toBe("pending");
		await first.approveDevice(pending.deviceId);
		expect((await second.devices()).length).toBe(2);
	});

	it("logs in again when the token is rejected", async () => {
		const api = client(uniqueName("relogin"), newSeed());
		await api.login(SHARED_SECRET);
		(api as unknown as { token: string }).token = "not-a-token";
		expect((await api.selfDevice()).id).toBe(api.deviceId);
	});
});
