import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";

import { ApiClient, checkChallenge, normalizeEndpoint } from "../src/api/client";
import { ApiError, disabledText, isDisabled, isMaintenance, maintenanceText, NetworkError, type HttpResponse, type Transport } from "../src/api/http";
import { fingerprint } from "../src/crypto/openssh";
import { client, newSeed, noBackend, SHARED_SECRET, uniqueName } from "./harness";

const json = (status: number, body: unknown, versions: Record<string, string> = { "x-syncryption-version": "0.1.1", "x-syncryption-protocol": "1" }): HttpResponse => ({
	status,
	headers: { "content-type": "application/json", ...versions },
	body: new TextEncoder().encode(JSON.stringify(body)).buffer as ArrayBuffer,
});

function fake(handler: (url: string) => HttpResponse): ApiClient {
	const transport: Transport = async (request) => handler(request.url);
	return new ApiClient({
		endpoint: "https://sync.example.com",
		identity: { username: "alice", seed: newSeed() },
		deviceName: "Test",
		vaultName: "Notes",
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
			`vault: ${overrides.vault ?? "Notes"}`,
			`key: ${overrides.key ?? fingerprint(key)}`,
			`nonce: ${overrides.nonce ?? "A".repeat(43)}`,
			`expires: ${overrides.expires ?? "2026-10-02T12:00:00Z"}`,
			"",
		].join("\n");

	it("accepts a challenge for this server, user, vault and key", () => {
		expect(() => checkChallenge(message(), "https://sync.example.com", "alice", "Notes", key)).not.toThrow();
		// The vault name as the server stores it: NFC, trimmed.
		const cafe = message({ vault: "Caf\u00e9" });
		expect(() => checkChallenge(cafe, "https://sync.example.com", "alice", " Cafe\u0301 ", key)).not.toThrow();
	});

	it.each([
		["first", "other-namespace"],
		["origin", "https://evil.example.com"],
		["username", "bob"],
		["vault", "Work"],
		["key", "SHA256:AAAA"],
		["nonce", "short"],
	])("rejects a wrong %s", (field, value) => {
		expect(() => checkChallenge(message({ [field]: value }), "https://sync.example.com", "alice", "Notes", key)).toThrow(
			expect.objectContaining({ code: "bad_challenge" }),
		);
	});

	it("rejects a message with extra or missing lines", () => {
		const extra = message() + "sign: this too\n";
		expect(() => checkChallenge(extra, "https://sync.example.com", "alice", "Notes", key)).toThrow(ApiError);
		const noVault = message().replace("vault: Notes\n", "");
		expect(() => checkChallenge(noVault, "https://sync.example.com", "alice", "Notes", key)).toThrow(ApiError);
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

	it("names the vault in the challenge, and sends the shared secret only when given", async () => {
		const seed = newSeed();
		const bodies: Record<string, unknown>[] = [];
		const challenges: Record<string, unknown>[] = [];
		const transport: Transport = async (request) => {
			if (request.url.endsWith("/challenge")) {
				challenges.push(JSON.parse(request.body as string) as Record<string, unknown>);
				const message = [
					"syncryption-auth@v1",
					"origin: https://sync.example.com",
					"username: alice",
					"vault: Notes",
					`key: ${fingerprint(ed25519.getPublicKey(seed))}`,
					`nonce: ${"A".repeat(43)}`,
					"expires: 2026-10-02T12:00:00Z",
					"",
				].join("\n");
				return json(200, { challengeId: "c", message, expiresAt: "2026-10-02T12:00:00Z" });
			}
			bodies.push(JSON.parse(request.body as string) as Record<string, unknown>);
			return json(200, { token: "t", deviceId: "d", vaultId: null, status: "active", created: true, expiresAt: "2026-10-02T13:00:00Z" });
		};
		const api = new ApiClient({
			endpoint: "https://sync.example.com",
			identity: { username: "alice", seed },
			deviceName: "Test",
			vaultName: " Notes ",
			transport,
		});
		await api.login();
		await api.login("secret");
		expect(challenges[0]).toMatchObject({ username: "alice", vaultName: "Notes" });
		expect(bodies[0]).not.toHaveProperty("sharedSecret");
		expect(bodies[1]).toMatchObject({ challengeId: "c", deviceName: "Test", sharedSecret: "secret" });
		expect(bodies[1]).not.toHaveProperty("vaultName");
	});

	it("checks the protocol version, not the server version", async () => {
		const login = (versions: Record<string, string>) => fake(() => json(200, {}, versions)).login();
		await expect(login({ "x-syncryption-version": "0.1.0" })).rejects.toMatchObject({ code: "version_mismatch", message: expect.stringContaining("Update the server") as unknown });
		await expect(login({ "x-syncryption-version": "0.2.0", "x-syncryption-protocol": "2" })).rejects.toMatchObject({ code: "version_mismatch", message: expect.stringContaining("Update the plugin") as unknown });
		await expect(login({ "x-syncryption-version": "7.3.1", "x-syncryption-protocol": "1" })).rejects.not.toMatchObject({ code: "version_mismatch" });
		await expect(login({})).rejects.toBeInstanceOf(NetworkError);
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

	it("turns the maintenance 503 into ApiError maintenance, not a NetworkError", async () => {
		const details = { adminContact: "ops@example.com", note: "Moving to a new disk.", since: "2026-10-05T10:00:00Z" };
		const api = fake(() => {
			const r = json(503, { error: "maintenance", message: "The server is in maintenance, so sync is paused.", details });
			r.headers["retry-after"] = "60";
			return r;
		});
		const error = await api.login().catch((e: unknown) => e);
		expect(error).toBeInstanceOf(ApiError);
		expect(error).toMatchObject({ status: 503, code: "maintenance", details, retryAfter: 60 });
		expect(isMaintenance(error)).toBe(true);
	});

	it("reports an unreachable server as a NetworkError", async () => {
		const api = new ApiClient({
			endpoint: "https://sync.example.com",
			identity: { username: "alice", seed: newSeed() },
			deviceName: "Test",
			vaultName: "Notes",
			transport: () => Promise.reject(new Error("offline")),
		});
		await expect(api.login()).rejects.toBeInstanceOf(NetworkError);
	});

	it("gives up on a request that never answers", async () => {
		const api = new ApiClient({
			endpoint: "https://sync.example.com",
			identity: { username: "alice", seed: newSeed() },
			deviceName: "Test",
			vaultName: "Notes",
			transport: () => new Promise(() => {}),
			timeoutMs: 20,
		});
		await expect(api.login()).rejects.toBeInstanceOf(NetworkError);
	});
});

describe("isDisabled", () => {
	it("is true only for the admin's 403s", () => {
		expect(isDisabled(new ApiError(403, "user_disabled", "x"))).toBe(true);
		expect(isDisabled(new ApiError(403, "vault_disabled", "x"))).toBe(true);
		expect(isDisabled(new ApiError(403, "device_pending", "x"))).toBe(false);
		expect(isDisabled(new NetworkError("x"))).toBe(false);
	});
});

describe("maintenance and disabled texts", () => {
	const base = "The server is in maintenance, so sync is paused. It resumes by itself.";

	it("isMaintenance is true only for the maintenance error", () => {
		expect(isMaintenance(new ApiError(503, "maintenance", "x"))).toBe(true);
		expect(isMaintenance(new ApiError(503, "http_503", "x"))).toBe(false);
		expect(isMaintenance(new NetworkError("x"))).toBe(false);
	});

	it("builds the maintenance text from the parts the server sent", () => {
		expect(maintenanceText({ note: "Back at 14:00", adminContact: "ops@example.com" })).toBe(
			`${base} Back at 14:00. For help, contact the server admin: ops@example.com.`,
		);
		expect(maintenanceText({ note: null, adminContact: "Ann in #it." })).toBe(`${base} For help, contact the server admin: Ann in #it.`);
		expect(maintenanceText({ note: "New disk!", since: "2026-10-05T10:00:00Z" })).toBe(`${base} New disk! For help or info, contact your server admin.`);
		expect(maintenanceText({ note: "  ", adminContact: null })).toBe(`${base} For help or info, contact your server admin.`);
		expect(maintenanceText({})).toBe(`${base} For help or info, contact your server admin.`);
	});

	it("adds the admin contact to disabled errors", () => {
		expect(disabledText(new ApiError(403, "user_disabled", "This user is disabled."))).toBe("This user is disabled.");
		expect(disabledText(new ApiError(403, "vault_disabled", "This vault is disabled", { adminContact: "ops@example.com" }))).toBe(
			"This vault is disabled. Contact the server admin: ops@example.com.",
		);
	});
});

describe.skipIf(noBackend)("ApiClient against the backend", () => {
	it("needs the shared secret for a new vault, then logs in without it", async () => {
		const username = uniqueName("join");
		const vaultName = uniqueName("Vault ");
		const seed = newSeed();
		const api = client(username, vaultName, seed);
		await expect(api.login()).rejects.toMatchObject({ status: 403, code: "join_required" });
		await expect(api.login("wrong")).rejects.toBeInstanceOf(ApiError);
		const joined = await api.login(SHARED_SECRET);
		expect(joined).toMatchObject({ status: "active", vaultId: null });
		expect(await api.selfDevice()).toMatchObject({ id: joined.deviceId, username, vaultName });

		const again = client(username, vaultName, seed);
		const result = await again.login();
		expect(result.deviceId).toBe(joined.deviceId);
	});

	it("refuses a known key for another vault or user", async () => {
		const username = uniqueName("onekey");
		const vaultName = uniqueName("Vault ");
		const seed = newSeed();
		await client(username, vaultName, seed).login(SHARED_SECRET);
		await expect(client(username, uniqueName("Other "), seed).login(SHARED_SECRET)).rejects.toBeInstanceOf(ApiError);
		await expect(client(uniqueName("other"), vaultName, seed).login(SHARED_SECRET)).rejects.toBeInstanceOf(ApiError);
	});

	it("tells a second new key that the vault is being created", async () => {
		const username = uniqueName("creating");
		const vaultName = uniqueName("Vault ");
		await client(username, vaultName, newSeed()).login(SHARED_SECRET);
		const second = client(username, vaultName, newSeed());
		await expect(second.login(SHARED_SECRET)).rejects.toMatchObject({ status: 409, code: "vault_being_created" });
	});

	it("logs in again when the token is rejected", async () => {
		const api = client(uniqueName("relogin"), uniqueName("Vault "), newSeed());
		await api.login(SHARED_SECRET);
		(api as unknown as { token: string }).token = "not-a-token";
		expect((await api.selfDevice()).id).toBe(api.deviceId);
	});
});
