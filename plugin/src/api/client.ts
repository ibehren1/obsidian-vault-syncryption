/** Typed client for the server API (docs/protocol.md), over a `Transport`. */
import { ed25519 } from "@noble/curves/ed25519.js";

import { fromUtf8, utf8 } from "../crypto/bytes";
import { fingerprint, publicKeyText } from "../crypto/openssh";
import { NAMESPACE_AUTH, signSshsig } from "../crypto/sshsig";
import { ApiError, NetworkError, type HttpResponse, type Transport } from "./http";
import type { components } from "./schema";

export type Schemas = components["schemas"];
export type Device = Schemas["Device"];
export type Vault = Schemas["Vault"];
export type Member = Schemas["Member"];
export type KeyringObject = Schemas["Keyring"];
export type KeyringUpload = Schemas["KeyringUpload"];
export type Revision = Schemas["Revision"];
export type CommitRequest = Schemas["CommitRequest"];
export type Changes = Schemas["Changes"];
export type History = Schemas["History"];
export type VerifyResponse = Schemas["VerifyResponse"];
export type OpenResponse = Schemas["OpenResponse"];
export type WaitResponse = Schemas["WaitResponse"];
export type Lock = Schemas["Lock"];
export type Locks = Schemas["Locks"];

/** The server major version this client speaks (protocol.md 13). */
export const SERVER_MAJOR = 0;
export const VERSION_HEADER = "x-syncryption-version";

export interface Identity {
	username: string;
	/** Ed25519 seed, kept in memory only. */
	seed: Uint8Array;
}

export interface ClientOptions {
	endpoint: string;
	identity: Identity;
	deviceName: string;
	transport: Transport;
	/** Give up on a request after this long (default 60 s, above the 25 s long-poll). */
	timeoutMs?: number;
}

/**
 * A request that hangs (a mobile app suspended mid-request) would otherwise stall every
 * later sync. The abandoned request may still finish; its result is ignored.
 */
const REQUEST_TIMEOUT_MS = 60_000;

/**
 * `https://Notes.Example.com/` -> `https://notes.example.com`. The endpoint must be an
 * origin: the server signs challenges for its origin, and the client compares the two.
 */
export function normalizeEndpoint(endpoint: string): string {
	let url: URL;
	try {
		url = new URL(endpoint.trim());
	} catch {
		throw new Error("The endpoint must be a URL like https://notes.example.com");
	}
	if (url.protocol !== "https:" && url.protocol !== "http:") {
		throw new Error("The endpoint must start with https://");
	}
	if ((url.pathname !== "/" && url.pathname !== "") || url.search || url.hash || url.username) {
		throw new Error("The endpoint must be just the server address, without a path");
	}
	return url.origin;
}

/**
 * Check a login challenge before signing it (protocol.md 5.1), so a malicious server
 * can't get a signature it could replay against another server.
 */
export function checkChallenge(message: string, origin: string, username: string, publicKey: Uint8Array): void {
	const lines = message.split("\n");
	const ok =
		lines.length === 7 &&
		lines[0] === NAMESPACE_AUTH &&
		lines[1] === `origin: ${origin}` &&
		lines[2] === `username: ${username}` &&
		lines[3] === `key: ${fingerprint(publicKey)}` &&
		/^nonce: [A-Za-z0-9_-]{43}$/.test(lines[4] ?? "") &&
		/^expires: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(lines[5] ?? "") &&
		lines[6] === "";
	if (!ok) throw new ApiError(0, "bad_challenge", "The server sent an unexpected login challenge.");
}

type Body = { json: unknown } | { bytes: Uint8Array } | undefined;

export class ApiClient {
	readonly origin: string;
	readonly publicKey: Uint8Array;
	private token: string | null = null;
	/** Set after login. */
	deviceId: string | null = null;
	deviceStatus: "active" | "pending" | null = null;

	constructor(private readonly opts: ClientOptions) {
		this.origin = normalizeEndpoint(opts.endpoint);
		this.publicKey = ed25519.getPublicKey(opts.identity.seed);
	}

	get username(): string {
		return this.opts.identity.username;
	}

	/**
	 * Log in, or join the server with `sharedSecret` (protocol.md 5). Without a secret, an
	 * unknown key gets `403 join_required`: the caller then asks the user for it.
	 */
	async login(sharedSecret?: string): Promise<VerifyResponse> {
		const publicKey = publicKeyText(this.publicKey);
		const challenge = await this.send<Schemas["ChallengeResponse"]>("POST", "/api/v1/auth/challenge", {
			json: { username: this.username, publicKey },
		});
		checkChallenge(challenge.message, this.origin, this.username, this.publicKey);
		const signature = signSshsig(this.opts.identity.seed, NAMESPACE_AUTH, utf8(challenge.message));
		const body: Schemas["VerifyRequest"] = {
			challengeId: challenge.challengeId,
			signature,
			deviceName: this.opts.deviceName,
		};
		if (sharedSecret !== undefined) body.sharedSecret = sharedSecret;
		const result = await this.send<VerifyResponse>("POST", "/api/v1/auth/verify", { json: body });
		this.token = result.token;
		this.deviceId = result.deviceId;
		this.deviceStatus = result.status;
		return result;
	}

	// Devices (protocol.md 6)
	selfDevice(): Promise<Device> {
		return this.call("GET", "/api/v1/devices/self");
	}
	async devices(): Promise<Device[]> {
		return (await this.call<Schemas["DeviceList"]>("GET", "/api/v1/devices")).devices;
	}
	approveDevice(deviceId: string): Promise<Device> {
		return this.call("POST", `/api/v1/devices/${enc(deviceId)}/approve`);
	}
	/** Revoke a device of this user: it loses every vault membership and its sessions. */
	revokeDevice(deviceId: string): Promise<Device> {
		return this.call("DELETE", `/api/v1/devices/${enc(deviceId)}`);
	}

	// Vaults (protocol.md 7)
	openVault(name: string): Promise<OpenResponse> {
		return this.call("POST", "/api/v1/vaults/open", { json: { name } });
	}
	createVault(id: string, name: string, keyring: KeyringUpload): Promise<Vault> {
		return this.call("POST", "/api/v1/vaults", { json: { id, name, keyring } });
	}
	async members(vaultId: string): Promise<Member[]> {
		return (await this.call<Schemas["MemberList"]>("GET", `${vaultPath(vaultId)}/members`)).members;
	}
	approveMember(vaultId: string, deviceId: string): Promise<Member> {
		return this.call("POST", `${vaultPath(vaultId)}/members/${enc(deviceId)}/approve`);
	}
	async removeMember(vaultId: string, deviceId: string): Promise<void> {
		await this.call("DELETE", `${vaultPath(vaultId)}/members/${enc(deviceId)}`);
	}
	keyring(vaultId: string, version?: number): Promise<KeyringObject> {
		const query = version === undefined ? "" : `?version=${version}`;
		return this.call("GET", `${vaultPath(vaultId)}/keyring${query}`);
	}
	putKeyring(vaultId: string, upload: KeyringUpload): Promise<KeyringObject> {
		return this.call("PUT", `${vaultPath(vaultId)}/keyring`, { json: upload });
	}

	/** The current keyring, for recovery (protocol.md 7.4). Pending tokens are allowed. */
	recoveryKeyring(vaultId: string): Promise<KeyringObject> {
		return this.call("GET", `${vaultPath(vaultId)}/recovery`);
	}

	/** Upload the next keyring signed by the recovery key, activating this device's membership. */
	recover(vaultId: string, upload: KeyringUpload): Promise<KeyringObject> {
		return this.call("POST", `${vaultPath(vaultId)}/recover`, { json: upload });
	}

	// Blobs (protocol.md 8)
	async putBlob(vaultId: string, blobId: string, bytes: Uint8Array): Promise<void> {
		await this.call("PUT", `${vaultPath(vaultId)}/blobs/${enc(blobId)}`, { bytes });
	}
	async getBlob(vaultId: string, blobId: string): Promise<Uint8Array> {
		const response = await this.raw("GET", `${vaultPath(vaultId)}/blobs/${enc(blobId)}`);
		return new Uint8Array(response.body);
	}
	async missingBlobs(vaultId: string, ids: string[]): Promise<string[]> {
		const missing: string[] = [];
		for (let i = 0; i < ids.length; i += 1000) {
			const batch = ids.slice(i, i + 1000);
			const r = await this.call<Schemas["MissingResponse"]>("POST", `${vaultPath(vaultId)}/blobs/missing`, {
				json: { ids: batch },
			});
			missing.push(...r.missing);
		}
		return missing;
	}

	// Files and the change feed (protocol.md 9, 10)
	commit(vaultId: string, fileId: string, body: CommitRequest): Promise<Revision> {
		return this.call("PUT", `${vaultPath(vaultId)}/files/${enc(fileId)}`, { json: body });
	}
	head(vaultId: string, fileId: string): Promise<Revision> {
		return this.call("GET", `${vaultPath(vaultId)}/files/${enc(fileId)}`);
	}
	revision(vaultId: string, fileId: string, rev: number): Promise<Revision> {
		return this.call("GET", `${vaultPath(vaultId)}/files/${enc(fileId)}/revs/${rev}`);
	}
	/** Newest first. Pass the last `rev` of a page as `before` for the next one. */
	revisions(vaultId: string, fileId: string, before?: number, limit = 50): Promise<History> {
		const query = `limit=${limit}${before === undefined ? "" : `&before=${before}`}`;
		return this.call("GET", `${vaultPath(vaultId)}/files/${enc(fileId)}/revs?${query}`);
	}
	changes(vaultId: string, since: number, limit = 500): Promise<Changes> {
		return this.call("GET", `${vaultPath(vaultId)}/changes?since=${since}&limit=${limit}`);
	}
	/** Also returns when the keyring version passes `keyringSince`, if given. */
	wait(vaultId: string, since: number, locksSince: number, timeout = 25, keyringSince?: number): Promise<WaitResponse> {
		const keyring = keyringSince === undefined ? "" : `&keyringSince=${keyringSince}`;
		const query = `since=${since}&locksSince=${locksSince}&timeout=${timeout}${keyring}`;
		return this.call("GET", `${vaultPath(vaultId)}/wait?${query}`);
	}

	// Locks (protocol.md 11)
	locks(vaultId: string): Promise<Locks> {
		return this.call("GET", `${vaultPath(vaultId)}/locks`);
	}
	/** Acquire or renew. Throws `ApiError` `locked` (423) with `details.lock` if another holder has it. */
	lock(vaultId: string, fileId: string, clientId: string, ttl: number): Promise<Lock> {
		return this.call("POST", `${vaultPath(vaultId)}/locks/${enc(fileId)}`, { json: { clientId, ttl } });
	}
	async unlock(vaultId: string, fileId: string, clientId: string): Promise<void> {
		await this.call("DELETE", `${vaultPath(vaultId)}/locks/${enc(fileId)}?clientId=${enc(clientId)}`);
	}

	/** An authenticated call. Logs in first if needed, and again once if the token expired. */
	private async call<T>(method: string, path: string, body?: Body): Promise<T> {
		const response = await this.raw(method, path, body);
		return (response.body.byteLength ? JSON.parse(fromUtf8(new Uint8Array(response.body))) : undefined) as T;
	}

	private async raw(method: string, path: string, body?: Body): Promise<HttpResponse> {
		if (this.token === null) await this.login();
		try {
			return await this.request(method, path, body, this.token);
		} catch (e) {
			if (!(e instanceof ApiError) || e.status !== 401) throw e;
			await this.login();
			return this.request(method, path, body, this.token);
		}
	}

	private async send<T>(method: string, path: string, body?: Body): Promise<T> {
		const response = await this.request(method, path, body, null);
		return JSON.parse(fromUtf8(new Uint8Array(response.body))) as T;
	}

	private async request(method: string, path: string, body: Body, token: string | null): Promise<HttpResponse> {
		const headers: Record<string, string> = {};
		if (token !== null) headers["Authorization"] = `Bearer ${token}`;
		let payload: string | ArrayBuffer | undefined;
		if (body && "json" in body) {
			headers["Content-Type"] = "application/json";
			payload = JSON.stringify(body.json);
		} else if (body) {
			headers["Content-Type"] = "application/octet-stream";
			payload = body.bytes.slice().buffer;
		}
		let response: HttpResponse;
		let timer: number | undefined;
		const timeout = new Promise<never>((_, reject) => {
			timer = window.setTimeout(() => reject(new Error("timed out")), this.opts.timeoutMs ?? REQUEST_TIMEOUT_MS);
		});
		try {
			const request = this.opts.transport({ method, url: this.origin + path, headers, body: payload });
			response = await Promise.race([request, timeout]);
		} catch (e) {
			throw new NetworkError("Can't reach the server.", { cause: e });
		} finally {
			window.clearTimeout(timer);
		}
		checkServerVersion(response);
		if (response.status >= 200 && response.status < 300) return response;
		throw errorFrom(response);
	}
}

function enc(segment: string): string {
	return encodeURIComponent(segment);
}

function vaultPath(vaultId: string): string {
	return `/api/v1/vaults/${enc(vaultId)}`;
}

function checkServerVersion(response: HttpResponse): void {
	const version = response.headers[VERSION_HEADER];
	if (version === undefined) {
		throw new NetworkError("The endpoint didn't answer like a Vault Syncryption server.");
	}
	if (Number(version.split(".")[0]) !== SERVER_MAJOR) {
		throw new ApiError(
			0,
			"version_mismatch",
			`The server runs Vault Syncryption ${version}, which this plugin doesn't support. Update the plugin or the server.`,
		);
	}
}

function errorFrom(response: HttpResponse): ApiError {
	let parsed: { error?: unknown; message?: unknown; details?: unknown } = {};
	try {
		parsed = JSON.parse(fromUtf8(new Uint8Array(response.body))) as typeof parsed;
	} catch {
		// not JSON: a proxy error page, for example
	}
	const code = typeof parsed.error === "string" ? parsed.error : `http_${response.status}`;
	const message = typeof parsed.message === "string" ? parsed.message : `Request failed (${response.status}).`;
	const details =
		typeof parsed.details === "object" && parsed.details !== null
			? (parsed.details as Record<string, unknown>)
			: {};
	const retryAfter = Number(response.headers["retry-after"]);
	return new ApiError(response.status, code, message, details, Number.isFinite(retryAfter) ? retryAfter : undefined);
}
