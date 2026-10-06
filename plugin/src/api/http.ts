/** The HTTP layer under the API client, so tests can use `fetch` (tests/harness.ts) and the plugin `requestUrl`. */

export interface HttpRequest {
	method: string;
	url: string;
	headers: Record<string, string>;
	body?: string | ArrayBuffer;
}

export interface HttpResponse {
	status: number;
	/** Header names in lower case. */
	headers: Record<string, string>;
	body: ArrayBuffer;
}

/** Sends a request and resolves with any status. Rejects only when there is no response. */
export type Transport = (request: HttpRequest) => Promise<HttpResponse>;

/** A non-2xx response (docs/protocol.md 1). `code` is the server's stable `error` code. */
export class ApiError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
		message: string,
		readonly details: Record<string, unknown> = {},
		/** Seconds, from `Retry-After` (on `429` and the maintenance `503`). */
		readonly retryAfter?: number,
	) {
		super(message);
		this.name = "ApiError";
	}
}

/** The server administrator disabled this user or vault (protocol.md 14): retrying won't help. */
export function isDisabled(e: unknown): e is ApiError {
	return e instanceof ApiError && (e.code === "user_disabled" || e.code === "vault_disabled");
}

/**
 * The administrator put the server in maintenance (`503 maintenance`): every request is
 * refused until it ends. A temporary pause, not an error: keep the session and retry.
 */
export function isMaintenance(e: unknown): e is ApiError {
	return e instanceof ApiError && e.code === "maintenance";
}

/** The admin's free-text contact, if the server sent one (maintenance and disabled errors). */
export function adminContact(details: Record<string, unknown>): string | null {
	return text(details["adminContact"]);
}

/** The user-facing text for maintenance, from the error's `details` (`note`, `adminContact`). */
export function maintenanceText(details: Record<string, unknown>): string {
	const parts = ["The server is in maintenance, so sync is paused. It resumes by itself."];
	const note = text(details["note"]);
	if (note) parts.push(sentence(note));
	const contact = adminContact(details);
	parts.push(contact ? `For help, contact the server admin: ${sentence(contact)}` : "For help or info, contact your server admin.");
	return parts.join(" ");
}

/** A disabled user's or vault's message, with the admin's contact when the server sent one. */
export function disabledText(e: ApiError): string {
	const contact = adminContact(e.details);
	return contact ? `${sentence(e.message)} Contact the server admin: ${sentence(contact)}` : e.message;
}

function text(value: unknown): string | null {
	return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

/** End with a full stop unless the text already ends with punctuation. */
function sentence(s: string): string {
	return /[.!?]$/.test(s) ? s : `${s}.`;
}

/** The server couldn't be reached, or the response wasn't one we understand. */
export class NetworkError extends Error {
	constructor(message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.name = "NetworkError";
	}
}
