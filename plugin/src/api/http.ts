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
		/** Seconds, from `Retry-After` on `429`. */
		readonly retryAfter?: number,
	) {
		super(message);
		this.name = "ApiError";
	}
}

/** The server couldn't be reached, or the response wasn't one we understand. */
export class NetworkError extends Error {
	constructor(message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.name = "NetworkError";
	}
}
