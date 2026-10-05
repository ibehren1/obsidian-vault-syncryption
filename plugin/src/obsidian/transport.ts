/** The plugin's HTTP transport: Obsidian's `requestUrl`, which works on desktop and mobile. */
import { requestUrl } from "obsidian";

import type { Transport } from "../api/http";

export const requestUrlTransport: Transport = async (request) => {
	const contentType = Object.entries(request.headers).find(([name]) => name.toLowerCase() === "content-type")?.[1];
	const response = await requestUrl({
		url: request.url,
		method: request.method,
		headers: request.headers,
		...(request.body !== undefined ? { body: request.body } : {}),
		...(contentType !== undefined ? { contentType } : {}),
		throw: false,
	});
	const headers: Record<string, string> = {};
	for (const [name, value] of Object.entries(response.headers)) headers[name.toLowerCase()] = value;
	return { status: response.status, headers, body: response.arrayBuffer };
};
