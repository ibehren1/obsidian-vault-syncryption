/** How a vault key is described, in the settings tab and the status window. */
import type { Device } from "../api/client";

export interface VaultKey {
	id: string;
	name: string;
	publicKey: string;
	added: string;
	self: boolean;
}

/** "Laptop · added 3/10/2026 · This device" */
export function keyDescription(key: VaultKey): string {
	const parts = [key.name, `added ${formatDate(key.added)}`];
	if (key.self) parts.push("This device");
	return parts.join(" · ");
}

/** The server's view of a key: active and last seen, waiting for approval, or revoked. */
export function keyServerStatus(device: Device | undefined): string {
	if (!device) return "Not on the server";
	if (device.status === "active") return device.lastSeenAt ? `Active · last seen ${formatDate(device.lastSeenAt)}` : "Active";
	return device.status === "pending" ? "Waiting for approval" : "Revoked";
}

/** A date in the user's locale. */
export function formatDate(iso: string): string {
	const date = new Date(iso);
	return Number.isNaN(date.getTime()) ? iso : date.toLocaleDateString();
}
