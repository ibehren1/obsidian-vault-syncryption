/** How a vault key is described, in the settings tab and the status window. */
import type { Device } from "../api/client";

export interface VaultKey {
	id: string;
	name: string;
	publicKey: string;
	added: string;
	self: boolean;
	/** Remote-only in the keyring (remote-only.md 4). */
	remoteOnly?: boolean;
}

/** "Laptop · added 3/10/2026 · remote-only · This device" */
export function keyDescription(key: VaultKey): string {
	const parts = [key.name, `added ${formatDate(key.added)}`];
	if (key.remoteOnly) parts.push("remote-only");
	if (key.self) parts.push("This device");
	return parts.join(" · ");
}

/** The server's view of a key: active (or locked) and last seen, waiting for approval, or revoked. */
export function keyServerStatus(device: Device | undefined): string {
	if (!device) return "Not on the server";
	if (device.status === "active") {
		const state = device.locked ? "Locked" : "Active";
		return device.lastSeenAt ? `${state} · last seen ${formatDate(device.lastSeenAt)}` : state;
	}
	return device.status === "pending" ? "Waiting for approval" : "Revoked";
}

/** How a key's state is shown: the dot's colour in the status window's key table. */
export type KeyStateKind = "ok" | "warn" | "off" | "error" | "unknown";

/** The same state as `keyServerStatus`, split for a table: a dot, a word and "last seen". */
export function keyServerState(device: Device | undefined): { label: string; kind: KeyStateKind } {
	if (!device) return { label: "Not on the server", kind: "unknown" };
	if (device.status === "active") {
		return device.locked ? { label: "Locked", kind: "off" } : { label: "Active", kind: "ok" };
	}
	return device.status === "pending" ? { label: "Waiting for approval", kind: "warn" } : { label: "Revoked", kind: "error" };
}

/** A date in the user's locale. */
export function formatDate(iso: string): string {
	const date = new Date(iso);
	return Number.isNaN(date.getTime()) ? iso : date.toLocaleDateString();
}
