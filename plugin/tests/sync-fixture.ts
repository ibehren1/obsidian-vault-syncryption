/** Two devices of one user syncing one vault against the real backend. */
import { MemoryStore } from "../src/store/state";
import { VaultCipher } from "../src/sync/cipher";
import { SyncEngine } from "../src/sync/engine";
import { pathFilter } from "../src/sync/filter";
import { MemoryFs } from "../src/sync/fs";
import { connect, type VaultSession } from "../src/sync/session";
import { client, newSeed, SHARED_SECRET, uniqueName } from "./harness";

export interface Device {
	name: string;
	session: VaultSession;
	fs: MemoryFs;
	store: MemoryStore;
	engine: SyncEngine;
	warnings: string[];
}

export function engineFor(session: VaultSession, fs: MemoryFs, name: string, warnings: string[]): SyncEngine {
	return new SyncEngine({
		api: session.api,
		vaultId: session.vault.id,
		cipher: new VaultCipher(() => session.keyring),
		fs,
		store: session.store,
		deviceId: session.deviceId,
		deviceName: name,
		include: pathFilter({ configDir: ".obsidian" }),
		configDir: ".obsidian",
		keyring: { version: () => session.keyring.version, refresh: () => session.refreshKeyring() },
		onWarning: (m) => warnings.push(m),
	});
}

export async function device(username: string, vaultName: string, name: string, seed = newSeed()): Promise<Device> {
	const store = new MemoryStore();
	// Join directly, without the join_required round trip.
	const api = client(username, seed, name);
	await api.login(SHARED_SECRET);
	const session = await connect({
		api,
		vaultName,
		deviceName: name,
		seed,
		openStore: async () => store,
		callbacks: {
			askSharedSecret: async () => null,
			showPairing: () => {},
		},
		pollMs: 20,
	});
	const fs = new MemoryFs();
	const warnings: string[] = [];
	return { name, session, fs, store, engine: engineFor(session, fs, name, warnings), warnings };
}

/** Connects a second device and approves it from `first` once it waits. */
export async function pairedDevice(
	first: Device,
	username: string,
	vaultName: string,
	name: string,
	seed = newSeed(),
): Promise<Device> {
	const second = device(username, vaultName, name, seed);
	let failed: unknown = null;
	second.catch((e: unknown) => (failed = e ?? new Error("device setup failed")));
	for (;;) {
		if (failed) throw failed;
		const pending = await first.session.pendingMembers();
		if (pending.length) {
			await first.session.approve(pending[0]!.member);
			break;
		}
		await new Promise((r) => setTimeout(r, 20));
	}
	return second;
}

export async function twoDevices(): Promise<[Device, Device]> {
	const username = uniqueName("sync");
	const vaultName = uniqueName("Vault ");
	const a = await device(username, vaultName, "Laptop");
	const b = await pairedDevice(a, username, vaultName, "Phone");
	return [a, b];
}
