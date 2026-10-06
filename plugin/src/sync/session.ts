/**
 * Connecting to a vault (docs/protocol.md 5 and 7, crypto.md 6): log in or join, open or
 * create the vault, wait for pairing or recover with the recovery key, and fetch and verify
 * the keyring. Also approving other keys (the active side of pairing), removing keys,
 * replacing this device's key and setting the recovery key. A key (a "device" in the API)
 * is one device in one vault.
 */
import { ed25519 } from "@noble/curves/ed25519.js";

import type { ApiClient, Device, KeyringObject, Vault } from "../api/client";
import { ApiError } from "../api/http";
import { fromB64u, toB64u } from "../crypto/bytes";
import {
	addKeyringDevice,
	createKeyring,
	KeyringError,
	openKeyring,
	openKeyringChain,
	openKeyringWithRecovery,
	recoverySigningSeed,
	removeKeyringDeviceAndRotate,
	sealKeyring,
	setKeyringRecovery,
	type Keyring,
	type KeyringBlob,
	type KeyringPin,
	type TrustedKeyring,
} from "../crypto/keyring";
import { pairingCode, parsePublicKeyText, publicKeyText } from "../crypto/openssh";
import type { SyncStore } from "../store/state";

export const PIN = "keyringPin";
export const VAULT_ID = "vaultId";
/** Store meta: the device whose key this device replaced, until it is removed (`handOver`). */
export const REPLACED = "replacedDevice";
const PAIRING_POLL_MS = 5000;

export interface ConnectCallbacks {
	/** The server needs the shared secret to join. Resolve with null if the user cancels. */
	askSharedSecret(): Promise<string | null>;
	/**
	 * This device must be approved from an active device. Called once with the code to show,
	 * then the session polls until it is approved or `signal` is aborted. `recover` is set
	 * when the vault exists: it adds this device with the vault's recovery key instead
	 * (crypto.md 9), and the session goes on at the next poll.
	 */
	showPairing(code: string, recover?: (identity: string) => Promise<void>): void;
}

export interface ConnectOptions {
	/** Logged in, or to log in, to the vault named by `api.vaultName`. */
	api: ApiClient;
	deviceName: string;
	seed: Uint8Array;
	/** Opens the local state for a vault id (one store per remote vault). */
	openStore(vaultId: string): Promise<SyncStore>;
	callbacks: ConnectCallbacks;
	signal?: AbortSignal;
	pollMs?: number;
}

export class SetupCancelled extends Error {
	constructor(message = "Setup was cancelled.") {
		super(message);
		this.name = "SetupCancelled";
	}
}

/** A connected vault: the keyring is verified and pinned. */
export class VaultSession {
	constructor(
		readonly api: ApiClient,
		readonly vault: Vault,
		readonly store: SyncStore,
		private trusted: TrustedKeyring,
		private readonly seed: Uint8Array,
	) {}

	get keyring() {
		return this.trusted.keyring;
	}

	get deviceId(): string {
		return this.api.deviceId!;
	}

	/** Fetch the latest keyring and check it against the pinned one (crypto.md 6.4). */
	async refreshKeyring(): Promise<void> {
		this.trusted = await fetchTrusted(this.api, this.vault, this.seed, this.trusted);
		await this.store.setMeta(PIN, this.trusted.pin);
	}

	/** Every key of this vault on the server, revoked ones included. */
	devices(): Promise<Device[]> {
		return this.api.devices(this.vault.id);
	}

	/** Keys waiting for approval, with the pairing code computed here, not by the server. */
	async pendingDevices(): Promise<Array<{ device: Device; code: string }>> {
		const devices = await this.devices();
		return devices
			.filter((d) => d.status === "pending")
			.map((device) => ({ device, code: pairingCode(parsePublicKeyText(device.publicKey)) }));
	}

	/**
	 * Pairing, active side (crypto.md 6.5): add the key to the keyring, upload it signed,
	 * then approve it. The user must have compared the pairing codes.
	 */
	async approve(device: Pick<Device, "id" | "name" | "publicKey">): Promise<void> {
		const key = publicKeyText(parsePublicKeyText(device.publicKey));
		await this.update((k) =>
			k.devices.some((d) => d.publicKey === key)
				? null
				: addKeyringDevice(k, { id: device.id, name: device.name, publicKey: key }, this.deviceId),
		);
		await this.api.approveDevice(this.vault.id, device.id);
	}

	/**
	 * Revocation (crypto.md 8.4): revoke the key on the server first, then remove it from
	 * the keyring with a new epoch. Other devices re-encrypt their files in the background.
	 */
	async removeDevice(deviceId: string): Promise<void> {
		if (deviceId === this.deviceId) throw new Error("This device can't remove its own key.");
		try {
			await this.api.removeDevice(this.vault.id, deviceId);
		} catch (e) {
			// Already gone from the server: the keyring still has to follow.
			if (!(e instanceof ApiError && e.status === 404)) throw e;
		}
		await this.rotateOut([deviceId]);
	}

	/**
	 * Finish revocations done elsewhere: remove keyring devices whose key is revoked or gone
	 * on the server (a rotation that didn't finish). Returns their names.
	 */
	async removeStaleDevices(): Promise<string[]> {
		const status = new Map((await this.devices()).map((d) => [d.id, d.status]));
		await this.refreshKeyring();
		const stale = this.keyring.devices.filter(
			(d) => d.id !== this.deviceId && (status.get(d.id) ?? "revoked") === "revoked",
		);
		if (stale.length === 0) return [];
		await this.rotateOut(stale.map((d) => d.id));
		return stale.map((d) => d.name);
	}

	/**
	 * After a key change (`handOver`): remove the replaced key, if this is the new one.
	 * Returns whether it removed one. Kept in the store until done, so it is retried.
	 */
	async finishReplace(): Promise<boolean> {
		const old = await this.store.getMeta<string | null>(REPLACED);
		if (!old) return false;
		const removed = old !== this.deviceId;
		if (removed) await this.removeDevice(old);
		await this.store.setMeta(REPLACED, null);
		return removed;
	}

	private async rotateOut(ids: string[]): Promise<void> {
		await this.update((k) => {
			const gone = ids.filter((id) => k.devices.some((d) => d.id === id));
			return gone.length === 0 ? null : removeKeyringDeviceAndRotate(k, gone, this.deviceId);
		});
	}

	/** Set this device's recovery key, or remove the recovery key (crypto.md 9). */
	async setRecovery(recovery: { recipient: string; signer: string } | undefined): Promise<void> {
		await this.update((k) => setKeyringRecovery(k, recovery, this.deviceId));
	}

	/**
	 * Upload the next keyring version built from the latest one by `change` (null: nothing
	 * to do), then refresh. Starts again if another device uploaded a version first.
	 */
	private async update(change: (k: Keyring) => Keyring | null): Promise<void> {
		for (let attempt = 0; ; attempt++) {
			await this.refreshKeyring();
			const next = change(this.keyring);
			if (next === null) return;
			try {
				await this.api.putKeyring(this.vault.id, upload(await sealKeyring(next, this.seed), next, this.deviceId));
				break;
			} catch (e) {
				if (!(e instanceof ApiError && e.code === "keyring_version") || attempt >= 3) throw e;
			}
		}
		await this.refreshKeyring();
	}
}

function upload(blob: KeyringBlob, keyring: Keyring, signer: string) {
	return {
		version: blob.version,
		keyring: toB64u(blob.keyring),
		signature: blob.signature,
		signer,
		recoverySigner: keyring.recoverySigner ?? null,
	};
}

function blobFrom(object: KeyringObject): KeyringBlob {
	return { version: object.version, keyring: fromB64u(object.keyring), signature: object.signature };
}

async function fetchTrusted(
	api: ApiClient,
	vault: Vault,
	seed: Uint8Array,
	trusted: TrustedKeyring | undefined,
): Promise<TrustedKeyring> {
	const ctx = { seed, vaultId: vault.id, name: vault.name };
	const latest = blobFrom(await api.keyring(vault.id));
	if (!trusted) return openKeyring(latest, ctx);
	if (latest.version <= trusted.pin.version + 1) return openKeyring(latest, ctx, trusted);
	const blobs = [latest];
	for (let v = trusted.pin.version + 1; v < latest.version; v++) blobs.push(blobFrom(await api.keyring(vault.id, v)));
	return openKeyringChain(blobs, ctx, trusted);
}

/** Log in, asking for the shared secret if the server needs it to let this key join. */
export async function login(api: ApiClient, callbacks: ConnectCallbacks): Promise<void> {
	try {
		await api.login();
	} catch (e) {
		if (!(e instanceof ApiError && e.code === "join_required")) throw e;
		const secret = await callbacks.askSharedSecret();
		if (secret === null) throw new SetupCancelled();
		await api.login(secret);
	}
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
	return new Promise((resolve, reject) => {
		if (signal?.aborted) return reject(new SetupCancelled());
		const timer = window.setTimeout(resolve, ms);
		signal?.addEventListener("abort", () => {
			window.clearTimeout(timer);
			reject(new SetupCancelled());
		});
	});
}

/**
 * Connect to the configured vault, creating it if it doesn't exist yet. Logs in first
 * unless `api` already has.
 */
export async function connect(opts: ConnectOptions): Promise<VaultSession> {
	const { api, seed, callbacks, signal } = opts;
	// The server stores names like this, and the keyring must name the vault the same way.
	const vaultName = api.vaultName;
	const pollMs = opts.pollMs ?? PAIRING_POLL_MS;
	if (api.deviceId === null) await login(api, callbacks);
	const myKey = publicKeyText(ed25519.getPublicKey(seed));

	let vault: Vault;
	let shownPairing = false;
	const pair = async (pending?: Vault) => {
		if (!shownPairing) {
			const recover = pending && ((identity: string) => recoverVault(api, pending, seed, opts.deviceName, identity));
			callbacks.showPairing(pairingCode(ed25519.getPublicKey(seed)), recover);
		}
		shownPairing = true;
		await sleep(pollMs, signal);
	};
	for (;;) {
		let opened;
		try {
			opened = await api.openVault(vaultName);
		} catch (e) {
			if (e instanceof ApiError && e.code === "not_found") {
				try {
					// Only the key that joined with the shared secret gets here (protocol.md 5).
					vault = await create(api, vaultName, myKey, opts.deviceName, seed);
				} catch (err) {
					if (err instanceof ApiError && err.code === "exists") continue; // created meanwhile
					throw err;
				}
				break;
			}
			throw e;
		}
		if (opened.membership === "active") {
			vault = opened.vault;
			break;
		}
		await pair(opened.vault);
	}

	const store = await opts.openStore(vault.id);
	if ((await store.getMeta<string>(VAULT_ID)) !== vault.id) {
		await store.clear();
		await store.setMeta(VAULT_ID, vault.id);
	}
	const pin = await store.getMeta<KeyringPin>(PIN);
	let trusted: TrustedKeyring;
	for (;;) {
		try {
			trusted = await fetchTrusted(api, vault, seed, pin && (await pinnedKeyring(api, vault, seed, pin)));
			break;
		} catch (e) {
			// Membership is approved after the keyring is uploaded, but don't rely on it.
			if (!(e instanceof KeyringError && e.code === "not-a-recipient")) throw e;
			await pair(vault);
		}
	}
	await store.setMeta(PIN, trusted.pin);
	return new VaultSession(api, vault, store, trusted, seed);
}

/** Re-open the pinned keyring version so newer versions can be checked against it. */
async function pinnedKeyring(
	api: ApiClient,
	vault: Vault,
	seed: Uint8Array,
	pin: KeyringPin,
): Promise<TrustedKeyring> {
	const blob = blobFrom(await api.keyring(vault.id, pin.version));
	const opened = await openKeyring(blob, { seed, vaultId: vault.id, name: vault.name });
	if (opened.pin.sha256 !== pin.sha256) {
		throw new KeyringError("rollback", "server keyring differs from the pinned one");
	}
	return opened;
}

async function create(
	api: ApiClient,
	name: string,
	publicKey: string,
	deviceName: string,
	seed: Uint8Array,
): Promise<Vault> {
	const vaultId = crypto.randomUUID();
	const keyring = createKeyring({ vaultId, name, device: { id: api.deviceId!, name: deviceName, publicKey } });
	const sealed = await sealKeyring(keyring, seed);
	return api.createVault(vaultId, name, upload(sealed, keyring, api.deviceId!));
}

/**
 * Replace this device's key, active side (PLAN, Rules: Replace). `old` is the connected
 * session of the current key, `api` a client for the new key, which isn't saved yet.
 *
 * 1. The new key logs in once, so the server knows it as a pending key of the vault.
 * 2. The old key adds it to the keyring and approves it. Both keys now work, and the
 *    store's keyring pin is a version the new key can open.
 * 3. The store records the old key as replaced. The caller then saves the new key, and
 *    the new key's session removes the old one (`finishReplace`) and rotates the vault key.
 *
 * Until the caller saves the new key, the old one keeps working; after, the new one does.
 * A failure in between leaves an extra key in the vault, removable from any device.
 */
export async function handOver(old: VaultSession, api: ApiClient, deviceName: string): Promise<void> {
	if (api.origin !== old.api.origin || api.username !== old.api.username || api.vaultName !== old.api.vaultName) {
		throw new Error("The new key must be for the same vault.");
	}
	const joined = await api.login();
	if (joined.vaultId !== null && joined.vaultId !== old.vault.id) throw new Error("The new key joined another vault.");
	await old.approve({ id: joined.deviceId, name: deviceName, publicKey: publicKeyText(api.publicKey) });
	await old.store.setMeta(REPLACED, old.deviceId);
}

/**
 * Recovery (crypto.md 9): open the current keyring with the recovery identity, add this
 * device, and upload the next version signed by the recovery key. The server then activates
 * this device's membership.
 */
async function recoverVault(
	api: ApiClient,
	vault: Vault,
	seed: Uint8Array,
	deviceName: string,
	identity: string,
): Promise<void> {
	const signing = recoverySigningSeed(identity);
	const publicKey = publicKeyText(ed25519.getPublicKey(seed));
	try {
		for (let attempt = 0; ; attempt++) {
			const current = blobFrom(await api.recoveryKeyring(vault.id));
			const { keyring } = await openKeyringWithRecovery(current, { identity, vaultId: vault.id, name: vault.name });
			if (keyring.devices.some((d) => d.publicKey === publicKey)) {
				throw new Error("This device is already in the keyring. Approve it from another device.");
			}
			const next = addKeyringDevice(keyring, { id: api.deviceId!, name: deviceName, publicKey }, api.deviceId!);
			try {
				await api.recover(vault.id, upload(await sealKeyring(next, signing), next, api.deviceId!));
				return;
			} catch (e) {
				if (!(e instanceof ApiError && e.code === "keyring_version") || attempt >= 3) throw e;
			}
		}
	} finally {
		signing.fill(0);
	}
}
