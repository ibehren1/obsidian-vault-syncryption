/** The remote-only compliance report (docs/remote-only.md 10), from what the device measured. */

/** Local storage: this device is remote-only for this vault. */
export interface RemoteOnlyFlag {
	vaultId: string;
}

/** One line of the compliance report. */
export interface ComplianceCheck {
	name: string;
	ok: boolean;
	detail: string;
}

export interface ComplianceReport {
	/** The keyring's policy when connected, else what this device remembers. */
	remoteOnly: boolean;
	/** Where `remoteOnly` comes from. */
	source: "keyring" | "this device";
	compliant: boolean;
	checks: ComplianceCheck[];
	/** Name and value pairs that aren't pass or fail. */
	facts: Array<[string, string]>;
}

export interface ComplianceFacts {
	/** The keyring's policy for this device, or null when not connected. */
	keyringRemoteOnly: boolean | null;
	flag: RemoteOnlyFlag | null;
	installed: boolean;
	locked: boolean;
	/** When the lease was last renewed (a login), and the grace period. */
	lease: { at: number; graceSeconds: number } | null;
	now: number;
	/** Remote-only paths on disk, and those of them that aren't empty stubs. */
	remoteFiles: number;
	plaintext: string[];
	storeEntries: number;
	/** Store entries without a file, and files without a store entry. */
	orphans: number;
	missing: number;
	fileRecovery: boolean;
	/** Plaintext content hashes in the sync state, or null without it. */
	plainHashes: number | null;
}

/** How many paths a check lists before it counts the rest. */
const LISTED = 5;

function list(paths: string[]): string {
	const shown = paths.slice(0, LISTED).join(", ");
	return paths.length > LISTED ? `${shown} and ${paths.length - LISTED} more` : shown;
}

export function duration(ms: number): string {
	const minutes = Math.max(0, Math.round(ms / 60_000));
	if (minutes < 60) return `${minutes} min`;
	const hours = Math.floor(minutes / 60);
	return minutes % 60 ? `${hours} h ${minutes % 60} min` : `${hours} h`;
}

/** The checks of the compliance report (docs/remote-only.md 10), from what was measured. */
export function complianceReport(f: ComplianceFacts): ComplianceReport {
	const remoteOnly = f.keyringRemoteOnly ?? f.flag !== null;
	const source = f.keyringRemoteOnly === null ? "this device" : "keyring";
	const facts: Array<[string, string]> = [];
	if (!remoteOnly) {
		const checks: ComplianceCheck[] = [];
		// A full device that still holds remote-only files converts them back at the next connection.
		if (f.flag) checks.push({ name: "Remote-only files", ok: false, detail: "Still stubs. They are restored at the next connection." });
		return { remoteOnly, source, compliant: checks.length === 0, checks, facts };
	}
	const checks: ComplianceCheck[] = [
		{
			name: "Policy remembered on this device",
			ok: f.flag !== null,
			detail: f.flag ? "Yes: the files stay locked until the server is reached." : "No: connect to apply the policy.",
		},
		{
			name: "Adapter wrapper",
			ok: f.installed,
			detail: f.installed ? "Installed: Obsidian reads remote-only files through it." : "Not installed.",
		},
		{
			name: "No plaintext on disk",
			ok: f.plaintext.length === 0,
			detail: f.plaintext.length === 0 ? `All ${f.remoteFiles} files are empty stubs.` : `Not empty on disk: ${list(f.plaintext)}.`,
		},
		{
			name: "File Recovery core plugin",
			ok: !f.fileRecovery,
			detail: f.fileRecovery ? "Enabled: it keeps plaintext snapshots. Turn it off." : "Off.",
		},
	];
	if (f.plainHashes !== null) {
		checks.push({
			name: "Content hashes sealed",
			ok: f.plainHashes === 0,
			detail: f.plainHashes === 0 ? "Yes." : `${f.plainHashes} stored in plaintext. They are sealed while unlocked.`,
		});
	}
	const left = f.lease ? f.lease.at + f.lease.graceSeconds * 1000 - f.now : null;
	checks.push({
		name: "Lease",
		ok: f.locked || (left !== null && left > 0),
		detail: f.locked ? "Locked." : left !== null && left > 0 ? `Valid for ${duration(left)}.` : "Expired, but not locked.",
	});

	facts.push(["State", f.locked ? "Locked: remote-only files can't be read" : "Unlocked"]);
	if (f.lease) {
		facts.push(["Lease renewed", new Date(f.lease.at).toLocaleString()]);
		facts.push(["Grace period", duration(f.lease.graceSeconds * 1000)]);
	} else {
		facts.push(["Lease renewed", "Not since Obsidian started"]);
	}
	facts.push(["Remote-only files", String(f.remoteFiles)]);
	facts.push(["Encrypted on this device", String(f.storeEntries)]);
	if (f.missing) facts.push(["Empty files without stored content", String(f.missing)]);
	if (f.orphans) facts.push(["Stored content without a file", String(f.orphans)]);
	facts.push(["Keyring and vault key", "In memory only, never stored"]);
	return { remoteOnly, source, compliant: checks.every((c) => c.ok), checks, facts };
}
