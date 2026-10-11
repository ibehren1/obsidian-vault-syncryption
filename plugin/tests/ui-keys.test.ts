import { describe, expect, it } from "vitest";

import type { Device } from "../src/api/client";
import { keyServerState, keyServerStatus } from "../src/ui/keys";

function device(over: Partial<Device>): Device {
	return { id: "d1", name: "Laptop", publicKey: "ssh-ed25519 AAAA", status: "active", added: "2026-01-02T00:00:00Z", ...over } as Device;
}

describe("keyServerState", () => {
	it("matches the sentence keyServerStatus makes", () => {
		const cases: Array<[Device | undefined, string, string]> = [
			[undefined, "Not on the server", "unknown"],
			[device({}), "Active", "ok"],
			[device({ locked: true }), "Locked", "off"],
			[device({ status: "pending" }), "Waiting for approval", "warn"],
			[device({ status: "revoked" }), "Revoked", "error"],
		];
		for (const [d, label, kind] of cases) {
			expect(keyServerState(d)).toEqual({ label, kind });
			expect(keyServerStatus(d)).toContain(label);
		}
	});

	it("keeps last seen out of the label, so a table can put it in its own column", () => {
		const seen = device({ lastSeenAt: "2026-10-11T10:41:07Z" });
		expect(keyServerState(seen).label).toBe("Active");
		expect(keyServerStatus(seen)).toContain("last seen");
	});
});
