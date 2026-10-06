import { describe, expect, it } from "vitest";

import { cleanDeviceName, defaultDeviceName, desktopHostname, keyComment, MAX_DEVICE_NAME, type DevicePlatform } from "../src/device";

const none: DevicePlatform = {
	isDesktopApp: false,
	isIosApp: false,
	isAndroidApp: false,
	isTablet: false,
	isMacOS: false,
	isWin: false,
	isLinux: false,
};

describe("device name", () => {
	it("uses the hostname without its domain", () => {
		const mac = { ...none, isDesktopApp: true, isMacOS: true };
		expect(defaultDeviceName(mac, "Isaacs-MacBook-Pro.local")).toBe("Isaacs-MacBook-Pro");
		expect(defaultDeviceName(mac, " desk.example.com ")).toBe("desk");
		expect(defaultDeviceName(mac, "x".repeat(100))).toHaveLength(MAX_DEVICE_NAME);
	});

	it("falls back to the platform without a hostname", () => {
		expect(defaultDeviceName({ ...none, isIosApp: true }, "")).toBe("iPhone");
		expect(defaultDeviceName({ ...none, isIosApp: true, isTablet: true }, "")).toBe("iPad");
		expect(defaultDeviceName({ ...none, isAndroidApp: true }, "")).toBe("Android phone");
		expect(defaultDeviceName({ ...none, isDesktopApp: true, isWin: true }, ".")).toBe("Windows");
		expect(defaultDeviceName(none, "")).toBe("Obsidian");
	});

	it("reads the hostname only on desktop", () => {
		const win = window as { require?: unknown };
		const saved = win.require;
		win.require = (id: string) => ({ hostname: () => `${id}-host` });
		try {
			expect(desktopHostname({ ...none, isDesktopApp: true })).toBe("os-host");
			expect(desktopHostname({ ...none, isIosApp: true })).toBe("");
			win.require = () => {
				throw new Error("no os");
			};
			expect(desktopHostname({ ...none, isDesktopApp: true })).toBe("");
		} finally {
			win.require = saved;
		}
	});

	it("cleans user input", () => {
		expect(cleanDeviceName("  Work laptop  ")).toBe("Work laptop");
		expect(cleanDeviceName("   ")).toBe("");
	});

	it("names the key after the user and device", () => {
		expect(keyComment("alice", " Work laptop ")).toBe("syncryption alice@Work-laptop");
		expect(keyComment("alice", "   ")).toBe("syncryption alice");
		expect(keyComment("alice", "x".repeat(100))).toBe(`syncryption alice@${"x".repeat(MAX_DEVICE_NAME)}`);
	});
});
