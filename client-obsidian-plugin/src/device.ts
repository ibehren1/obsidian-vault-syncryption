/** The device name: a friendly label for lock warnings and the device lists (protocol.md 5.2). */

/** The server's limit for `deviceName`. */
export const MAX_DEVICE_NAME = 64;

/** The parts of Obsidian's `Platform` the default name depends on. */
export interface DevicePlatform {
	isDesktopApp: boolean;
	isIosApp: boolean;
	isAndroidApp: boolean;
	isTablet: boolean;
	isMacOS: boolean;
	isWin: boolean;
	isLinux: boolean;
}

/** The OS hostname on desktop, where Electron exposes Node. Mobile has no hostname API. */
export function desktopHostname(platform: DevicePlatform): string {
	if (!platform.isDesktopApp) return "";
	try {
		const nodeRequire = (window as { require?: (id: string) => { hostname(): string } }).require;
		return nodeRequire?.("os").hostname() ?? "";
	} catch {
		return "";
	}
}

/** Trimmed and cut to the server's limit; empty if nothing is left. */
export function cleanDeviceName(name: string): string {
	return name.trim().slice(0, MAX_DEVICE_NAME).trim();
}

/** The hostname without its domain (`Isaacs-MacBook.local` becomes `Isaacs-MacBook`), else the platform. */
export function defaultDeviceName(platform: DevicePlatform, hostname: string): string {
	const host = cleanDeviceName(hostname.split(".")[0] ?? "");
	if (host !== "") return host;
	if (platform.isIosApp) return platform.isTablet ? "iPad" : "iPhone";
	if (platform.isAndroidApp) return platform.isTablet ? "Android tablet" : "Android phone";
	if (platform.isMacOS) return "Mac";
	if (platform.isWin) return "Windows";
	if (platform.isLinux) return "Linux";
	return "Obsidian";
}

/** The comment of a new device key: `syncryption alice@Isaacs-MacBook`, whitespace as `-`. */
export function keyComment(username: string, deviceName: string): string {
	const device = cleanDeviceName(deviceName).replace(/\s+/g, "-");
	return device === "" ? `syncryption ${username}` : `syncryption ${username}@${device}`;
}
