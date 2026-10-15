/** The plugin's two marks: a monochrome glyph for Obsidian's chrome and the logo for dialogs. */
import { addIcon } from "obsidian";

/** The id of the glyph, for `addRibbonIcon` and `setIcon`. */
export const ICON = "vault-syncryption";

/**
 * Sync arrows around the logo's keyhole: a line glyph in `currentColor`, so it matches
 * Obsidian's own icons in every theme. The full-colour logo is too detailed at 16-18 px.
 * Obsidian's icon grid is 100x100, so the 24-unit lucide geometry is scaled by 100/24.
 */
const GLYPH = `<g transform="scale(4.1667)" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/>
<path d="M21 3v5h-5"/>
<path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/>
<path d="M8 16H3v5"/>
<circle cx="12" cy="10.5" r="1.6" fill="currentColor" stroke="none"/>
<path d="M12 11.5v3" stroke-width="2.2"/>
</g>`;

/** Called once, before anything that shows the glyph. */
export function registerIcon(): void {
	addIcon(ICON, GLYPH);
}

/**
 * The colour logo, drawn into `parent` at `size` pixels: the simplified artwork of
 * `images/vault-syncryption-small.svg`, built as DOM so it needs no bundled file.
 */
export function logo(parent: HTMLElement, size: number): SVGSVGElement {
	const svg = parent.createSvg("svg", {
		attr: { viewBox: "0 0 512 512", width: size, height: size, "aria-hidden": "true" },
		cls: "syncryption-logo",
	});
	const tile = "#2d2f31";
	const steel = "#e8eaed";
	svg.createSvg("rect", { attr: { width: 512, height: 512, rx: 112, fill: tile } });
	svg.createSvg("circle", { attr: { cx: 256, cy: 256, r: 200, fill: "#d9dbde" } });
	const arrows = svg.createSvg("g", { attr: { fill: "#B3101F" } });
	for (const d of [
		"M115.0,204.7 A150,150 0 0 1 348.3,137.8 L360.7,122.0 L376.8,216.8 L307.7,189.8 L320.0,174.0 A104,104 0 0 0 158.3,220.4 Z",
		"M397.0,307.3 A150,150 0 0 1 163.7,374.2 L151.3,390.0 L135.2,295.2 L204.3,322.2 L192.0,338.0 A104,104 0 0 0 353.7,291.6 Z",
	]) {
		arrows.createSvg("path", { attr: { d } });
	}
	svg.createSvg("circle", { attr: { cx: 256, cy: 256, r: 64, fill: tile } });
	const keyhole = svg.createSvg("g", { attr: { fill: steel } });
	keyhole.createSvg("circle", { attr: { cx: 256, cy: 246, r: 18 } });
	keyhole.createSvg("polygon", { attr: { points: "248,254 264,254 272,290 240,290" } });
	return svg;
}
