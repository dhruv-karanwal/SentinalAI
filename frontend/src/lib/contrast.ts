// WCAG 2 relative luminance and contrast ratio, plus a reader for the token blocks in tokens.css.
// Used by contrast.test.ts so every colour pairing in DESIGN.md is measured, not asserted.

export function luminance(hex: string): number {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex.trim());
  if (!m) throw new Error(`not a #rrggbb colour: ${hex}`);
  const n = parseInt(m[1]!, 16);
  const ch = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * ch[0]! + 0.7152 * ch[1]! + 0.0722 * ch[2]!;
}

export function contrast(a: string, b: string): number {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** `{ dark: {--bg: '#..'}, light: {...} }` from the two theme blocks of tokens.css. */
export function readThemes(css: string): Record<'dark' | 'light', Record<string, string>> {
  const block = (selector: RegExp): Record<string, string> => {
    const m = selector.exec(css);
    if (!m) throw new Error(`theme block not found: ${selector}`);
    const body = css.slice(m.index + m[0].length, css.indexOf('}', m.index));
    const out: Record<string, string> = {};
    for (const d of body.matchAll(/(--[a-z0-9-]+)\s*:\s*(#[0-9a-f]{6})\s*;/gi)) out[d[1]!] = d[2]!;
    return out;
  };
  return { dark: block(/:root\[data-theme="dark"\]\s*\{/), light: block(/:root\[data-theme="light"\]\s*\{/) };
}

// ---- colour-vision-deficiency simulation (palette.test.ts) ------------------------------------

export type Rgb = [number, number, number];

/** #rrggbb -> linear-light sRGB, each channel 0..1. */
export function hexToLinear(hex: string): Rgb {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex.trim());
  if (!m) throw new Error(`not a #rrggbb colour: ${hex}`);
  const n = parseInt(m[1]!, 16);
  const lin = (c: number): number => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return [lin((n >> 16) & 255), lin((n >> 8) & 255), lin(n & 255)];
}

/** Machado, Oliveira and Fernandes (2009), severity 1.0, applied to linear RGB. */
export const CVD: Record<'none' | 'protan' | 'deutan' | 'tritan', number[][]> = {
  none: [[1, 0, 0], [0, 1, 0], [0, 0, 1]],
  protan: [[0.152286, 1.052583, -0.204868], [0.114503, 0.786281, 0.099216], [-0.003882, -0.048116, 1.051998]],
  deutan: [[0.367322, 0.860646, -0.227968], [0.280085, 0.672501, 0.047413], [-0.01182, 0.04294, 0.968881]],
  tritan: [[1.255528, -0.076749, -0.178779], [-0.078411, 0.930809, 0.147602], [0.004733, 0.691367, 0.3039]],
};

export function simulate(rgb: Rgb, kind: keyof typeof CVD): Rgb {
  const m = CVD[kind];
  const row = (r: number[]): number => Math.min(1, Math.max(0, r[0]! * rgb[0] + r[1]! * rgb[1] + r[2]! * rgb[2]));
  return [row(m[0]!), row(m[1]!), row(m[2]!)];
}

/** Linear sRGB -> OKLab (Ottosson 2020). */
export function oklab([r, g, b]: Rgb): Rgb {
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [
    0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  ];
}

/** OKLab distance between two #rrggbb colours as seen under a simulated deficiency. */
export function cvdDistance(a: string, b: string, kind: keyof typeof CVD): number {
  const pa = oklab(simulate(hexToLinear(a), kind));
  const pb = oklab(simulate(hexToLinear(b), kind));
  return Math.hypot(pa[0] - pb[0], pa[1] - pb[1], pa[2] - pb[2]);
}

/** HSL of an sRGB colour given as 0..255 channels: hue in degrees, saturation and lightness 0..1. */
export function hsl(r: number, g: number, b: number): Rgb {
  const [rr, gg, bb] = [r / 255, g / 255, b / 255];
  const max = Math.max(rr, gg, bb);
  const min = Math.min(rr, gg, bb);
  const l = (max + min) / 2;
  const d = max - min;
  if (d === 0) return [0, 0, l];
  const s = d / (1 - Math.abs(2 * l - 1));
  const h = max === rr ? ((gg - bb) / d) % 6 : max === gg ? (bb - rr) / d + 2 : (rr - gg) / d + 4;
  return [(h * 60 + 360) % 360, s, l];
}
