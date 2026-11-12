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
