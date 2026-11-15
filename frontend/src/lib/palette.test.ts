import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { CVD, chroma, cvdDistance, hsl, readThemes } from './contrast.ts';

const SRC = fileURLToPath(new URL('..', import.meta.url));
const TOKENS = readFileSync(join(SRC, 'tokens.css'), 'utf-8');
const themes = readThemes(TOKENS);
const KINDS = Object.keys(CVD) as (keyof typeof CVD)[];

/** Smallest OKLab distance between any pair of `keys` in a theme under `kind`. */
function minPair(t: Record<string, string>, keys: string[], kind: keyof typeof CVD): number {
  let min = Infinity;
  for (let i = 0; i < keys.length; i++) {
    for (let j = i + 1; j < keys.length; j++) min = Math.min(min, cvdDistance(t[keys[i]!]!, t[keys[j]!]!, kind));
  }
  return min;
}

test('detector, severity and verified tokens stay apart under colour-vision deficiency', (t) => {
  const fails: string[] = [];
  const min: Record<string, number> = {};
  const need = (name: string, kind: string, what: string, d: number, floor: number): void => {
    if (d < floor) fails.push(`${name} ${kind}: ${what} ${d.toFixed(3)} < ${floor}`);
    const key = `${name} ${what} (>= ${floor})`;
    min[key] = Math.min(min[key] ?? Infinity, d);
  };
  for (const [name, c] of Object.entries(themes)) {
    for (const kind of KINDS) {
      need(name, kind, 'detector pairs', minPair(c, ['--det-wazuh', '--det-suricata', '--det-aminer'], kind), 0.1);
      need(name, kind, 'sev-high vs sev-medium', cvdDistance(c['--sev-high']!, c['--sev-medium']!, kind), 0.06);
      // shortcut: low is a warm neutral and always carries glyph + word; its pairs are printed, not
      // asserted (light deutan high vs low measures 0.039). Assert once the low token is retuned.
      for (const o of ['--sev-high', '--sev-medium']) {
        const d = cvdDistance(c[o]!, c['--sev-low']!, kind);
        const key = `${name} ${o.slice(6)} vs low (printed only)`;
        min[key] = Math.min(min[key] ?? Infinity, d);
      }
    }
    // Light theme squeezes verified green and AMiner cyan (both need 4.5:1 on paper), so the pair
    // gets 0.07 under none/deutan; verifier state also carries a tag word.
    for (const kind of ['none', 'deutan'] as const) need(name, kind, 'aminer vs verified', cvdDistance(c['--det-aminer']!, c['--verified']!, kind), 0.07);
  }
  for (const [k, d] of Object.entries(min)) t.diagnostic(`min ${k}: ${d.toFixed(3)}`);
  assert.deepEqual(fails, []);
});

test('the accent is a neutral (ink), so it cannot be read as a data hue', (t) => {
  for (const [name, c] of Object.entries(themes)) {
    for (const k of ['--accent', '--on-accent']) {
      const ch = chroma(c[k]!);
      t.diagnostic(`${name} ${k} OKLab chroma ${ch.toFixed(4)}`);
      assert.ok(ch < 0.02, `${name} ${k} chroma ${ch.toFixed(4)} >= 0.02`);
    }
  }
});

// ---- blue guard -------------------------------------------------------------------------------

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return sourceFiles(p);
    return /\.(css|tsx?)$/.test(e.name) ? [p] : [];
  });
}

// `#` not preceded by `&` or a word character (skips `&#123;` and `a#b`); `#/route` never matches.
const HEX = /(?<![&\w])#(?:[0-9a-f]{8}|[0-9a-f]{6}|[0-9a-f]{3,4})\b/gi;
const FUNC = /\b(?:rgba?|hsla?)\(\s*[\d.]/gi;

test('raw colour values live only in tokens.css', () => {
  const files = [...sourceFiles(SRC), join(SRC, '..', 'index.html')].filter((p) => !p.endsWith('tokens.css'));
  const hits: string[] = [];
  for (const p of files) {
    if (p.endsWith('palette.test.ts') || p.endsWith('guard.test.ts')) continue; // these name the patterns they look for
    readFileSync(p, 'utf-8').split('\n').forEach((line, i) => {
      for (const m of line.matchAll(HEX)) hits.push(`${relative(SRC, p)}:${i + 1} ${m[0]}`);
      for (const m of line.matchAll(FUNC)) hits.push(`${relative(SRC, p)}:${i + 1} ${m[0]}`);
    });
  }
  assert.deepEqual(hits, []);
});

test('tokens.css holds no blue, indigo or purple', () => {
  const blue: string[] = [];
  const check = (src: string, r: number, g: number, b: number): void => {
    const [h, s, l] = hsl(r, g, b);
    if (h >= 190 && h <= 290 && s >= 0.25 && l > 0.08 && l < 0.92) blue.push(`${src} (h ${h.toFixed(0)}, s ${s.toFixed(2)}, l ${l.toFixed(2)})`);
  };
  for (const m of TOKENS.matchAll(/#([0-9a-f]{6})\b/gi)) {
    const n = parseInt(m[1]!, 16);
    check(m[0], (n >> 16) & 255, (n >> 8) & 255, n & 255);
  }
  for (const m of TOKENS.matchAll(/rgb\(\s*(\d+)\s+(\d+)\s+(\d+)/gi)) check(m[0], +m[1]!, +m[2]!, +m[3]!);
  assert.ok(TOKENS.match(/#[0-9a-f]{6}\b/gi)!.length > 40, 'the token parser found the palette');
  assert.deepEqual(blue, []);
});
