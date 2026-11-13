import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { CVD, cvdDistance, hsl, readThemes } from './contrast.ts';

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

test('detector, accent and severity tokens stay apart under colour-vision deficiency', () => {
  for (const [name, t] of Object.entries(themes)) {
    for (const kind of KINDS) {
      const det = minPair(t, ['--det-wazuh', '--det-suricata', '--det-aminer'], kind);
      assert.ok(det >= 0.1, `${name} ${kind}: detector min OKLab distance ${det.toFixed(3)}`);
      const sev = cvdDistance(t['--sev-high']!, t['--sev-medium']!, kind);
      assert.ok(sev >= 0.06, `${name} ${kind}: sev-high vs sev-medium ${sev.toFixed(3)}`);
    }
    // Light theme squeezes olive accent, verified green and AMiner cyan (all need 4.5:1 on paper),
    // so these two pairs get 0.07 under none/deutan; verifier state also carries a tag word.
    for (const kind of ['none', 'deutan'] as const) {
      const acc = cvdDistance(t['--accent']!, t['--verified']!, kind);
      assert.ok(acc >= 0.07, `${name} ${kind}: accent vs verified ${acc.toFixed(3)}`);
      const ami = cvdDistance(t['--det-aminer']!, t['--verified']!, kind);
      assert.ok(ami >= 0.07, `${name} ${kind}: aminer vs verified ${ami.toFixed(3)}`);
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
    if (p.endsWith('palette.test.ts')) continue; // this file names the patterns it looks for
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
