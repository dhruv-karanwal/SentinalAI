// Style guard (DESIGN.md section 10): fails on the effects the design system bans, naming
// file:line, selector and declaration. Every stylesheet in src/ is scanned; tokens.css is the one
// place raw colours, sizes, radii, durations and the easing curve may be written.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const SRC = fileURLToPath(new URL('..', import.meta.url));

export type Decl = { line: number; selector: string; prop: string; value: string };

/** Comments blanked out (newlines kept, so line numbers stay right). */
function stripComments(css: string): string {
  return css.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '));
}

/** Every `prop: value` declaration with its line and innermost selector. */
export function declarations(css: string): Decl[] {
  const src = stripComments(css);
  const out: Decl[] = [];
  const stack: string[] = [];
  let buf = '';
  let start = -1; // offset of the first non-space char of buf
  let paren = 0;
  let quote = '';
  const lineAt = (i: number): number => src.slice(0, i).split('\n').length;
  const flush = (): void => {
    const text = buf.trim();
    const colon = text.indexOf(':');
    if (stack.length && colon > 0 && !text.startsWith('@')) {
      out.push({ line: lineAt(start), selector: stack[stack.length - 1]!, prop: text.slice(0, colon).trim().toLowerCase(), value: text.slice(colon + 1).trim() });
    }
    buf = '';
    start = -1;
  };
  for (let i = 0; i < src.length; i++) {
    const ch = src[i]!;
    if (quote) {
      if (ch === quote && src[i - 1] !== '\\') quote = '';
    } else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '(') paren++;
    else if (ch === ')') paren--;
    else if (paren === 0 && ch === '{') {
      stack.push(buf.trim().replace(/\s+/g, ' '));
      buf = '';
      start = -1;
      continue;
    } else if (paren === 0 && (ch === ';' || ch === '}')) {
      flush();
      if (ch === '}') stack.pop();
      continue;
    }
    if (start < 0 && !/\s/.test(ch)) start = i;
    buf += ch;
  }
  return out;
}

/** Split on `sep` outside parentheses. */
function splitTop(value: string, sep: RegExp): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of value) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (depth === 0 && sep.test(ch)) {
      if (cur.trim()) parts.push(cur.trim());
      cur = '';
    } else cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

const LENGTH_VAR = /^var\(--(hairline|focus-w|sp-\d+)\)$/;
const RAW_LENGTH = /^-?[\d.]+(px|em|rem)?$/;

/** none, var(--shadow-overlay), or zero-blur hairlines (offsets and spread only). */
function shadowOk(value: string): boolean {
  if (value === 'none' || value === 'var(--shadow-overlay)') return true;
  return splitTop(value, /,/).every((item) => {
    const lengths: string[] = [];
    let colours = 0;
    for (const tok of splitTop(item, /\s/)) {
      if (tok === 'inset') continue;
      if (RAW_LENGTH.test(tok) || LENGTH_VAR.test(tok)) lengths.push(tok);
      else if (/^var\(--[a-z0-9-]+\)$/.test(tok) || tok === 'currentColor' || tok === 'transparent') colours++;
      else return false; // calc(), raw colours, anything unparsed: not a plain hairline
    }
    const blur = lengths[2];
    return lengths.length >= 2 && lengths.length <= 4 && colours <= 1 && (blur === undefined || /^0(px)?$/.test(blur));
  });
}

// CSS Color 4 named colours (transparent / currentColor are allowed and not listed).
const NAMED = new Set(
  ('aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue blueviolet brown burlywood cadetblue ' +
    'chartreuse chocolate coral cornflowerblue cornsilk crimson cyan darkblue darkcyan darkgoldenrod darkgray darkgreen darkgrey ' +
    'darkkhaki darkmagenta darkolivegreen darkorange darkorchid darkred darksalmon darkseagreen darkslateblue darkslategray ' +
    'darkslategrey darkturquoise darkviolet deeppink deepskyblue dimgray dimgrey dodgerblue firebrick floralwhite forestgreen ' +
    'fuchsia gainsboro ghostwhite gold goldenrod gray green greenyellow grey honeydew hotpink indianred indigo ivory khaki ' +
    'lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral lightcyan lightgoldenrodyellow lightgray lightgreen ' +
    'lightgrey lightpink lightsalmon lightseagreen lightskyblue lightslategray lightslategrey lightsteelblue lightyellow lime ' +
    'limegreen linen magenta maroon mediumaquamarine mediumblue mediumorchid mediumpurple mediumseagreen mediumslateblue ' +
    'mediumspringgreen mediumturquoise mediumvioletred midnightblue mintcream mistyrose moccasin navajowhite navy oldlace olive ' +
    'olivedrab orange orangered orchid palegoldenrod palegreen paleturquoise palevioletred papayawhip peachpuff peru pink plum ' +
    'powderblue purple rebeccapurple red rosybrown royalblue saddlebrown salmon sandybrown seagreen seashell sienna silver skyblue ' +
    'slateblue slategray slategrey snow springgreen steelblue tan teal thistle tomato turquoise violet wheat white whitesmoke ' +
    'yellow yellowgreen canvas canvastext buttonface buttontext highlight graytext').split(' '),
);

const HEX = /(?<![&\w])#(?:[0-9a-f]{8}|[0-9a-f]{6}|[0-9a-f]{3,4})\b/i;
const COLOUR_FN = /\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\(/i;
const TIME = /^-?[\d.]+m?s$/;
const EASING_PROPS = /^(transition|animation)(-timing-function)?$/;
const TIMED_PROPS = /^(transition|animation)(-duration|-delay)?$/;

/** Value with var(...), url(...) and quoted strings removed, for keyword matching. */
function bare(value: string): string {
  return value.replace(/(["'])[\s\S]*?\1/g, ' ').replace(/url\([^)]*\)/g, ' ').replace(/var\([^()]*(\([^()]*\))*[^()]*\)/g, ' ');
}

/** Why a declaration is banned (empty when it is fine). `tokens` = it sits in tokens.css. */
export function violations(d: Decl, tokens = false): string[] {
  const { prop, value } = d;
  const v = value.toLowerCase();
  const why: string[] = [];
  if (/^(-webkit-)?backdrop-filter$/.test(prop) && v !== 'none') why.push('backdrop-filter');
  if (prop === 'filter' && /\b(blur|drop-shadow|brightness)\(/.test(v)) why.push('filter blur / drop-shadow / brightness');
  if (/^animation(-iteration-count)?$/.test(prop) && /\binfinite\b/.test(v)) why.push('infinite animation');
  if (prop === 'box-shadow' && !shadowOk(value)) why.push('box-shadow that is not none, var(--shadow-overlay) or a zero-blur hairline');
  if (/(linear|radial|conic)-gradient\(/.test(v)) why.push('gradient');
  if (/^(-webkit-)?background-clip$/.test(prop) && /\btext\b/.test(v)) why.push('background-clip: text');
  if (prop === 'text-transform' && v.includes('uppercase')) why.push('text-transform: uppercase');
  if (tokens) return why;

  const words = bare(value);
  if (HEX.test(words) || COLOUR_FN.test(words) || words.split(/[\s,/()]+/).some((w) => NAMED.has(w.toLowerCase()))) why.push('raw colour outside tokens.css');
  // --row-fs is the density alias of --fs-small / --fs-body (tokens.css)
  if (prop === 'font-size' && !/^(var\(--(fs-[a-z]+|row-fs)\)|inherit|[\d.]+(em|%))$/.test(v)) why.push('font-size not var(--fs-*)');
  if (prop === 'font' && v !== 'inherit' && !/var\(--fs-[a-z]+\)/.test(v)) why.push('font shorthand without var(--fs-*)');
  if (/^border(-[a-z]+)*-radius$/.test(prop) && !splitTop(v, /[\s/]/).every((t) => /^(0|50%|inherit|var\(--radius-[a-z]+\))$/.test(t))) why.push('border-radius not var(--radius-*)');
  if (TIMED_PROPS.test(prop) && splitTop(words, /[\s,]/).some((t) => TIME.test(t) && parseFloat(t) !== 0)) why.push('raw duration (use var(--dur-*))');
  if (EASING_PROPS.test(prop) && /\b(cubic-bezier|steps)\(|\b(ease|ease-in|ease-out|ease-in-out|linear|step-start|step-end)\b/.test(words)) why.push('easing not var(--ease)');
  return why;
}

// ---- files -------------------------------------------------------------------------------------

function walk(dir: string, ext: RegExp): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    return e.isDirectory() ? walk(p, ext) : ext.test(e.name) ? [p] : [];
  });
}

const CSS = walk(SRC, /\.css$/).map((p) => ({ name: relative(SRC, p).replace(/\\/g, '/'), text: readFileSync(p, 'utf-8') }));
const TSX = walk(SRC, /\.tsx$/).map((p) => ({ name: relative(SRC, p).replace(/\\/g, '/'), text: readFileSync(p, 'utf-8') }));

/** Custom properties defined anywhere: a CSS declaration, an inline style key or setProperty. */
const DEFINED = new Set<string>();
for (const f of CSS) for (const d of declarations(f.text)) if (d.prop.startsWith('--')) DEFINED.add(d.prop);
for (const f of TSX) {
  for (const m of f.text.matchAll(/['"](--[a-z0-9-]+)['"]\s*\]?\s*:/gi)) DEFINED.add(m[1]!);
  for (const m of f.text.matchAll(/setProperty\(\s*['"`](--[a-z0-9-]+)/gi)) DEFINED.add(m[1]!);
}

const undefinedRefs = (text: string): string[] => [...text.matchAll(/var\(\s*(--[a-z0-9-]+)/gi)].map((m) => m[1]!).filter((n) => !n.endsWith('-') && !DEFINED.has(n)); // `--sev-${tone}` templates are not checkable

test('the guard found the stylesheets', () => {
  const names = CSS.map((f) => f.name);
  for (const n of ['tokens.css', 'base.css', 'system.css']) assert.ok(names.includes(n), `${n} missing`);
  assert.ok(DEFINED.has('--bg') && DEFINED.has('--ease') && DEFINED.has('--fs-body'), 'tokens.css custom properties parsed');
});

for (const f of CSS) {
  test(`style guard: ${f.name}`, () => {
    const hits: string[] = [];
    for (const d of declarations(f.text)) {
      const why = violations(d, f.name === 'tokens.css');
      const missing = undefinedRefs(d.value);
      if (missing.length) why.push(`undefined custom property ${[...new Set(missing)].join(', ')}`);
      if (why.length) hits.push(`${f.name}:${d.line} ${d.selector} { ${d.prop}: ${d.value} } -> ${why.join('; ')}`);
    }
    assert.deepEqual(hits, []);
  });
}

test('style guard: .tsx inline styles (raw colours, undefined custom properties, dangerouslySetInnerHTML)', () => {
  const hits: string[] = [];
  for (const f of TSX) {
    f.text.split('\n').forEach((line, i) => {
      const at = `${f.name}:${i + 1}`;
      const hex = new RegExp(HEX.source, 'gi');
      for (const m of line.matchAll(hex)) hits.push(`${at} raw colour ${m[0]}`);
      if (/\b(rgba?|hsla?|oklch)\(/i.test(line)) hits.push(`${at} raw colour function: ${line.trim()}`);
      if (line.includes('dangerouslySetInnerHTML')) hits.push(`${at} dangerouslySetInnerHTML`);
      for (const n of new Set(undefinedRefs(line))) hits.push(`${at} undefined custom property ${n}`);
    });
  }
  assert.deepEqual(hits, []);
});

// ---- the guard's own matcher -------------------------------------------------------------------

const check = (css: string): string[] => declarations(css).flatMap((d) => violations(d));

test('guard self-test: the parser keeps lines, selectors and values with parentheses', () => {
  const ds = declarations('/* a\n b */\n.a,\n.b {\n  color: var(--text);\n  background: url("x;y");\n}\n@media (x) {\n  .c { margin: 0 }\n}\n');
  assert.deepEqual(ds.map((d) => [d.line, d.selector, d.prop, d.value]), [
    [5, '.a, .b', 'color', 'var(--text)'],
    [6, '.a, .b', 'background', 'url("x;y")'],
    [9, '.c', 'margin', '0'],
  ]);
});

test('guard self-test: glows fail, hairlines and the overlay shadow pass', () => {
  assert.deepEqual(check('.a { box-shadow: 0 0 12px var(--sev-high); }'), ['box-shadow that is not none, var(--shadow-overlay) or a zero-blur hairline']);
  assert.equal(check('.a { box-shadow: 0 0 0 1px var(--border), 0 4px 8px var(--x); }').length, 1);
  assert.deepEqual(check('.a { box-shadow: inset 2px 0 0 var(--accent); }'), []);
  assert.deepEqual(check('.a { box-shadow: 0 0 0 var(--focus-w) var(--accent), inset 0 -1px var(--border); }'), []);
  assert.deepEqual(check('.a { box-shadow: var(--shadow-overlay); }'), []);
  assert.deepEqual(check('.a { box-shadow: none; }'), []);
});

test('guard self-test: loops, filters, gradients, caps, glass fail', () => {
  assert.deepEqual(check('.a { animation: spin var(--dur-slow) var(--ease) infinite; }'), ['infinite animation']);
  assert.deepEqual(check('.a { animation-iteration-count: infinite; }'), ['infinite animation']);
  assert.deepEqual(check('.a { animation: in var(--dur-mid) var(--ease) both; }'), []);
  assert.deepEqual(check('.a { backdrop-filter: blur(8px); }'), ['backdrop-filter']);
  assert.deepEqual(check('.a { backdrop-filter: none; }'), []);
  assert.deepEqual(check('.a:hover { filter: brightness(1.2); }'), ['filter blur / drop-shadow / brightness']);
  assert.deepEqual(check('.a { background: linear-gradient(var(--bg), var(--surface)); }'), ['gradient']);
  assert.deepEqual(check('.a { -webkit-background-clip: text; }'), ['background-clip: text']);
  assert.deepEqual(check('.a { text-transform: uppercase; }'), ['text-transform: uppercase']);
});

test('guard self-test: raw colours, sizes, radii, durations and easing fail outside tokens.css', () => {
  assert.deepEqual(check('.a { color: #fff; }'), ['raw colour outside tokens.css']);
  assert.deepEqual(check('.a { border: 1px solid white; }'), ['raw colour outside tokens.css']);
  assert.deepEqual(check('.a { color: rgb(0 0 0 / 0.5); }'), ['raw colour outside tokens.css']);
  assert.deepEqual(check('.a { color: transparent; background: currentColor; border-color: var(--text-muted); }'), []);
  assert.deepEqual(check('.a { font-size: 13px; }'), ['font-size not var(--fs-*)']);
  assert.deepEqual(check('.a { font-size: var(--fs-small); } .b { font-size: 0.9em; }'), []);
  assert.deepEqual(check('.a { font: 500 12px var(--font-mono); }'), ['font shorthand without var(--fs-*)']);
  assert.deepEqual(check('.a { border-radius: 8px; }'), ['border-radius not var(--radius-*)']);
  assert.deepEqual(check('.a { border-radius: 50%; } .b { border-top-left-radius: var(--radius-s); } .c { border-radius: 0; }'), []);
  assert.deepEqual(check('.a { transition: opacity 200ms var(--ease); }'), ['raw duration (use var(--dur-*))']);
  assert.deepEqual(check('.a { transition: opacity var(--dur-fast) ease-out; }'), ['easing not var(--ease)']);
  assert.deepEqual(check('.a { transition: transform var(--dur-mid) cubic-bezier(0.3, 1.6, 0.6, 1); }'), ['easing not var(--ease)']);
  assert.deepEqual(check('.a { transition: opacity var(--dur-fast) var(--ease) 0s; animation-delay: calc(var(--stagger) * var(--i, 0)); }'), []);
  // tokens.css defines the raw values but still may not hold banned effects
  assert.deepEqual(declarations(':root { --ease: cubic-bezier(0.2, 0, 0, 1); --fs-body: 13px; }').flatMap((d) => violations(d, true)), []);
});

test('guard self-test: undefined custom properties are reported', () => {
  assert.deepEqual(undefinedRefs('box-shadow: var(--glow-accent); color: var(--text); fill: var(--sev-${t});'), ['--glow-accent']);
});
