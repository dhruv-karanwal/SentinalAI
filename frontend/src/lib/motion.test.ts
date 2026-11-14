import assert from 'node:assert/strict';
import { test } from 'node:test';

import { countAt, easeOutCubic, activeSection, packetT } from './motion.ts';
import { chatReducer, errorNote, initialChat, loadChat, nextFocus, saveChat, suggestionsFor, CHAT_LIMIT } from './chat.ts';
import { readFileSync } from 'node:fs';

test('easeOutCubic is 0 at 0, 1 at 1, clamped and monotone', () => {
  assert.equal(easeOutCubic(0), 0);
  assert.equal(easeOutCubic(1), 1);
  assert.equal(easeOutCubic(-1), 0);
  assert.equal(easeOutCubic(2), 1);
  let prev = 0;
  for (let i = 1; i <= 10; i++) {
    const v = easeOutCubic(i / 10);
    assert.ok(v >= prev);
    prev = v;
  }
});

test('countAt reaches the exact value and stays an integer', () => {
  assert.equal(countAt(11208, 0, 900), 0);
  assert.equal(countAt(11208, 900, 900), 11208);
  assert.equal(countAt(11208, 5000, 900), 11208);
  const mid = countAt(11208, 450, 900);
  assert.ok(Number.isInteger(mid) && mid > 0 && mid < 11208);
  assert.equal(countAt(0, 100, 900), 0);
  assert.equal(countAt(7, 10, 0), 7); // zero duration (reduced motion) = final value
});

test('activeSection picks the last section whose top passed the line', () => {
  assert.equal(activeSection([], 100), -1);
  assert.equal(activeSection([300, 900, 1500], 100), 0); // nothing passed yet: first
  assert.equal(activeSection([50, 900, 1500], 100), 0);
  assert.equal(activeSection([-800, 80, 1500], 100), 1);
  assert.equal(activeSection([-2000, -900, -10], 100), 2);
});

test('packetT wraps phase into [0, 1)', () => {
  assert.equal(packetT(0, 6000, 0), 0);
  assert.equal(packetT(3000, 6000, 0), 0.5);
  assert.equal(packetT(6000, 6000, 0), 0);
  assert.equal(packetT(0, 6000, 0.25), 0.25);
});

// ---------------------------------------------------------------- floating chat

test('chat opens, minimises, closes; close remembers to return focus', () => {
  let s = initialChat();
  assert.equal(s.open, false);
  s = chatReducer(s, { type: 'open' });
  assert.equal(s.open, true);
  assert.equal(s.minimised, false);
  s = chatReducer(s, { type: 'minimise' });
  assert.equal(s.minimised, true);
  s = chatReducer(s, { type: 'open' });
  assert.equal(s.minimised, false);
  s = chatReducer(s, { type: 'close' });
  assert.equal(s.open, false);
  assert.equal(s.returnFocus, true);
});

test('chat keeps at most CHAT_LIMIT messages and clear empties the log', () => {
  let s = chatReducer(initialChat(), { type: 'open' });
  for (let i = 0; i < CHAT_LIMIT + 5; i++) s = chatReducer(s, { type: 'push', msg: { id: i, who: 'you', text: `q${i}` } });
  assert.equal(s.msgs.length, CHAT_LIMIT);
  assert.equal(s.msgs[0]!.text, 'q5');
  s = chatReducer(s, { type: 'clear' });
  assert.deepEqual(s.msgs, []);
  assert.equal(s.open, true);
});

test('Esc / Tab focus trap wraps inside the panel', () => {
  assert.equal(nextFocus(3, 2, false), 0); // Tab on the last -> first
  assert.equal(nextFocus(3, 0, true), 2); // Shift+Tab on the first -> last
  assert.equal(nextFocus(3, 1, false), null); // inside: let the browser move
  assert.equal(nextFocus(3, -1, false), 0); // focus outside the panel -> first
  assert.equal(nextFocus(0, -1, false), null);
});

test('error notes: 429 busy keeps the model online, 503/0 marks it offline', () => {
  const busy = errorNote(429, 'busy');
  assert.match(busy.note, /busy/);
  assert.equal(busy.offline, false);
  for (const st of [0, 502, 503, 504]) assert.equal(errorNote(st, '').offline, true);
  assert.match(errorNote(503, '').note, /offline/i);
  const other = errorNote(500, 'boom');
  assert.equal(other.offline, false);
  assert.match(other.note, /500/);
});

test('suggested chips: every screen has three, unknown falls back to About', () => {
  for (const p of ['/about', '/overview', '/incidents', '/alerts', '/study']) assert.equal(suggestionsFor(p).length, 3);
  assert.deepEqual(suggestionsFor('/nope'), suggestionsFor('/about'));
  assert.ok(suggestionsFor('/incidents').some((q) => /H2/.test(q)));
});

test('chat storage survives a throwing or empty store and drops junk', () => {
  const bad = { getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); } };
  assert.deepEqual(loadChat(bad), initialChat());
  saveChat(bad, initialChat()); // must not throw
  const mem = new Map<string, string>();
  const store = { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v) };
  assert.deepEqual(loadChat(store), initialChat());
  const s = chatReducer(chatReducer(initialChat(), { type: 'open' }), { type: 'push', msg: { id: 1, who: 'help', text: 'hi', by: 'glossary' } });
  saveChat(store, s);
  const back = loadChat(store);
  assert.equal(back.open, true);
  assert.equal(back.msgs[0]!.text, 'hi');
  assert.equal(back.returnFocus, false);
  mem.set('sentinel.chat', '{"open":true,"msgs":[{"id":"x","text":5}]}');
  assert.deepEqual(loadChat(store).msgs, []);
});

test('long answers wrap: the chat text rule breaks anywhere and keeps newlines', () => {
  const css = readFileSync(new URL('../shell.css', import.meta.url), 'utf8');
  const rule = css.slice(css.indexOf('.fab-text'), css.indexOf('}', css.indexOf('.fab-text')));
  assert.match(rule, /overflow-wrap:\s*anywhere/);
  assert.match(rule, /white-space:\s*pre-wrap/);
});

test('system.css has a reduced-motion fallback that stops animations', () => {
  const css = readFileSync(new URL('../system.css', import.meta.url), 'utf8');
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)[\s\S]*animation: none/);
  assert.doesNotMatch(css, /#[0-9a-fA-F]{3,8}\b/); // tokens only
});

test('verifier demo uses the real quote rule: exact, case-sensitive, >= 8 chars', async () => {
  const { quoteSupported, VERIFIER_SAMPLE } = await import('../content/about.ts');
  const l = VERIFIER_SAMPLE.line;
  assert.equal(quoteSupported(l, VERIFIER_SAMPLE.claims[0].quote).kept, true);
  assert.equal(quoteSupported(l, VERIFIER_SAMPLE.claims[1].quote).kept, false);
  assert.equal(quoteSupported(l, 'wpscan v3.8.22').kept, false); // case matters
  assert.match(quoteSupported(l, 'WPScan').reason, /8 characters/);
  assert.match(l, /192\.0\.2\./); // TEST-NET: synthetic sample
});
