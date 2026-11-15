import assert from 'node:assert/strict';
import { test } from 'node:test';

import { barHeight, binIndex, binRange, binTicks } from './bins.ts';
import { compareQueue, fmtDuration, fmtStep, fmtTime, fmtInt, isoUtc, parseEntity, relTime, sortBy } from './format.ts';
import { needlesFromQuery, splitHighlight } from './highlight.ts';
import { clampIndex, scrollTopFor, visibleRange } from './virtual.ts';

test('fmtInt groups thousands', () => {
  assert.equal(fmtInt(0), '0');
  assert.equal(fmtInt(999), '999');
  assert.equal(fmtInt(11208), '11,208');
  assert.equal(fmtInt(1234567), '1,234,567');
  assert.equal(fmtInt(-4200), '-4,200');
});

test('isoUtc prints UTC with seconds and keeps invalid input', () => {
  assert.equal(isoUtc('2022-01-21T00:02:27+00:00'), '2022-01-21T00:02:27Z');
  assert.equal(isoUtc('2022-01-21T03:02:27+03:00'), '2022-01-21T00:02:27Z');
  assert.equal(isoUtc('not a time'), 'not a time');
});

test('fmtDuration always carries units', () => {
  assert.equal(fmtDuration(0), '0\u00a0s');
  assert.equal(fmtDuration(42), '42\u00a0s');
  assert.equal(fmtDuration(222), '3\u00a0min 42\u00a0s');
  assert.equal(fmtDuration(3720), '1\u00a0h 02\u00a0min');
  assert.equal(fmtDuration(187200), '2\u00a0d 04\u00a0h');
});

test('relTime past and future', () => {
  const now = Date.parse('2022-01-21T01:00:00Z');
  assert.equal(relTime('2022-01-21T00:59:48Z', now), '12 s ago');
  assert.equal(relTime('2022-01-21T00:30:00Z', now), '30 min ago');
  assert.equal(relTime('2022-01-20T01:00:00Z', now), '1 d ago');
  assert.equal(relTime('2022-01-21T03:00:00Z', now), 'in 2 h');
  assert.equal(relTime('nope', now), '');
});

test('queue order: severity, then status, then newest', () => {
  const rows = [
    { id: 'a', severity: 'Low', status: 'open', last_ts: '2022-01-23T10:00:00+00:00' },
    { id: 'b', severity: 'High', status: 'closed', last_ts: '2022-01-24T10:00:00+00:00' },
    { id: 'c', severity: 'High', status: 'open', last_ts: '2022-01-22T10:00:00+00:00' },
    { id: 'd', severity: 'High', status: 'open', last_ts: '2022-01-23T10:00:00+00:00' },
    { id: 'e', severity: 'Medium', status: 'open', last_ts: '2022-01-25T10:00:00+00:00' },
  ];
  assert.deepEqual([...rows].sort(compareQueue).map((r) => r.id), ['d', 'c', 'b', 'e', 'a']);
});

test('sortBy is stable, numeric and puts nulls last', () => {
  const rows = [{ n: 3, k: 'x' }, { n: null, k: 'y' }, { n: 1, k: 'z' }, { n: 3, k: 'w' }];
  assert.deepEqual(sortBy(rows, (r) => r.n, 'asc').map((r) => r.k), ['z', 'x', 'w', 'y']);
  assert.deepEqual(sortBy(rows, (r) => r.n, 'desc').map((r) => r.k), ['x', 'w', 'z', 'y']);
});

test('parseEntity', () => {
  assert.deepEqual(parseEntity('host:192.168.231.56'), { kind: 'host', value: '192.168.231.56' });
  assert.deepEqual(parseEntity('plain'), { kind: '', value: 'plain' });
});

test('visibleRange renders a window, not the list', () => {
  const r = visibleRange(24000, 480, 24, 11208, 8);
  assert.equal(r.start, 992);
  assert.equal(r.end, 1029);
  assert.equal(r.offset, 992 * 24);
  assert.equal(r.total, 11208 * 24);
  assert.ok(r.end - r.start < 60);
});

test('visibleRange clamps at both ends and handles empty lists', () => {
  assert.deepEqual(visibleRange(0, 480, 24, 0), { start: 0, end: 0, offset: 0, total: 0 });
  const top = visibleRange(-50, 480, 24, 100);
  assert.equal(top.start, 0);
  const bottom = visibleRange(1e9, 480, 24, 100);
  assert.equal(bottom.end, 100);
  assert.ok(bottom.start >= 100 - 21 - 8 - 1);
});

test('scrollTopFor moves only when the row is outside the viewport', () => {
  assert.equal(scrollTopFor(5, 0, 240, 24), 0);
  assert.equal(scrollTopFor(10, 0, 240, 24), 24);
  assert.equal(scrollTopFor(2, 240, 240, 24), 48);
  assert.equal(clampIndex(-1, 5), 0);
  assert.equal(clampIndex(9, 5), 4);
  assert.equal(clampIndex(0, 0), -1);
});

test('binTicks counts per detector and keeps the last instant in the last bin', () => {
  const ticks = [
    { t: 0, detector: 'wazuh' },
    { t: 0.5, detector: 'wazuh' },
    { t: 50, detector: 'aminer' },
    { t: 100, detector: 'wazuh' },
  ];
  const b = binTicks(ticks, 0, 100, 10, ['wazuh', 'suricata', 'aminer']);
  assert.deepEqual([...b.rows.get('wazuh')!], [2, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual([...b.rows.get('aminer')!], [0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
  assert.equal(b.rows.get('suricata')!.reduce((x, y) => x + y, 0), 0);
  assert.equal(b.max, 2);
  let total = 0;
  for (const row of b.rows.values()) total += row.reduce((x, y) => x + y, 0);
  assert.equal(total, ticks.length);
});

test('binIndex with a zero-length span', () => {
  assert.equal(binIndex(5, 5, 5, 100), 0);
});

test('barHeight is a log scale with a visible minimum', () => {
  assert.equal(barHeight(0, 100, 16), 0);
  assert.equal(barHeight(1, 100, 16), 3);
  assert.equal(barHeight(100, 100, 16), 16);
  assert.ok(barHeight(10, 100, 16) > 3 && barHeight(10, 100, 16) < 16);
  assert.equal(barHeight(1, 1, 16), 16);
});

test('binRange covers the selected bins and includes the final instant', () => {
  const b = { t0: 0, t1: 100, bins: 10 };
  assert.deepEqual(binRange(2, 3, b), { from: 20, to: 40 });
  assert.deepEqual(binRange(9, 7, b), { from: 70, to: 101 });
});

test('needlesFromQuery', () => {
  assert.deepEqual(needlesFromQuery('  sshd  "Failed" a sshd '), ['sshd', 'Failed']);
});

test('splitHighlight keeps every character and marks matches', () => {
  const text = 'GET /wp-login.php HTTP/1.1 <script>alert(1)</script>';
  const segs = splitHighlight(text, ['wp-login', 'SCRIPT']);
  assert.equal(segs.map((s) => s.text).join(''), text);
  assert.deepEqual(segs.filter((s) => s.hit).map((s) => s.text), ['wp-login', 'script', 'script']);
  assert.deepEqual(splitHighlight(text, ['SCRIPT'], true), [{ text, hit: false }]);
  assert.deepEqual(splitHighlight('', ['a']), []);
  assert.deepEqual(splitHighlight('abc', []), [{ text: 'abc', hit: false }]);
});

test('splitHighlight merges overlapping needles', () => {
  assert.deepEqual(splitHighlight('abcdef', ['abc', 'cde']), [
    { text: 'abcde', hit: true },
    { text: 'f', hit: false },
  ]);
});

test('fmtTime prints UTC in the chosen format and keeps invalid input', () => {
  assert.equal(fmtTime('2022-01-21T00:02:27+00:00'), '2022-01-21T00:02:27Z');
  assert.equal(fmtTime('2022-01-21T00:02:27+00:00', 'short'), '2022-01-21 00:02:27');
  assert.equal(fmtTime('nope', 'short'), 'nope');
});

test('fmtStep prints bin widths as short units', () => {
  assert.equal(fmtStep(10), '10 s');
  assert.equal(fmtStep(300), '5 min');
  assert.equal(fmtStep(3600), '1 h');
  assert.equal(fmtStep(10800), '3 h');
  assert.equal(fmtStep(86400 * 2), '2 d');
  assert.equal(fmtStep(90), '1 min 30 s');
});
