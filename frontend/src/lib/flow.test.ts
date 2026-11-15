import assert from 'node:assert/strict';
import { test } from 'node:test';

import { FLOW_LAST, interleave, isDropped, markAt, parseMs, shareSplit, stepMs } from './flow.ts';

test('shareSplit keeps the total and follows the real shares', () => {
  const s = shareSplit([{ key: 'wazuh', count: 700 }, { key: 'suricata', count: 200 }, { key: 'aminer', count: 100 }], 12);
  assert.equal(s.reduce((a, x) => a + x.n, 0), 12);
  assert.deepEqual(s.map((x) => x.n), [8, 3, 1]); // 8.4, 2.4, 1.2 -> floors 8, 2, 1, one remainder to the largest (0.4 tie: first)
  assert.deepEqual(shareSplit([{ key: 'a', count: 0 }, { key: 'b', count: 0 }], 4).map((x) => x.n), [2, 2]);
  assert.deepEqual(shareSplit([], 10), []);
});

test('interleave spreads every key over the set', () => {
  const out = interleave([{ key: 'a', n: 2 }, { key: 'b', n: 2 }]);
  assert.equal(out.length, 4);
  assert.notEqual(out[0], out[1]);
  assert.equal(out.filter((k) => k === 'a').length, 2);
});

test('markAt: hidden before the run, all shown at ingest, dropped ones gone at verify, final row at report', () => {
  const n = 12;
  for (let i = 0; i < n; i += 1) {
    assert.equal(markAt(i, n, -1).shown, false);
    assert.equal(markAt(i, n, 0).shown, true);
    assert.equal(markAt(i, n, 0).stage, 0);
    assert.equal(markAt(i, n, 2).stage, 2);
    const last = markAt(i, n, FLOW_LAST);
    assert.equal(last.shown, !isDropped(i));
    if (!isDropped(i)) assert.equal(last.stage, 4);
  }
  assert.equal(Array.from({ length: n }, (_, i) => markAt(i, n, 3)).filter((m) => m.dropped).length, 3);
  // kept marks never overlap at the end
  const ends = Array.from({ length: n }, (_, i) => markAt(i, n, FLOW_LAST)).filter((m) => m.shown).map((m) => `${m.dx},${m.dy}`);
  assert.equal(new Set(ends).size, ends.length);
});

test('stepMs and parseMs read the duration tokens; reduced motion (0) gives 0', () => {
  assert.equal(parseMs('250ms'), 250);
  assert.equal(parseMs(' 0.25s'), 250);
  assert.equal(parseMs('0ms'), 0);
  assert.equal(parseMs(''), 0);
  assert.equal(stepMs(250, 30, 12), 830);
  assert.equal(stepMs(0, 0, 12), 0);
});
