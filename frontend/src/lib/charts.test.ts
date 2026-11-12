import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { contrast, readThemes } from './contrast.ts';
import { coverageOf, noiseRunFor, refsFor } from './study.ts';
import { fnv1a, layout, PAD } from './graph.ts';
import { bandRange, bandScale, binByKey, compact, heatStep, fmtPct, linearScale, logScale, logTicks, niceMax, niceStep, niceTicks, stack, timeTicks } from './scale.ts';

// ---- scales ---------------------------------------------------------------------------------

test('linear scale maps the domain onto the range and survives a zero-width domain', () => {
  const s = linearScale([0, 100], [0, 200]);
  assert.equal(s(50), 100);
  assert.equal(s(0), 0);
  assert.equal(s(100), 200);
  const flat = linearScale([5, 5], [0, 10]);
  assert.equal(flat(5), 5);
  assert.equal(flat(999), 5);
  assert.equal(linearScale([0, 1], [0, 10])(Number.NaN), 0);
});

test('log1p scale draws zero, orders values, handles huge counts', () => {
  const s = logScale([0, 11208], [100, 0]);
  assert.equal(s(0), 100);
  assert.equal(Math.round(s(11208)), 0);
  assert.ok(s(10) > s(100));
  assert.deepEqual(logTicks(11208), [0, 1, 10, 100, 1000, 10000]);
  assert.deepEqual(logTicks(0), [0]);
  const huge = logScale([0, 1e15], [0, 1]);
  assert.ok(Number.isFinite(huge(1e15)) && huge(1e15) <= 1.0000001);
  assert.equal(logScale([0, 0], [0, 10])(0), 5);
});

test('nice ticks, steps and max', () => {
  assert.deepEqual(niceTicks(0, 10, 5), [0, 2, 4, 6, 8, 10]);
  assert.deepEqual(niceTicks(0, 1, 4), [0, 0.5, 1]);
  assert.deepEqual(niceTicks(3, 3), [3]);
  assert.deepEqual(niceTicks(10, 0, 5), [0, 2, 4, 6, 8, 10]);
  assert.equal(niceStep(0), 1);
  assert.equal(niceStep(7), 10);
  assert.equal(niceStep(0.3), 0.5);
  assert.equal(niceMax(0), 1);
  assert.equal(niceMax(11208), 15000); // step 5000 for 4 ticks
  assert.equal(niceMax(1), 1);
  const t = niceTicks(0, 9.99e12, 4);
  assert.ok(t.length >= 2 && t.every(Number.isFinite));
});

test('band scale divides the range and keeps a positive bandwidth', () => {
  const b = bandScale(4, [0, 100], 0.2);
  assert.equal(b.step, 25);
  assert.equal(b.bandwidth, 20);
  assert.equal(b(0), 2.5);
  const one = bandScale(0, [0, 50]);
  assert.equal(one.step, 50);
  assert.deepEqual(bandRange(30, 10, 0, 25, 4), [0, 1]);
  assert.deepEqual(bandRange(-50, 500, 0, 25, 4), [0, 3]);
});

test('time ticks align to round UTC times and label dates', () => {
  const t0 = Date.UTC(2022, 0, 21, 0, 0, 1) / 1000;
  const t1 = Date.UTC(2022, 0, 24, 23, 39, 13) / 1000;
  const ticks = timeTicks(t0, t1, 6);
  assert.ok(ticks.length >= 3 && ticks.length <= 12);
  for (const k of ticks) assert.equal(k.t % 3600, 0);
  const short = timeTicks(1000, 1222, 4);
  assert.ok(short.every((k) => /\d\d:\d\d/.test(k.label)));
  assert.equal(timeTicks(5, 5).length, 1);
  assert.equal(timeTicks(5, 1).length, 1);
});

test('compact numbers, shares and stacks', () => {
  assert.equal(compact(950), '950');
  assert.equal(compact(11208), '11.2k');
  assert.equal(compact(450000), '450k');
  assert.equal(compact(3_400_000), '3.4M');
  assert.equal(compact(Number.POSITIVE_INFINITY), '0');
  assert.equal(fmtPct(0.4658), '46.6 %');
  assert.equal(fmtPct(null), 'n/a');
  assert.equal(fmtPct(0), '0.0 %');
  assert.deepEqual(stack([3, 0, 2]), [[0, 3], [3, 3], [3, 5]]);
  assert.deepEqual(stack([]), []);
  assert.deepEqual(stack([-1, 2]), [[0, 0], [0, 2]]);
});

test('heat steps are 0 for empty cells and 4 for the largest', () => {
  assert.equal(heatStep(0, 100), 0);
  assert.equal(heatStep(5, 0), 0);
  assert.equal(heatStep(100, 100), 4);
  assert.equal(heatStep(1, 14487), 1);
  assert.ok(heatStep(500, 14487) >= 2);
});

test('binByKey counts every event once in aligned bins', () => {
  const ev = [
    { t: 3600, key: 'a' },
    { t: 3601, key: 'b' },
    { t: 3600 + 86400, key: 'a' },
  ];
  const r = binByKey(ev, 60);
  assert.equal(r.start % r.step, 0);
  assert.equal(Object.values(r.series).flat().reduce((x, y) => x + y, 0), 3);
  assert.equal(r.series.a!.length, r.bins);
  assert.deepEqual(binByKey([]), { start: 0, step: 60, bins: 0, series: {} });
  assert.equal(binByKey([{ t: 5, key: 'x' }]).bins, 1);
});

// ---- layout ---------------------------------------------------------------------------------

test('fnv1a matches the reference values', () => {
  assert.equal(fnv1a('a'), 0xe40c292c);
  assert.equal(fnv1a(''), 0x811c9dc5);
});

test('layout is deterministic, bounded and handles 0, 1 and 60 nodes', () => {
  const ids = Array.from({ length: 60 }, (_, i) => `host:10.0.0.${i}`);
  const edges = ids.map((id, i) => [id, ids[(i * 7) % 60]!] as const);
  const a = layout(ids, edges, 600, 400);
  assert.deepEqual(a, layout(ids, edges, 600, 400));
  for (const p of a) assert.ok(p.x >= PAD && p.x <= 600 - PAD && p.y >= PAD && p.y <= 400 - PAD);
  assert.deepEqual(layout([], [], 10, 10), []);
  assert.deepEqual(layout(['x'], [], 100, 80), [{ id: 'x', x: 50, y: 40 }]);
});

test('layout reproduces the Python fixture exactly', () => {
  const spec = JSON.parse(readFileSync(new URL('./graph.fixture.json', import.meta.url), 'utf-8')) as {
    nodes: string[];
    edges: Array<[string, string]>;
    width: number;
    height: number;
    expected: Array<[number, number]>;
  };
  const got = layout(spec.nodes, spec.edges, spec.width, spec.height).map((p) => [p.x, p.y]);
  assert.deepEqual(got, spec.expected);
});

// ---- contrast of the tokens -----------------------------------------------------------------

test('chart and text tokens meet WCAG contrast in both themes', () => {
  const themes = readThemes(readFileSync(new URL('../tokens.css', import.meta.url), 'utf-8'));
  for (const [name, t] of Object.entries(themes)) {
    const surfaces = ['--bg', '--surface', '--raised'].map((k) => t[k]!);
    for (const s of surfaces) {
      for (const k of ['--text', '--text-muted', '--text-faint', '--accent', '--sev-high', '--sev-medium', '--sev-low', '--det-wazuh', '--det-suricata', '--det-aminer']) {
        assert.ok(contrast(t[k]!, s) >= 4.5, `${name} ${k} on ${s}: ${contrast(t[k]!, s).toFixed(2)}`);
      }
      assert.ok(contrast(t['--ref']!, s) >= 3, `${name} --ref on ${s}`);
    }
    for (const k of ['--heat-1', '--heat-2', '--heat-3', '--heat-4']) {
      assert.ok(contrast(t['--text']!, t[k]!) >= 4.5, `${name} text on ${k}: ${contrast(t['--text']!, t[k]!).toFixed(2)}`);
    }
  }
});

test('study reference lines come only from values in the result file', () => {
  const rate = (r: number | null) => ({ coverage: { event_label: { reachable: { covered: 0, cases: 0, rate: r } } } });
  const run = {
    variant: 'wazuh',
    scenario: 'russellmitchell',
    arms: { 'graph+verifier': rate(0.5) },
    baselines: { 'cite-all': rate(0.9), 'cite-top-k-detector-order@k5': rate(0.3), 'cite-top-k-detector-order@k3-matched': rate(0.4), 'cite-none': rate(null) },
  };
  const noise = { ...run, variant: 'noise-wazuh', arms: { 'graph+verifier': rate(0.1) } };
  const refs = refsFor(run, noise, 'graph+verifier', coverageOf);
  assert.deepEqual(refs.map((r) => [r.key, r.value]), [['all', 0.9], ['topk', 0.4], ['noise', 0.1]]);
  assert.equal(refs[1]!.label, 'cite-top-k-detector-order@k3-matched');
  assert.equal(noiseRunFor(run, [run, noise]), noise);
  const bare = { ...run, baselines: {} };
  assert.deepEqual(refsFor(bare, undefined, 'graph+verifier', coverageOf), []);
  assert.equal(coverageOf(undefined), null);
});
