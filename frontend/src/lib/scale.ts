// Scales and ticks for the SVG chart module (DESIGN.md 11.3). Pure functions, no DOM: tested with
// `node --test`. Every scale is total: empty domains, one point and huge values give finite output.

export interface Scale {
  (v: number): number;
  domain: [number, number];
  range: [number, number];
  ticks: (count?: number) => number[];
  kind: 'linear' | 'log';
}

const finite = (v: number, fallback = 0): number => (Number.isFinite(v) ? v : fallback);

/** Linear scale; a zero-width domain maps everything to the middle of the range. */
export function linearScale(domain: [number, number], range: [number, number]): Scale {
  const [d0, d1] = [finite(domain[0]), finite(domain[1])];
  const [r0, r1] = range;
  const span = d1 - d0;
  const f = ((v: number) => (span === 0 ? (r0 + r1) / 2 : r0 + ((finite(v, d0) - d0) / span) * (r1 - r0))) as Scale;
  f.domain = [d0, d1];
  f.range = [r0, r1];
  f.kind = 'linear';
  f.ticks = (count = 5) => niceTicks(d0, d1, count);
  return f;
}

/**
 * "log1p" scale for counts: position of log10(1 + v), so 0 is drawn (a plain log scale cannot
 * draw a zero bin). Ticks are 0, 1, 10, 100, ... up to the domain maximum.
 */
export function logScale(domain: [number, number], range: [number, number]): Scale {
  const max = Math.max(0, finite(domain[1]));
  const inner = linearScale([0, Math.log10(1 + max)], range);
  const f = ((v: number) => inner(Math.log10(1 + Math.max(0, finite(v))))) as Scale;
  f.domain = [0, max];
  f.range = range;
  f.kind = 'log';
  f.ticks = () => logTicks(max);
  return f;
}

export function logTicks(max: number): number[] {
  const out = [0];
  if (!(max >= 1)) return out;
  for (let p = 1; p <= max * 1.0000001 && out.length < 20; p *= 10) out.push(p);
  return out;
}

/** Round step (1, 2, 5 x 10^n) ticks covering [min, max]; at least one tick. */
export function niceTicks(min: number, max: number, count = 5): number[] {
  let lo = finite(min);
  let hi = finite(max);
  if (lo > hi) [lo, hi] = [hi, lo];
  if (lo === hi) return [lo];
  const step = niceStep((hi - lo) / Math.max(1, count));
  const start = Math.ceil(lo / step - 1e-9) * step;
  const out: number[] = [];
  for (let v = start; v <= hi + step * 1e-9 && out.length < 1000; v += step) out.push(Number(v.toPrecision(12)));
  return out;
}

export function niceStep(raw: number): number {
  if (!(raw > 0) || !Number.isFinite(raw)) return 1;
  const exp = Math.floor(Math.log10(raw));
  const base = 10 ** exp;
  const f = raw / base;
  const m = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return m * base;
}

/** Upper end of a count axis: the next nice tick at or above max (1 for an empty chart). */
export function niceMax(max: number, count = 4): number {
  if (!(max > 0) || !Number.isFinite(max)) return 1;
  const step = niceStep(max / count);
  return Math.ceil(max / step - 1e-9) * step;
}

export interface Band {
  (i: number): number;
  bandwidth: number;
  step: number;
}

/** Equal bands for n items across the range, with `padding` (0..1) of each step left empty. */
export function bandScale(n: number, range: [number, number], padding = 0.1): Band {
  const count = Math.max(1, Math.floor(finite(n, 1)));
  const step = (range[1] - range[0]) / count;
  const pad = Math.min(0.9, Math.max(0, padding));
  const f = ((i: number) => range[0] + i * step + (step * pad) / 2) as Band;
  f.step = step;
  f.bandwidth = Math.max(0, step * (1 - pad));
  return f;
}

const TIME_STEPS = [1, 5, 10, 15, 30, 60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800];

export interface TimeTick {
  t: number;
  label: string;
}

/**
 * Ticks for an epoch-seconds axis, aligned to round UTC times. Labels show what changes: the
 * date at day steps, HH:MM below a day, HH:MM:SS below a minute; the first tick and each new day
 * carry the date.
 */
export function timeTicks(t0: number, t1: number, count = 6): TimeTick[] {
  const lo = finite(t0);
  const hi = finite(t1, lo);
  if (hi <= lo) return [{ t: lo, label: fmtUtc(lo, 'full') }];
  const raw = (hi - lo) / Math.max(1, count);
  const step = TIME_STEPS.find((s) => s >= raw) ?? Math.ceil(raw / 86400) * 86400;
  const out: TimeTick[] = [];
  let prevDay = '';
  for (let t = Math.ceil(lo / step) * step; t <= hi && out.length < 200; t += step) {
    const day = new Date(t * 1000).toISOString().slice(0, 10);
    const mode = step >= 86400 ? 'date' : step < 60 ? 'sec' : 'min';
    const label = day !== prevDay && mode !== 'date' ? `${day.slice(5)} ${fmtUtc(t, mode)}` : fmtUtc(t, mode);
    out.push({ t, label });
    prevDay = day;
  }
  return out;
}

export function fmtUtc(t: number, mode: 'full' | 'date' | 'min' | 'sec'): string {
  const d = new Date(finite(t) * 1000);
  if (Number.isNaN(d.getTime())) return String(t);
  const iso = d.toISOString();
  if (mode === 'date') return iso.slice(0, 10);
  if (mode === 'min') return iso.slice(11, 16);
  if (mode === 'sec') return iso.slice(11, 19);
  return iso.replace(/\.\d{3}Z$/, 'Z');
}

/** Axis labels for counts: 950, 1.2k, 45k, 3.4M. Exact values go in the tooltip. */
export function compact(n: number): string {
  const v = finite(n);
  const a = Math.abs(v);
  if (a < 1000) return String(Math.round(v * 100) / 100);
  if (a < 1e6) return `${trim(v / 1e3)}k`;
  if (a < 1e9) return `${trim(v / 1e6)}M`;
  return `${trim(v / 1e9)}B`;
}

const trim = (v: number): string => (Math.abs(v) >= 100 ? String(Math.round(v)) : String(Math.round(v * 10) / 10));

/** A share as a percentage with one decimal; null stays "n/a" (never 0 %). */
export function fmtPct(share: number | null | undefined, digits = 1): string {
  if (share === null || share === undefined || !Number.isFinite(share)) return 'n/a';
  return `${(share * 100).toFixed(digits)} %`;
}

/** Stack segments for one bar: cumulative [start, end) per series, in series order. */
export function stack(values: readonly number[]): Array<[number, number]> {
  let acc = 0;
  return values.map((v) => {
    const s = acc;
    acc += Math.max(0, finite(v));
    return [s, acc];
  });
}

/** Bin index range covered by a pixel span on a band axis (for brushing). */
export function bandRange(x0: number, x1: number, rangeStart: number, step: number, n: number): [number, number] {
  const a = Math.min(x0, x1);
  const b = Math.max(x0, x1);
  const lo = Math.max(0, Math.floor((a - rangeStart) / step));
  const hi = Math.min(n - 1, Math.floor((b - rangeStart) / step));
  return [Math.min(lo, n - 1), Math.max(lo, hi)];
}

/** Heat step 1..4 from log10 of the count relative to the largest cell. */
export function heatStep(v: number, max: number): number {
  if (v <= 0 || max <= 0) return 0;
  const r = Math.log10(1 + v) / Math.log10(1 + max);
  return r > 0.75 ? 4 : r > 0.5 ? 3 : r > 0.25 ? 2 : 1;
}

const BIN_STEPS_S = [60, 300, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 604800];

/** Events (epoch seconds + a series key) into aligned bins of a round step: at most ~target bins. */
export function binByKey(events: ReadonlyArray<{ t: number; key: string }>, target = 60): { start: number; step: number; bins: number; series: Record<string, number[]> } {
  if (events.length === 0) return { start: 0, step: 60, bins: 0, series: {} };
  let lo = Infinity;
  let hi = -Infinity;
  for (const e of events) {
    if (e.t < lo) lo = e.t;
    if (e.t > hi) hi = e.t;
  }
  const span = hi - lo;
  const step = BIN_STEPS_S.find((x) => span / x <= target) ?? Math.ceil(span / target / 86400) * 86400;
  const start = Math.floor(lo / step) * step;
  const bins = Math.floor((hi - start) / step) + 1;
  const series: Record<string, number[]> = {};
  for (const e of events) {
    const row = (series[e.key] ??= new Array<number>(bins).fill(0));
    row[Math.floor((e.t - start) / step)]! += 1;
  }
  return { start, step, bins, series };
}
