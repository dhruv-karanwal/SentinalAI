// Time binning for the incident strip: any number of alerts becomes `bins` counts per detector.

export interface Tick {
  /** epoch seconds */
  t: number;
  detector: string;
}

export interface Binned {
  t0: number;
  t1: number;
  bins: number;
  /** detector -> count per bin */
  rows: Map<string, Uint32Array>;
  /** largest single-bin count over all detectors */
  max: number;
}

/** Bin index of time t in [t0, t1] split into `bins` equal parts; t1 falls in the last bin. */
export function binIndex(t: number, t0: number, t1: number, bins: number): number {
  if (bins <= 1 || t1 <= t0) return 0;
  const i = Math.floor(((t - t0) / (t1 - t0)) * bins);
  return Math.min(bins - 1, Math.max(0, i));
}

export function binTicks(ticks: readonly Tick[], t0: number, t1: number, bins: number, detectors: readonly string[]): Binned {
  const n = Math.max(1, Math.floor(bins));
  const rows = new Map<string, Uint32Array>();
  for (const d of detectors) rows.set(d, new Uint32Array(n));
  let max = 0;
  for (const tick of ticks) {
    let row = rows.get(tick.detector);
    if (!row) {
      row = new Uint32Array(n);
      rows.set(tick.detector, row);
    }
    const i = binIndex(tick.t, t0, t1, n);
    const v = ++row[i]!;
    if (v > max) max = v;
  }
  return { t0, t1, bins: n, rows, max };
}

/** Bar height in pixels on a log scale: 1 alert is always visible (minPx), `max` fills the row. */
export function barHeight(count: number, max: number, rowPx: number, minPx = 3): number {
  if (count <= 0) return 0;
  if (max <= 1) return rowPx;
  const h = minPx + ((rowPx - minPx) * Math.log(count)) / Math.log(max);
  return Math.min(rowPx, Math.max(minPx, Math.round(h)));
}

/** Time range [from, to) covered by bins a..b inclusive (order free). */
export function binRange(a: number, b: number, binned: Pick<Binned, 't0' | 't1' | 'bins'>): { from: number; to: number } {
  const lo = Math.min(a, b);
  const hi = Math.max(a, b);
  const w = (binned.t1 - binned.t0) / binned.bins;
  if (w <= 0) return { from: binned.t0, to: binned.t0 + 1 };
  // the last bin is closed on the right so the final alert is inside the range
  const to = hi >= binned.bins - 1 ? binned.t1 + 1 : binned.t0 + (hi + 1) * w;
  return { from: binned.t0 + lo * w, to };
}
