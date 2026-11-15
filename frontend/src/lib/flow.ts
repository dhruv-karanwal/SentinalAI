// Pure logic of the About page flows (DESIGN.md 7): the share split behind the detector marks and the
// position of every mark at each step of the "How it works" flow. The flow plays once: steps 0..4
// are the five pipeline stages, -1 is "not started". Positions are unitless multipliers that the
// stylesheet scales by tokens (stage = a fifth of the track, offsets in --sp-4 units).

export interface Share {
  key: string;
  n: number;
}

/** Split `total` marks over `counts` by their real shares (largest remainder). All zero = equal split. */
export function shareSplit(counts: ReadonlyArray<{ key: string; count: number }>, total: number): Share[] {
  if (counts.length === 0 || total <= 0) return counts.map((c) => ({ key: c.key, n: 0 }));
  const sum = counts.reduce((a, c) => a + Math.max(0, c.count), 0);
  const exact = counts.map((c) => ({ key: c.key, x: sum > 0 ? (Math.max(0, c.count) / sum) * total : total / counts.length }));
  const out = exact.map((e) => ({ key: e.key, n: Math.floor(e.x), r: e.x - Math.floor(e.x) }));
  let left = total - out.reduce((a, s) => a + s.n, 0);
  // ties keep the input order (stable sort)
  for (const s of [...out].sort((a, b) => b.r - a.r)) {
    if (left <= 0) break;
    s.n += 1;
    left -= 1;
  }
  return out.map(({ key, n }) => ({ key, n }));
}

/** Expand shares into one key per mark, interleaved so every detector shows across the whole set. */
export function interleave(shares: readonly Share[]): string[] {
  const total = shares.reduce((a, s) => a + s.n, 0);
  const placed = shares.map(() => 0);
  const out: string[] = [];
  for (let i = 0; i < total; i += 1) {
    // pick the share that is furthest behind its quota at this point
    let best = -1;
    let gap = -Infinity;
    shares.forEach((s, k) => {
      if (placed[k]! >= s.n) return;
      const g = ((i + 1) * s.n) / total - placed[k]!;
      if (g > gap) {
        gap = g;
        best = k;
      }
    });
    placed[best]! += 1;
    out.push(shares[best]!.key);
  }
  return out;
}

export const FLOW_LAST = 4;

export interface MarkPos {
  /** stage index 0..4 (the mark sits at the centre of that fifth of the track) */
  stage: number;
  /** offsets in --sp-4 units */
  dx: number;
  dy: number;
  shown: boolean;
  /** dropped at Verify (schematic: an unsupported citation) */
  dropped: boolean;
}

/** Marks that the Verify stage drops in the schematic: every fourth one. */
export const isDropped = (i: number): boolean => i % 4 === 3;

/** Where mark `i` of `n` is at `step` (-1 = before the run, 0..4 = the stages). */
export function markAt(i: number, n: number, step: number): MarkPos {
  const col = i % 4;
  const row = Math.floor(i / 4);
  const rows = Math.max(1, Math.ceil(n / 4));
  const mid = (rows - 1) / 2;
  if (step < 0) return { stage: 0, dx: (col - 1.5) * 4 - 6, dy: (row - mid) * 4, shown: false, dropped: false };
  if (step === 0) return { stage: 0, dx: (col - 1.5) * 4, dy: (row - mid) * 4, shown: true, dropped: false };
  // detect and triage onwards: the alerts sit grouped as one incident
  const grouped = { dx: (col - 1.5) * 2.5, dy: (row - mid) * 2.5 };
  if (step <= 2) return { stage: step, ...grouped, shown: true, dropped: false };
  const dropped = isDropped(i);
  if (step === 3) return dropped ? { stage: 3, dx: grouped.dx, dy: grouped.dy + 4, shown: false, dropped } : { stage: 3, ...grouped, shown: true, dropped };
  // report: the kept marks line up in one row
  const kept = Array.from({ length: i }, (_, k) => k).filter((k) => !isDropped(k)).length;
  const keptTotal = Array.from({ length: n }, (_, k) => k).filter((k) => !isDropped(k)).length;
  if (dropped) return { stage: 3, dx: grouped.dx, dy: grouped.dy + 4, shown: false, dropped };
  const perRow = 5;
  const r = Math.floor(kept / perRow);
  const c = kept % perRow;
  const inRow = Math.min(perRow, keptTotal - r * perRow);
  const rowCount = Math.ceil(keptTotal / perRow);
  return { stage: 4, dx: (c - (inRow - 1) / 2) * 2.5, dy: (r - (rowCount - 1) / 2) * 2.5, shown: true, dropped: false };
}

/** Milliseconds per step: one slow transition, the stagger over all marks, and one more slow beat to read it. */
export function stepMs(durSlow: number, stagger: number, n: number): number {
  return 2 * durSlow + stagger * Math.max(0, n - 1);
}

/** "250ms" / "0.25s" (a computed custom property) to milliseconds; unparseable = 0. */
export function parseMs(value: string): number {
  const v = value.trim();
  const m = /^(-?[\d.]+)(ms|s)$/.exec(v);
  if (!m) return 0;
  const n = Number(m[1]);
  if (!Number.isFinite(n)) return 0;
  return m[2] === 's' ? n * 1000 : n;
}
