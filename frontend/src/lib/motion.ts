// Motion helpers (DESIGN.md section 13). Pure and tested; the hooks that drive them live in hooks.ts
// and components/motion.tsx. Everything here returns the final state when the duration is 0, which
// is what prefers-reduced-motion sets.

export const easeOutCubic = (t: number): number => {
  const c = Math.min(1, Math.max(0, t));
  return 1 - (1 - c) ** 3;
};

/** The integer shown by a counter `elapsed` ms into a `duration` ms count-up to `value`. */
export function countAt(value: number, elapsed: number, duration: number): number {
  if (duration <= 0 || elapsed >= duration) return value;
  return Math.round(value * easeOutCubic(elapsed / duration));
}

/** Index of the section a sticky stepper highlights: the last whose top is above `line` px. */
export function activeSection(tops: readonly number[], line: number): number {
  if (tops.length === 0) return -1;
  let idx = 0;
  tops.forEach((t, i) => {
    if (t <= line) idx = i;
  });
  return idx;
}

/** Position in [0, 1) along a looping path for a packet with `offset` (fraction of a cycle). */
export function packetT(nowMs: number, cycleMs: number, offset: number): number {
  const t = (nowMs / cycleMs + offset) % 1;
  return t < 0 ? t + 1 : t;
}

export function prefersReducedMotion(): boolean {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return false;
  }
}
