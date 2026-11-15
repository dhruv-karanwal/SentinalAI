// Motion helpers. Pure and tested; the hooks that drive them live in hooks.ts
// and components/motion.tsx. Everything here returns the final state when the duration is 0, which
// is what prefers-reduced-motion sets.

/** Index of the section a sticky stepper highlights: the last whose top is above `line` px. */
export function activeSection(tops: readonly number[], line: number): number {
  if (tops.length === 0) return -1;
  let idx = 0;
  tops.forEach((t, i) => {
    if (t <= line) idx = i;
  });
  return idx;
}

export function prefersReducedMotion(): boolean {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return false;
  }
}
