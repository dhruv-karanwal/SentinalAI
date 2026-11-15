// Pure helpers for the Study page: read values out of scores.json rows and pick the reference
// baselines. Nothing is computed that the result files do not contain.

export interface RateLike {
  covered: number;
  cases: number;
  rate: number | null;
}

export interface ScoreLike {
  coverage?: { event_label?: { reachable?: RateLike } };
  citation_precision?: { event_label: number | null } | undefined;
}

export interface RunLike<S extends ScoreLike = ScoreLike> {
  variant: string | null;
  scenario: string | null;
  arms: Record<string, S>;
  baselines: Record<string, S>;
}

export interface Ref {
  key: string;
  label: string;
  value: number;
  dash: string;
}

export const coverageOf = (r: ScoreLike | undefined): number | null => r?.coverage?.event_label?.reachable?.rate ?? null;
export const precisionOf = (r: ScoreLike | undefined): number | null => r?.citation_precision?.event_label ?? null;

/** cite-all (ceiling), the matched-k detector-order baseline (else the first detector-order row), and the noise control's same arm. */
export function refsFor<S extends ScoreLike>(run: RunLike<S>, noise: RunLike<S> | undefined, arm: string, metric: (r: S | undefined) => number | null): Ref[] {
  const out: Ref[] = [];
  const all = metric(run.baselines['cite-all']);
  if (all !== null) out.push({ key: 'all', label: 'cite-all (ceiling)', value: all, dash: '1 2' });
  const names = Object.keys(run.baselines).sort();
  const matched = names.find((k) => k.startsWith('cite-top-k-detector-order') && k.endsWith('-matched')) ?? names.find((k) => k.startsWith('cite-top-k-detector-order'));
  const mv = matched ? metric(run.baselines[matched]) : null;
  if (matched && mv !== null) out.push({ key: 'topk', label: matched, value: mv, dash: '4 2' });
  const nv = noise ? metric(noise.arms[arm]) : null;
  if (noise && nv !== null) out.push({ key: 'noise', label: `same arm on ${noise.variant}`, value: nv, dash: '6 2 1 2' });
  return out;
}

/** The noise-control run that belongs to a variant run (same scenario, variant noise-<variant>). */
export function noiseRunFor<R extends RunLike>(run: R, runs: readonly R[]): R | undefined {
  return runs.find((x) => x.variant === `noise-${run.variant}` && x.scenario === run.scenario);
}

/** Sort key of a prompt revision "<single>+<graph>": the -vN number of each part; "unknown" sorts
 * first. Same rule as backend app/study/revisions.py, so the page and study-stats agree on "latest". */
export function revisionKey(revision: string): string {
  if (revision === 'unknown') return '';
  return revision
    .split('+')
    .map((part) => String(Number(/v(\d+)$/.exec(part)?.[1] ?? 0)).padStart(6, '0'))
    .join('.');
}

export function latestRevision(revisions: readonly string[]): string | null {
  return revisions.length === 0 ? null : [...revisions].sort((a, b) => (revisionKey(a) < revisionKey(b) ? -1 : revisionKey(a) > revisionKey(b) ? 1 : 0)).at(-1)!;
}
