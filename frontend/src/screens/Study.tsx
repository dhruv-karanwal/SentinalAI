// Study page: "What do the finished runs say so far?" Matched-budget results rendered from the
// result files (GET /study/results), by study part in tabs. Only numbers that are in scores.json
// are drawn: no interpolation, no invented intervals. FakeClient runs are excluded by the API and
// only counted here.

import { useMemo, useState } from 'react';

import { api, type ScoreRow, type StudyRun } from '../api.ts';
import { DotPairs, HBars } from '../charts/Bars.tsx';
import { ChartFrame, type LegendItem } from '../charts/ChartFrame.tsx';
import { Disclosure, ErrorState, Page, PageHeader, Tabs } from '../components/ui.tsx';
import { useLoad, useScreenContext } from '../hooks.ts';
import { Term } from '../components/Term.tsx';
import { Icon } from '../icons.tsx';
import { fmtDuration, fmtInt } from '../lib/format.ts';
import { fmtPct, heatStep } from '../lib/scale.ts';
import { coverageOf, noiseRunFor, precisionOf, refsFor } from '../lib/study.ts';
import { DashSkeleton } from './Overview.tsx';

const ARMS = ['single', 'single+verifier', 'graph', 'graph+verifier'];
const LABEL = 'dev scenarios, pilot numbers, not paper results';
const PURPOSE = 'What do the finished runs say so far?';
type Part = 'pilot' | 'held-out' | 'adhoc';
const PART_ORDER: readonly Part[] = ['pilot', 'held-out', 'adhoc'];
const PART_NAME: Record<Part, string> = { pilot: 'Pilot', 'held-out': 'Final (held-out)', adhoc: 'Ad hoc' };
const PART_TEXT: Record<string, string> = {
  pilot: 'The matched-budget pilot on the dev scenarios (run-pilot).',
  'held-out': 'Final runs on the held-out scenarios, after the protocol freeze.',
  adhoc: 'Single runs made by hand (run-matched), e.g. smoke tests; not part of the pilot.',
};
/** scores.json says which part of the study a run belongs to; older files without it are dev pilot material. */
const partOfRun = (r: StudyRun): string => r.study_part ?? (r.split === 'held-out' ? 'held-out' : 'pilot');

const cov = (r: ScoreRow | undefined): number | null => coverageOf(r);
const prec = (r: ScoreRow | undefined): number | null => precisionOf(r);

export function StudyScreen() {
  const { data, error, reload } = useLoad((signal) => api.study(signal), []);
  const allRuns = useMemo(() => data?.runs ?? [], [data]);
  const truncations = useMemo(() => [...new Set(allRuns.map((r) => r.truncation ?? 'unknown'))].sort(), [allRuns]);
  const [trunc, setTrunc] = useState<string | null>(null);
  const t = trunc ?? truncations[0] ?? null;
  const counts = useMemo(() => Object.fromEntries(PART_ORDER.map((p) => [p, allRuns.filter((r) => partOfRun(r) === p).length])) as Record<Part, number>, [allRuns]);
  const [partPick, setPartPick] = useState<Part | null>(null);
  const part: Part = partPick ?? PART_ORDER.find((p) => counts[p] > 0) ?? 'pilot';
  const runs = useMemo(() => allRuns.filter((r) => (r.truncation ?? 'unknown') === t && partOfRun(r) === part), [allRuns, t, part]);
  const main = runs.filter((r) => !(r.variant ?? '').startsWith('noise-'));
  const noiseFor = (r: StudyRun) => noiseRunFor(r, runs);
  const parts = [...new Set(allRuns.map(partOfRun))];
  useScreenContext(
    'study',
    data
      ? `Study page. ${data.runs.length} finished runs with a real model (${parts.join(', ') || 'none'}); ${data.incomplete_runs} runs without scores yet; ${data.excluded_fake_runs} fake-model runs excluded. ${data.runs.length === 0 ? 'No results to show yet: the page is empty on purpose.' : 'Charts: coverage of reachable attack phases, citation precision, unsupported-claim rate before and after the verifier, tokens per arm, detector variant by arm.'}`
      : '',
  );

  if (error && !data) return <ErrorState what="study results" error={error} onRetry={reload} />;
  if (!data) return <DashSkeleton title="Study" purpose={PURPOSE} />;
  return (
    <Page>
      <PageHeader
        title="Study"
        purpose={PURPOSE}
        actions={
          truncations.length > 1 ? (
            <span className="segmented" role="group" aria-label="Truncation rule">
              {truncations.map((x) => (
                <button key={x} type="button" className="btn" aria-pressed={x === t} onClick={() => setTrunc(x)}>
                  {x}
                </button>
              ))}
            </span>
          ) : undefined
        }
      />
      <p className="study-notice" role="note">
        <Icon name="warning" />
        <span>
          <strong>{parts.includes('held-out') ? 'Contains final (held-out) runs; pilot runs are marked pilot.' : `${LABEL.charAt(0).toUpperCase()}${LABEL.slice(1)}.`}</strong> Headline: event_label coverage on alert-reachable phases, after the verifier. Held-out scenarios stay untouched until the protocol is frozen.
        </span>
      </p>
      <Disclosure summary="What this page shows">
        <div className="study-explain">
          <p>
            The same <Term id="agent">investigation agent</Term> and <Term id="multi-agent">multi-agent graph</Term> run on the same cases with different alert sources (Wazuh, Suricata, AMiner, all fused, and the <Term id="oracle">oracle</Term> and{' '}
            <Term id="noise">noise</Term> controls), under a <Term id="matched-budget">matched budget</Term>. Each arm is scored before and after the <Term id="verifier">evidence verifier</Term>, next to simple <Term id="baseline">baselines</Term>.
          </p>
          <p>
            It answers the research question: how much does the alert source change how many attack steps are found (<Term id="coverage">coverage</Term> of <Term id="reachable-phase">reachable phases</Term>) and how often the AI claims things the evidence does not support (<Term id="unsupported-claim">unsupported claims</Term>)?
          </p>
          <p className="faint">Every number is read from the run files (scores.json). Nothing is typed in, estimated or interpolated; the files carry no confidence intervals, so none are drawn.</p>
        </div>
      </Disclosure>
      {data.runs.length === 0 ? (
        <section className="card study-empty" aria-labelledby="st-empty-t">
          <h2 id="st-empty-t">No results yet: this page is empty on purpose</h2>
          <p>
            No matched run with a real model has finished. Results appear when <span className="mono">run-pilot</span> (or <span className="mono">run-matched</span>) writes <span className="mono">scores.json</span> under data/processed/runs/. Then this page shows, per alert source and arm:
          </p>
          <ul>
            <li>coverage of the reachable attack phases, next to the cite-all ceiling, matched top-k and the noise control</li>
            <li>citation precision</li>
            <li>the unsupported-claim rate before and after the verifier</li>
            <li>tokens and latency per arm, and coverage by detector variant and arm</li>
          </ul>
          {(data.excluded_fake_runs > 0 || data.incomplete_runs > 0) && (
            <p className="faint">
              {data.excluded_fake_runs > 0 && `${data.excluded_fake_runs} FakeClient run${data.excluded_fake_runs === 1 ? ' was' : 's were'} excluded (plumbing checks, never results). `}
              {data.incomplete_runs > 0 && `${data.incomplete_runs} run${data.incomplete_runs === 1 ? ' is' : 's are'} incomplete (no scores.json yet).`}
            </p>
          )}
        </section>
      ) : (
        <section className="sec" aria-label="Runs by study part">
          <Tabs tabs={PART_ORDER.map((p) => ({ id: p, label: PART_NAME[p], count: fmtInt(counts[p]) }))} value={part} onChange={setPartPick} label="Study part" idBase="st" inset />
          <div className="tab-panel tab-enter" key={`${part}:${t}`} role="tabpanel" id={`st-panel-${part}`} aria-labelledby={`st-tab-${part}`}>
            <p className="study-meta">
              {PART_TEXT[part]} {fmtInt(runs.length)} run{runs.length === 1 ? '' : 's'} · truncation {t} · {data.excluded_fake_runs} FakeClient run{data.excluded_fake_runs === 1 ? '' : 's'} excluded · {data.incomplete_runs} incomplete
            </p>
            {runs.length === 0 ? (
              <div className="card study-empty">
                <h2>No {PART_NAME[part].toLowerCase()} runs{truncations.length > 1 ? ` with truncation ${t}` : ''} yet</h2>
                <p>The charts for this part appear when one of its runs writes scores.json.</p>
              </div>
            ) : (
              <div className="grid-12">
                <div className="col-12">
                  <CoverageChart runs={main} noiseFor={noiseFor} metric={cov} title="Coverage: event_label, alert-reachable phases" question="Does an arm cover more attack phases than citing by detector order, and how close does it get to citing everything?" />
                </div>
                <div className="col-12">
                  <CoverageChart runs={main} noiseFor={noiseFor} metric={prec} title="Citation precision (event_label)" question="Of the alerts an arm cites, what share are attack-labelled?" />
                </div>
                <div className="col-6">
                  <ClaimsChart runs={main} />
                </div>
                <div className="col-6">
                  <CostChart runs={main} />
                </div>
                <div className="col-12">
                  <HeatTable runs={runs} />
                </div>
              </div>
            )}
          </div>
        </section>
      )}
    </Page>
  );
}

function CoverageChart({ runs, noiseFor, metric, title, question }: { runs: StudyRun[]; noiseFor: (r: StudyRun) => StudyRun | undefined; metric: (r: ScoreRow | undefined) => number | null; title: string; question: string }) {
  const rows = runs.flatMap((run) =>
    ARMS.filter((a) => metric(run.arms[a]) !== null).map((arm) => {
      const v = metric(run.arms[arm])!;
      const r = run.arms[arm]?.coverage?.event_label?.reachable;
      return {
        key: `${run.run_id}:${arm}`,
        label: (
          <span>
            <span className="faint">{run.scenario}</span> <span className="mono">{run.variant}</span> · {arm}
          </span>
        ),
        text: `${run.scenario} ${run.variant} ${arm}`,
        value: v,
        display: fmtPct(v),
        tone: arm.endsWith('verifier') ? ('verified' as const) : ('muted' as const),
        detail: r ? [`${r.covered} of ${r.cases} reachable attack cases`] : [],
        refs: refsFor(run, noiseFor(run), arm, metric),
      };
    }),
  );
  const legend: LegendItem[] = [
    { key: 'v', label: 'after verifier (headline)', tone: 'verified' },
    { key: 'b', label: 'before verifier', tone: 'muted' },
    { key: 'all', label: 'cite-all ceiling', tone: 'ref', mark: 'ref', dash: '1 2' },
    { key: 'k', label: 'top-k detector order, matched k', tone: 'ref', mark: 'ref', dash: '4 2' },
    { key: 'n', label: 'noise control (same arm)', tone: 'ref', mark: 'ref', dash: '6 2 1 2' },
  ];
  return (
    <ChartFrame
      title={title}
      question={question}
      legend={legend}
      table={{ columns: ['run', 'arm', 'value', 'references'], rows: rows.map((r) => [r.text, r.key.split(':')[1] ?? '', fmtPct(r.value), r.refs.map((f) => `${f.label} ${fmtPct(f.value)}`).join('; ')]) }}
      empty={rows.length === 0 ? 'The result files carry no value for this measure.' : undefined}
      note={`${LABEL}. Shares over cases; the files carry no confidence intervals, so none are drawn.`}
    >
      <HBars rows={rows} unit="" pct max={1} />
    </ChartFrame>
  );
}

function ClaimsChart({ runs }: { runs: StudyRun[] }) {
  const rows = runs.flatMap((run) =>
    ['single', 'graph'].map((arm) => ({
      key: `${run.run_id}:${arm}`,
      label: `${run.scenario} ${run.variant} · ${arm}`,
      before: run.arms[arm]?.unsupported_claim_rate ?? null,
      after: run.arms[`${arm}+verifier`]?.unsupported_claim_rate ?? null,
    })),
  );
  return (
    <ChartFrame
      title="Unsupported-claim rate"
      question="How often do the arms claim something the evidence does not support, and what does the verifier remove?"
      legend={[
        { key: 'b', label: 'before verifier (hallucination measure)', tone: 'muted', mark: 'hollow' },
        { key: 'a', label: 'after verifier', tone: 'verified', mark: 'dot' },
      ]}
      table={{ columns: ['run, arm', 'before verifier', 'after verifier'], rows: rows.map((r) => [r.label, fmtPct(r.before), fmtPct(r.after)]) }}
      note={`${LABEL}. Axis 0 % to 100 % of claims.`}
    >
      <DotPairs rows={rows} beforeLabel="before verifier" afterLabel="after verifier" />
    </ChartFrame>
  );
}

function CostChart({ runs }: { runs: StudyRun[] }) {
  const rows = runs.flatMap((run) =>
    ['single', 'graph'].map((arm) => {
      const r = run.arms[arm]?.runs;
      const tokens = r ? r.input_tokens + r.output_tokens : 0;
      return {
        key: `${run.run_id}:${arm}`,
        label: `${run.scenario} ${run.variant} · ${arm}`,
        text: `${run.variant} ${arm}`,
        value: tokens,
        tone: 'ref' as const,
        detail: r ? [`input ${fmtInt(r.input_tokens)}, output ${fmtInt(r.output_tokens)}`, `latency ${fmtDuration(r.latency_seconds)} over ${run.cases} cases`, `${fmtInt(r.tool_calls)} tool calls, ${r.budget_hit} budget stops`] : ['no run summary'],
      };
    }),
  );
  return (
    <ChartFrame
      title="Tokens and latency per arm"
      question="What does each arm cost under the same budget?"
      table={{ columns: ['run, arm', 'tokens', 'detail'], rows: rows.map((r) => [r.text, r.value, r.detail.join('; ')]) }}
      note={`${LABEL}. Tokens = input + output over all cases of the run; latency in the tooltip.`}
    >
      <HBars rows={rows} unit="tokens" />
    </ChartFrame>
  );
}

function HeatTable({ runs }: { runs: StudyRun[] }) {
  const byVariant = new Map<string, StudyRun>();
  for (const r of runs) if (r.variant) byVariant.set(`${r.scenario}/${r.variant}`, r);
  const keys = [...byVariant.keys()].sort();
  return (
    <ChartFrame
      title="Detector variant by arm"
      question="Which alert source helps which arm? (event_label coverage, reachable phases)"
      table={{ columns: ['scenario / variant', ...ARMS], rows: keys.map((k) => [k, ...ARMS.map((a) => fmtPct(cov(byVariant.get(k)!.arms[a])))]) }}
      note={`${LABEL}. The value is printed in every cell; shade only repeats it.`}
    >
      <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th>Scenario / variant</th>
            {ARMS.map((a) => (
              <th key={a} className="right">
                {a}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {keys.map((k) => (
            <tr key={k}>
              <td className="mono">{k}</td>
              {ARMS.map((a) => {
                const v = cov(byVariant.get(k)!.arms[a]);
                return (
                  <td key={a} className="heatcell" data-step={v === null ? 0 : heatStep(v * 100, 100)}>
                    {fmtPct(v, 0)}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      </div>
    </ChartFrame>
  );
}
