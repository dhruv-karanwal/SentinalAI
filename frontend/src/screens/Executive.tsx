// Executive view (read-only, printable): severity trend, top risks, ATT&CK coverage, time to
// review, open approvals. A plain-language caption under each chart; no raw records.

import { api } from '../api.ts';
import { ChainStrip } from '../charts/Attack.tsx';
import { HBars } from '../charts/Bars.tsx';
import { ChartFrame, sevTone } from '../charts/ChartFrame.tsx';
import { Button, ErrorState, SeverityCell, SkeletonLines, Time } from '../components/ui.tsx';
import { buildHash, useApp, useElementSize, useLoad } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { fmtDuration, fmtInt } from '../lib/format.ts';
import { bandScale, compact, linearScale, niceMax } from '../lib/scale.ts';
import { useTip } from '../charts/ChartFrame.tsx';
import { sevLevel } from './Overview.tsx';
import { Term } from '../components/Term.tsx';
import { distinctLabels, incidentLabel } from '../lib/explain.ts';
import { useScreenContext } from '../hooks.ts';

const SEVS = ['High', 'Medium', 'Low'] as const;

export function ExecutiveScreen({ scenario }: { scenario: string }) {
  const { session } = useApp();
  const { data, error, reload } = useLoad((signal) => api.executive(scenario, signal), [scenario]);
  if (error && !data) return <ErrorState what="the executive summary" error={error} onRetry={reload} />;
  if (!data) return <SkeletonLines lines={8} />;
  const observed = data.coverage.filter((c) => c.alerts > 0);
  const high = data.severity_trend.reduce((s, d) => s + d.High, 0);
  return <ExecutiveBody data={data} scenario={scenario} role={session.role} high={high} observed={observed} />;
}

function ExecutiveBody({ data, scenario, role, high, observed }: { data: import('../api.ts').Executive; scenario: string; role: string; high: number; observed: Array<{ name: string }> }) {
  const q = data.queue;
  const ttr = data.time_to_review;
  const session = { role };
  const labels = distinctLabels(data.top_risks);
  useScreenContext(
    'executive',
    `Executive summary of ${scenario}. Open incidents: High ${q.open_by_severity.High ?? 0}, Medium ${q.open_by_severity.Medium ?? 0}, Low ${q.open_by_severity.Low ?? 0}. Reviewed ${ttr.reviewed}, not reviewed ${ttr.unreviewed}. Pending approvals ${data.open_approvals.pending}. ATT&CK tactics observed: ${observed.map((c) => c.name).join(', ') || 'none'}. Top risks: ${data.top_risks.map((r) => `${r.severity} ${incidentLabel(r)} (${r.alerts} alerts)`).join('; ')}.`,
  );
  return (
    <div className="page draw-charts">
      <div className="page-head">
        <h1>Executive summary</h1>
        <span className="muted">
          {scenario} · dataset replay (AIT-ADS dev scenario) · read-only{session.role === 'executive' ? '' : ` · viewed as ${session.role}`}
        </span>
        <span className="spacer" />
        <Button icon="print" className="no-print" onClick={() => window.print()}>
          Print
        </Button>
      </div>
      <div className="page-body" style={{ maxWidth: 1180 }}>
        <div className="statusrow">
          <div className="status-cell">
            <div className="k">
              Open <Term id="incident">incidents</Term>
            </div>
            <div className="v">
              {SEVS.map((s) => (
                <span key={s}>
                  <SeverityCell value={s} /> <span className="num">{fmtInt(q.open_by_severity[s] ?? 0)}</span>
                </span>
              ))}
            </div>
          </div>
          <div className="status-cell">
            <div className="k">Time to review (median)</div>
            <div className="v num">{ttr.median_seconds === null ? 'none yet' : fmtDuration(ttr.median_seconds)}</div>
            <div className="s">
              {fmtInt(ttr.reviewed)} reviewed, {fmtInt(ttr.unreviewed)} not yet
            </div>
          </div>
          <div className="status-cell">
            <div className="k">Open approvals</div>
            <div className="v num">{fmtInt(data.open_approvals.pending)}</div>
            <div className="s">{data.open_approvals.oldest_utc ? <>oldest since <Time ts={data.open_approvals.oldest_utc} /></> : 'nothing waiting'}</div>
          </div>
          <div className="status-cell">
            <div className="k">
              <Term id="attack-tactic">ATT&amp;CK tactics</Term> observed
            </div>
            <div className="v num">
              {observed.length} of {data.coverage.length}
            </div>
            <div className="s">from the deterministic mapping</div>
          </div>
        </div>

        <ChartFrame
          title="Incidents by first-seen day"
          question="Is the severe part of the workload growing or shrinking?"
          legend={SEVS.map((s) => ({ key: s, label: s, tone: sevTone(s) }))}
          table={{ columns: ['day (UTC)', ...SEVS], rows: data.severity_trend.map((d) => [d.day, d.High, d.Medium, d.Low]) }}
          empty={data.severity_trend.length === 0 ? 'No incidents yet.' : undefined}
        >
          <DayBars days={data.severity_trend} />
          <p className="chart-note">
            In plain words: {fmtInt(high)} High incident{high === 1 ? '' : 's'} over {data.severity_trend.length} day{data.severity_trend.length === 1 ? '' : 's'} of replayed data; days are the
            dates in the 2022 dataset, not today's dates.
          </p>
        </ChartFrame>

        <div className="grid-2">
          <ChartFrame
            title="Top risks"
            question="Which open incidents deserve attention first?"
            term="incident-severity"
            table={{ columns: ['incident', 'main host or IP, first seen (data date)', 'severity', 'why', 'alerts'], rows: data.top_risks.map((r) => [r.incident_id, labels.get(r.incident_id) ?? incidentLabel(r), r.severity, r.rule?.rule ?? '', r.alerts]) }}
            empty={data.top_risks.length === 0 ? 'No open High or Medium incident.' : undefined}
          >
            <div className="wide-labels">
            <HBars
              unit="alerts"
              rows={data.top_risks.map((r) => ({
                key: r.incident_id,
                label: <span className="mono">{labels.get(r.incident_id)}</span>,
                text: `${r.severity}: ${labels.get(r.incident_id) ?? r.incident_id}`,
                value: r.alerts,
                tone: sevTone(r.severity),
                sev: sevLevel(r.severity),
                detail: [`${r.incident_id}`, r.rule ? `why ${r.severity}: ${r.rule.rule} (rule ${r.rule.row})` : `severity ${r.severity}`, `first seen ${r.first_ts} (data date)`, `status ${r.status ?? 'open'}`],
                onActivate: session.role === 'executive' ? undefined : () => (window.location.hash = buildHash('/incidents', { id: r.incident_id })),
              }))}
            />
            </div>
            <p className="chart-note">In plain words: each bar is one open incident, named by its main host or source IP and when it started in the data; the bar length is how many alerts it groups. Hover a bar for the triage rule that made it severe.</p>
          </ChartFrame>
          <ChartFrame
            title="Review and approvals"
            question="Is the team keeping up?"
            table={{
              columns: ['measure', 'value'],
              rows: [
                ['incidents reviewed', ttr.reviewed],
                ['incidents not reviewed', ttr.unreviewed],
                ['median time to review', ttr.median_seconds === null ? 'n/a' : fmtDuration(ttr.median_seconds)],
                ['longest time to review', ttr.max_seconds === null ? 'n/a' : fmtDuration(ttr.max_seconds)],
                ['pending approvals', data.open_approvals.pending],
              ],
            }}
          >
            <HBars
              unit="incidents"
              rows={[
                { key: 'r', label: 'reviewed', text: 'Incidents reviewed (status changed at least once)', value: ttr.reviewed, tone: 'ref' },
                { key: 'u', label: 'not reviewed', text: 'Incidents never reviewed', value: ttr.unreviewed, tone: 'muted' },
              ]}
            />
            <p className="chart-note">
              In plain words: an incident counts as reviewed once an analyst changed its status; time to review runs from when triage created it. Median{' '}
              {ttr.median_seconds === null ? 'not available yet' : fmtDuration(ttr.median_seconds)}.
            </p>
          </ChartFrame>
        </div>

        <ChartFrame
          title="ATT&CK coverage"
          question="Which stages of an attack does the evidence show?"
          table={{ columns: ['tactic', 'alerts', 'techniques'], rows: data.coverage.map((c) => [c.name, c.alerts, c.techniques]) }}
        >
          <ChainStrip stages={data.coverage.map((c) => ({ ...c, techniques: [] }))} />
          <p className="chart-note">
            In plain words: {observed.length ? `alerts point to ${observed.map((c) => c.name).join(', ')}` : 'no alert is mapped to ATT&CK'}. A dashed cell means no mapped alert, not proof that
            nothing happened.
          </p>
        </ChartFrame>
        <p className="faint" style={{ fontSize: 'var(--fs-12)', display: 'flex', gap: 'var(--sp-4)', alignItems: 'center' }}>
          <Icon name="warning" />
          <span>Platform outputs on replayed demo data. No labels and no study results are shown here.</span>
        </p>
      </div>
    </div>
  );
}

/**
 * Incidents per first-seen day as small multiples: one row per severity with its own scale (the
 * row's maximum is printed), so a handful of High incidents is not flattened under hundreds of Low.
 */
function DayBars({ days }: { days: Array<{ day: string; High: number; Medium: number; Low: number }> }) {
  const [ref, size] = useElementSize<HTMLDivElement>();
  const tip = useTip();
  const width = Math.max(240, size.width);
  const L = 120;
  const ROW = 46;
  const B = 22;
  const H = SEVS.length * ROW + B;
  const band = bandScale(days.length, [L, width - 8], 0.3);
  return (
    <div ref={ref} className="chart-plot">
      <svg width={width} height={H} className="chart-svg" role="group" aria-label="Incidents per day, one row per severity">
        {SEVS.map((sev, r) => {
          const max = Math.max(0, ...days.map((d) => d[sev]));
          const top = niceMax(max, 2);
          const y0 = r * ROW + ROW - 6;
          const y = linearScale([0, top], [y0, r * ROW + 8]);
          return (
            <g key={sev}>
              <text x={0} y={r * ROW + 22} className="axis-text" style={{ fontWeight: 600, fill: `var(--sev-${sev.toLowerCase()})` }}>
                {sev}
              </text>
              <text x={0} y={r * ROW + 36} className="axis-text">
                {`scale 0 to ${compact(top)}`}
              </text>
              <line x1={L} x2={width - 8} y1={y0} y2={y0} stroke="var(--border-strong)" />
              {days.map((d, i) => {
                const v = d[sev];
                const lines = [`${d.day}: ${sev}`, `${fmtInt(v)} incidents`];
                return (
                  <g
                    key={d.day}
                    tabIndex={0}
                    aria-label={lines.join(', ')}
                    onPointerEnter={(e) => tip.show(e.currentTarget, lines)}
                    onPointerLeave={() => tip.hide()}
                    onFocus={(e) => tip.show(e.currentTarget, lines)}
                    onBlur={() => tip.hide()}
                  >
                    <rect x={band(i)} width={band.bandwidth} y={r * ROW + 6} height={ROW - 12} fill="transparent" />
                    {v > 0 && <rect x={band(i)} width={band.bandwidth} y={y(v)} height={Math.max(1, y0 - y(v))} fill={`var(--sev-${sev.toLowerCase()})`} />}
                    <text x={band(i) + band.bandwidth / 2} y={Math.min(y(v), y0) - 3} textAnchor="middle" className="axis-text">
                      {fmtInt(v)}
                    </text>
                  </g>
                );
              })}
            </g>
          );
        })}
        {days.map((d, i) => (
          <text key={d.day} x={band(i) + band.bandwidth / 2} y={H - 6} textAnchor="middle" className="axis-text">
            {d.day.slice(5)}
          </text>
        ))}
      </svg>
      <div className="axis-caption faint">first-seen day (UTC, month-day) · each row has its own scale; the count is printed on every bar</div>
    </div>
  );
}
