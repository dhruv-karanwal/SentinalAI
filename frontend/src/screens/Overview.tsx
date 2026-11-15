// Overview (DESIGN.md 5): "What needs attention right now?" Header, KPI row, one primary chart
// (alerts over time), the incidents to look at first as a list, and everything else in tabs. Every
// chart filters the alert table in the Alerts tab (the filter is kept in the URL, so a filtered view
// can be linked). All numbers come from GET /overview and GET /incidents (summaries).

import { useCallback, useMemo, useState } from 'react';

import { api, type AlertFilter, type IncidentSummaryRow, type Overview } from '../api.ts';
import { Term } from '../components/Term.tsx';
import { distinctLabels } from '../lib/explain.ts';
import { compareQueue } from '../lib/format.ts';
import { ChainStrip, HeatStrip } from '../charts/Attack.tsx';
import { HBars, StackedHBars } from '../charts/Bars.tsx';
import { ChartFrame, DETECTOR_ORDER, detectorTone, sevTone, type LegendItem } from '../charts/ChartFrame.tsx';
import { TimeBars } from '../charts/TimeBars.tsx';
import { AlertQueryTable, describeFilter } from '../components/AlertQueryTable.tsx';
import { Button, ErrorNotice, ErrorState, Kpi, Page, PageHeader, Section, SeverityCell, Tabs, Time, detectorName, type TabItem } from '../components/ui.tsx';
import { Icon } from '../icons.tsx';
import { buildHash, storageGet, storageSet, useLoad, useScreenContext, type RouteApi } from '../hooks.ts';
import { epochSeconds, fmtDuration, fmtInt, fmtStep } from '../lib/format.ts';
import { fmtPct, heatStep } from '../lib/scale.ts';

const SEVS = ['High', 'Medium', 'Low'] as const;
const STATUS_PATTERN: Record<string, 'solid' | 'hatch' | 'outline'> = { open: 'solid', investigating: 'hatch', contained: 'outline', closed: 'outline' };
const FILTER_KEYS: Array<keyof AlertFilter> = ['detector', 'level', 'rule_id', 'technique', 'host', 'ip', 'since', 'until'];

type DetailTab = 'attack' | 'entities' | 'detectors' | 'queue' | 'chain' | 'alerts';
const DETAIL_TABS: readonly TabItem<DetailTab>[] = [
  { id: 'attack', label: 'ATT&CK' },
  { id: 'entities', label: 'Hosts and IPs' },
  { id: 'detectors', label: 'Detectors' },
  { id: 'queue', label: 'Incident queue' },
  { id: 'chain', label: 'Attack chain' },
  { id: 'alerts', label: 'Alerts' },
];
/** the selected detail tab (replaces the wave G "More detail" flag, sentinel.overview.more) */
const TAB_KEY = 'sentinel.overview.tab';
const isTab = (v: string | null): v is DetailTab => DETAIL_TABS.some((t) => t.id === v);

export function sevLevel(sev: string | null | undefined): 0 | 1 | 2 | 3 {
  return sev === 'High' ? 3 : sev === 'Medium' ? 2 : sev === 'Low' ? 1 : 0;
}

/** Still skeleton in the shape of a dashboard page: KPI row, one chart, one list (shared with Executive and Study). */
export function DashSkeleton({ title, purpose, note }: { title: string; purpose: string; note?: string }) {
  return (
    <Page>
      <PageHeader title={title} purpose={purpose} actions={note ? <span className="page-meta">{note}</span> : undefined} />
      <div className="dash-skel" aria-busy="true" aria-label="Loading">
        <div className="skel-kpis">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="skel-block" />
          ))}
        </div>
        <div className="skel-block skel-chart" />
        <div className="skel-block skel-list" />
      </div>
    </Page>
  );
}

export function OverviewScreen({ scenario, route }: { scenario: string; route: RouteApi }) {
  const { data, error, loading, reload } = useLoad((signal) => api.overview(scenario, signal), [scenario]);
  const [log, setLog] = useState(() => storageGet('sentinel.overview.log') === '1');
  const filter = useMemo<AlertFilter>(() => Object.fromEntries(FILTER_KEYS.map((k) => [k, route.params[k] ?? null])), [route.params]);
  const active = FILTER_KEYS.some((k) => filter[k]);
  // the selected detail tab is remembered; a filter in the URL opens the Alerts tab
  const [tab, setTabState] = useState<DetailTab>(() => {
    if (active) return 'alerts';
    const v = storageGet(TAB_KEY);
    return isTab(v) ? v : 'attack';
  });
  const setTab = useCallback((t: DetailTab) => {
    setTabState(t);
    storageSet(TAB_KEY, t);
  }, []);
  const setFilter = useCallback(
    (patch: Partial<AlertFilter>) => {
      route.setParams(Object.fromEntries(Object.entries(patch).map(([k, v]) => [k, v ?? null])) as Record<string, string | null>);
      // the alert table lives in the Alerts tab: switch to it and bring it into view
      setTab('alerts');
      window.setTimeout(() => document.getElementById('ov-detail')?.scrollIntoView({ block: 'start', behavior: 'auto' }), 50);
    },
    [route, setTab],
  );
  const clear = () => route.setParams(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])));
  const incidents = useLoad((signal) => api.incidentSummaries(scenario, signal), [scenario]);
  useScreenContext(
    'overview',
    data
      ? `Data source ${scenario}: ${data.alerts} stored alerts. Open incidents by severity: High ${data.status.open_by_severity.High ?? 0}, Medium ${data.status.open_by_severity.Medium ?? 0}, Low ${data.status.open_by_severity.Low ?? 0}; ${data.status.incidents} incidents in total (triage gap 300 s). Pending approvals: ${data.status.pending_approvals}. Alerts by detector: ${data.detectors.map((d) => `${d.detector} ${d.alerts}`).join(', ')}. ATT&CK-mapped alerts: ${data.attack.mapped_alerts} of ${data.attack.alerts}. IOC matching: ${data.ioc_loaded ? 'loaded' : 'not measured (no indicator list loaded)'}. On screen: headline numbers, alerts over time by detector, incidents to look at first; in tabs: ATT&CK techniques by tactic, top hosts and source IPs, detector comparison, incident severity and status, attack chain, alert table.`
      : '',
  );

  if (error && !data) return <ErrorState what="the overview" error={error} onRetry={reload} />;
  if (!data) return <DashSkeleton title="Overview" purpose="What needs attention right now?" note="Building the per-scenario index (the first load after a restart takes a few seconds)." />;
  return (
    <Page className="draw-charts">
      <PageHeader
        title="Overview"
        purpose="What needs attention right now?"
        actions={
          <>
            <span className="page-meta num">
              {scenario} · {fmtInt(data.alerts)} stored alerts
              {data.timeseries.start && (
                <>
                  <br />
                  <Time ts={data.timeseries.start} /> to <Time ts={data.timeseries.end} kind="data" />
                </>
              )}
            </span>
            <Button icon="refresh" onClick={reload} disabled={loading}>
              Reload
            </Button>
          </>
        }
      />
      {error && <ErrorNotice what="the overview" error={error} onRetry={reload} />}
      <KpiRow data={data} />
      <VolumeChart data={data} log={log} setLog={(v) => (setLog(v), storageSet('sentinel.overview.log', v ? '1' : '0'))} filter={filter} setFilter={setFilter} />
      <LookFirst rows={incidents.data?.incidents ?? null} error={incidents.error} />
      <section className="sec" id="ov-detail" aria-label="Detail">
        <Tabs tabs={DETAIL_TABS.map((t) => (t.id === 'alerts' && active ? { ...t, count: 'filtered' } : t))} value={tab} onChange={setTab} label="Overview detail" idBase="ov" inset />
        <div className="tab-panel tab-enter" key={tab} role="tabpanel" id={`ov-panel-${tab}`} aria-labelledby={`ov-tab-${tab}`}>
          {tab === 'attack' && <AttackChart data={data} filter={filter} setFilter={setFilter} />}
          {tab === 'entities' && (
            <div className="grid-12">
              <div className="col-6">
                <EntityChart data={data} kind="host" scenario={scenario} />
              </div>
              <div className="col-6">
                <EntityChart data={data} kind="ip" scenario={scenario} />
              </div>
            </div>
          )}
          {tab === 'detectors' && <DetectorChart data={data} setFilter={setFilter} />}
          {tab === 'queue' && <QueueCharts data={data} />}
          {tab === 'chain' && <ChainChart data={data} />}
          {tab === 'alerts' && (
            <section id="ov-table" className="chart table-card" aria-labelledby="ov-table-t">
              <div className="table-card-head">
                <h3 id="ov-table-t">Alerts behind the charts</h3>
                <span className="muted">{describeFilter(filter)}</span>
                <span className="spacer" />
                {active && (
                  <Button icon="close" onClick={clear}>
                    Clear filter
                  </Button>
                )}
                <a className="btn" href={buildHash('/alerts', Object.fromEntries(FILTER_KEYS.map((k) => [k, filter[k] ?? null])))}>
                  Open in Alerts
                </a>
              </div>
              <div className="table-card-body">
                <AlertQueryTable scenario={scenario} filter={filter} label="Alerts filtered by the overview charts" onOpen={(a) => (window.location.hash = buildHash('/alerts', { id: a.alert_id }))} />
              </div>
            </section>
          )}
        </div>
      </section>
    </Page>
  );
}

/** The open incidents an analyst should open first (queue order), each named by host / IP and data time. */
function LookFirst({ rows, error }: { rows: IncidentSummaryRow[] | null; error: import('../api.ts').ApiError | null }) {
  const top = useMemo(() => (rows ?? []).filter((r) => (r.status ?? 'open') !== 'closed').map((r) => ({ ...r, status: r.status ?? 'open' })).sort(compareQueue).slice(0, 6), [rows]);
  const labels = useMemo(() => distinctLabels(top), [top]);
  return (
    <Section
      id="ov-first"
      title={<Term id="incident">Incidents to look at first</Term>}
      description="Open incidents in queue order: highest severity, then untouched, then most recent. Named by main host or source IP and data time (UTC)."
      actions={
        <a className="btn" href="#/incidents">
          Open the queue
        </a>
      }
    >
      <div className="card flush">
        {error && !rows ? (
          <p className="inc-empty">Incidents could not be loaded ({error.status || 'API unreachable'}).</p>
        ) : !rows ? (
          <div className="inc-empty" aria-busy="true" aria-label="Loading">
            <div className="skeleton-bar" style={{ width: '60%' }} />
          </div>
        ) : top.length === 0 ? (
          <p className="inc-empty">No open incident. Build incidents on the Incidents screen (triage).</p>
        ) : (
          <ul className="inc-list">
            {top.map((r, i) => (
              <li key={r.incident_id} className="row-enter" style={{ '--i': i } as React.CSSProperties}>
                <a className="inc-row" href={buildHash('/incidents', { id: r.incident_id })} title={`${r.incident_id}: ${labels.get(r.incident_id)}`}>
                  <SeverityCell value={r.severity} />
                  <span className="inc-name mono">{labels.get(r.incident_id)}</span>
                  <span className="inc-count num">{fmtInt(r.alerts)} alerts</span>
                  <span className="inc-meta">
                    {r.status}
                    {r.detail.severity_row ? ` · rule ${r.detail.severity_row}` : ''}
                  </span>
                  <span className="inc-chev" aria-hidden="true">
                    <Icon name="chevronRight" />
                  </span>
                </a>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Section>
  );
}

function KpiRow({ data }: { data: Overview }) {
  const s = data.status;
  const oldest = s.oldest_unreviewed_high;
  return (
    <div className="kpi-row" role="group" aria-label="Status">
      <Kpi
        label={
          <>
            Open <Term id="incident-severity">incidents by severity</Term>
          </>
        }
        value={
          <span className="kpi-sevs">
            {SEVS.map((sev) => (
              <a key={sev} href={buildHash('/incidents', { sev, status: 'open' })} title={`Open ${sev} incidents`}>
                <SeverityCell value={sev} />
                <span>{fmtInt(s.open_by_severity[sev] ?? 0)}</span>
              </a>
            ))}
          </span>
        }
        hint={
          <>
            {fmtInt(s.incidents)} in total, <Term id="triage-gap">gap</Term> 5 min
          </>
        }
      />
      <Kpi
        label={
          <>
            <Term id="alert">Alerts</Term> stored (replayed)
          </>
        }
        value={fmtInt(data.alerts)}
        hint={DETECTOR_ORDER.filter((d) => data.timeseries.series[d]).map((d) => `${detectorName(d)} ${fmtInt(data.timeseries.series[d]!.reduce((a, b) => a + b, 0))}`).join(' · ')}
      />
      {oldest ? (
        <Kpi
          label="Oldest High nobody has opened"
          value={fmtDuration(oldest.age_seconds)}
          href={buildHash('/incidents', { id: oldest.incident_id })}
          hint={
            <span className="mono" title={`${oldest.incident_id}: waiting since it was created (not the data date)`}>
              {oldest.incident_id} · {fmtInt(oldest.alerts)} alerts
            </span>
          }
        />
      ) : (
        <Kpi label="Oldest High nobody has opened" value="none" hint="No open High incident" />
      )}
      <Kpi
        label={
          <>
            Waiting for <Term id="four-eyes">approval</Term>
          </>
        }
        value={fmtInt(s.pending_approvals)}
        href="#/approvals"
        hint="A second person decides each one"
      />
    </div>
  );
}

function VolumeChart({ data, log, setLog, filter, setFilter }: { data: Overview; log: boolean; setLog: (v: boolean) => void; filter: AlertFilter; setFilter: (p: Partial<AlertFilter>) => void }) {
  const ts = data.timeseries;
  const start = ts.start ? epochSeconds(ts.start) : 0;
  const step = ts.bin_seconds ?? 1;
  const dets = DETECTOR_ORDER.filter((d) => ts.series[d]).concat(Object.keys(ts.series).filter((d) => !DETECTOR_ORDER.includes(d)));
  const legend: LegendItem[] = dets.map((d) => ({ key: d, label: detectorName(d), tone: detectorTone(d), value: fmtInt(ts.series[d]!.reduce((a, b) => a + b, 0)) }));
  const selection = useMemo<[number, number] | null>(() => {
    if (!filter.since || !filter.until || !ts.start) return null;
    const a = Math.round((epochSeconds(filter.since) - start) / step);
    const b = Math.round((epochSeconds(filter.until) - start) / step) - 1;
    return [a, Math.max(a, b)];
  }, [filter.since, filter.until, start, step, ts.start]);
  const markers = data.incident_starts.markers.map((m) => ({ t: epochSeconds(m.ts), severity: m.severity, label: m.incident_id }));
  const table = {
    columns: ['bin start (UTC)', 'total', ...dets.map(detectorName)],
    rows: Array.from({ length: ts.bins }, (_, i) => [new Date((start + i * step) * 1000).toISOString().replace('.000Z', 'Z'), dets.reduce((s, d) => s + (ts.series[d]![i] ?? 0), 0), ...dets.map((d) => ts.series[d]![i] ?? 0)]).filter((r) => Number(r[1]) > 0),
  };
  return (
    <ChartFrame
      id="ch-volume"
      title="Alerts over time, by detector"
      term="detector"
      question="Where did alert volume spike, and which detector raised it? Drag across the bars to filter the alerts."
      what="How many alerts arrived in each time slice of the recording, stacked by the tool that raised them. Triangles under the axis mark where High (filled) and Medium (outline) incidents start."
      why="Spikes are where the attack steps are likely to be; drag across bars (or use Shift and the arrow keys) to see those alerts in the Alerts tab."
      legend={[...legend, { key: 'h', label: 'High incident start', tone: 'high', mark: 'dot' }, { key: 'm', label: 'Medium incident start', tone: 'medium', mark: 'hollow' }]}
      table={table}
      empty={ts.total === 0 ? 'No stored alerts for this data source. Replay one with app.main platform-ingest.' : undefined}
      actions={
        <>
          <span className="segmented" role="group" aria-label="Count axis">
            <Button aria-pressed={!log} onClick={() => setLog(false)}>
              Linear
            </Button>
            <Button aria-pressed={log} onClick={() => setLog(true)}>
              Log
            </Button>
          </span>
          {selection && (
            <Button icon="close" onClick={() => setFilter({ since: null, until: null })}>
              Clear time
            </Button>
          )}
        </>
      }
      note={`Bins of ${fmtStep(step)}. ${data.incident_starts.low_not_marked ? `${fmtInt(data.incident_starts.low_not_marked)} Low incidents are not marked. ` : ''}${data.incident_starts.omitted ? `${fmtInt(data.incident_starts.omitted)} High/Medium markers omitted. ` : ''}Log scale draws log10(1 + count) so empty bins stay at zero.`}
    >
      <TimeBars
        series={ts.series}
        start={start}
        binSeconds={step}
        log={log}
        height={220}
        markers={markers}
        selection={selection}
        label="Alerts over time"
        onSelect={(b) => setFilter(b ? { since: new Date((start + b[0] * step) * 1000).toISOString(), until: new Date((start + (b[1] + 1) * step) * 1000).toISOString() } : { since: null, until: null })}
        onMarker={(m) => (window.location.hash = buildHash('/incidents', { id: m.label }))}
      />
    </ChartFrame>
  );
}

function QueueCharts({ data }: { data: Overview }) {
  const s = data.status;
  const statuses = ['open', 'investigating', 'contained', 'closed'];
  const segTone = (sev: string) => sevTone(sev);
  const rows = SEVS.map((sev) => ({
    key: sev,
    label: <SeverityCell value={sev} />,
    text: `${sev} incidents`,
    segments: statuses.map((st) => ({ key: st, label: st, value: s.by_severity_status[sev]?.[st] ?? 0, tone: segTone(sev), pattern: STATUS_PATTERN[st] })),
    onActivate: () => (window.location.hash = buildHash('/incidents', { sev })),
  }));
  return (
    <ChartFrame
      id="ch-queue"
      title="Incident severity and status"
      term="incident-severity"
      question="How much of the queue is High, and how much of it has nobody touched yet?"
      what="Incidents per severity, split by status: open (solid), investigating (hatched), contained or closed (outline); then how long they have waited."
      why="A large solid High bar means serious work nobody has started."
      legend={[
        { key: 'o', label: 'open (solid)', tone: 'muted', mark: 'bar' },
        { key: 'i', label: 'investigating (hatched)', tone: 'muted', mark: 'line', dash: '2 2' },
        { key: 'c', label: 'contained or closed (outline)', tone: 'muted', mark: 'hollow' },
      ]}
      table={{
        columns: ['severity', ...statuses, ...s.age_buckets.map((b) => `age ${b}`)],
        rows: SEVS.map((sev) => [sev, ...statuses.map((st) => s.by_severity_status[sev]?.[st] ?? 0), ...s.age_buckets.map((b) => s.age_in_queue[sev]?.[b] ?? 0)]),
      }}
      empty={s.incidents === 0 ? 'No incidents yet. Build them on the Incidents screen (triage, gap 300 s).' : undefined}
      note="Age in queue counts from the created date (when triage stored the incident), not the data date of its alerts (2022). Click a bar to open those incidents."
    >
      <StackedHBars rows={rows} unit="incidents" />
      <h4 className="chart-subtitle">Age in queue of incidents not closed (count per age band; stronger shade = more)</h4>
      <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th>Severity</th>
            {s.age_buckets.map((b) => (
              <th key={b} className="right">
                {b}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {SEVS.map((sev) => {
            const max = Math.max(1, ...SEVS.flatMap((x) => s.age_buckets.map((b) => s.age_in_queue[x]?.[b] ?? 0)));
            return (
              <tr key={sev}>
                <td>
                  <SeverityCell value={sev} />
                </td>
                {s.age_buckets.map((b) => {
                  const v = s.age_in_queue[sev]?.[b] ?? 0;
                  return (
                    <td key={b} className="heatcell" data-step={heatStep(v, max)}>
                      {fmtInt(v)}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
      </div>
    </ChartFrame>
  );
}

function DetectorChart({ data, setFilter }: { data: Overview; setFilter: (p: Partial<AlertFilter>) => void }) {
  const rows = data.detectors;
  const max = Math.max(1, ...rows.map((r) => r.alerts));
  return (
    <ChartFrame
      id="ch-detectors"
      title="Detector comparison"
      term="detector"
      question="Which detector's alerts carry context (ATT&CK mapping, indicator matches) and which mostly repeat another's?"
      what="For each tool: how many alerts, how many are linked to a known attack technique, how many match a known-bad indicator, and how many only copy another tool's alert."
      why="A detector whose alerts carry more context gives the investigator more to work with; that is the study's question."
      table={{
        columns: ['detector', 'alerts', 'mapped to ATT&CK', 'IOC match', 'duplicate of Suricata'],
        rows: rows.map((r) => [detectorName(r.detector), r.alerts, fmtPct(r.mapped_share), r.ioc_share === null ? 'no indicator list loaded' : fmtPct(r.ioc_share), fmtPct(r.duplicate_share)]),
      }}
      empty={rows.length === 0 ? 'No stored alerts.' : undefined}
      note={`Counts from the stores, no labels. ${data.ioc_loaded ? '' : 'No local indicator list is loaded (the OTX / MISP / VirusTotal feeds are disabled), so IOC match is not measured, not 0 %. '}Duplicates are Wazuh copies of Suricata fast.log lines, excluded from evaluation by default.`}
    >
      <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th>Detector</th>
            <th>Alerts</th>
            <th className="right">
              <Term id="attack-technique">Linked to a technique</Term>
            </th>
            <th className="right">
              <Term id="ioc">Known-bad match</Term>
            </th>
            <th className="right">
              <Term id="duplicate">Copies</Term>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.detector}>
              <td>
                <button type="button" className="linklike" onClick={() => setFilter({ detector: r.detector })} title={`Filter the alerts to ${detectorName(r.detector)}`}>
                  <span className="det" data-det={r.detector}>
                    {detectorName(r.detector)}
                  </span>
                </button>
              </td>
              <td>
                <span className="cellbar">
                  <span className="num">{fmtInt(r.alerts)}</span>
                  <span className="minibar" style={{ width: '100%' }} aria-hidden="true">
                    <span style={{ width: `${(r.alerts / max) * 100}%`, background: `var(--det-${DETECTOR_ORDER.includes(r.detector) ? r.detector : 'sigma'})` }} />
                  </span>
                </span>
              </td>
              <td className="right num" title={`${fmtInt(r.mapped)} of ${fmtInt(r.alerts)}`}>
                {fmtPct(r.mapped_share)}
              </td>
              <td className="right num" title={r.ioc === null ? 'no indicator list loaded' : `${fmtInt(r.ioc)} of ${fmtInt(r.alerts)}`}>
                {r.ioc_share === null ? <span className="faint">not measured</span> : fmtPct(r.ioc_share)}
              </td>
              <td className="right num" title={`${fmtInt(r.duplicates)} of ${fmtInt(r.alerts)}`}>
                {fmtPct(r.duplicate_share)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
    </ChartFrame>
  );
}

function AttackChart({ data, filter, setFilter }: { data: Overview; filter: AlertFilter; setFilter: (p: Partial<AlertFilter>) => void }) {
  const a = data.attack;
  return (
    <ChartFrame
      id="ch-attack"
      title="ATT&CK techniques by tactic"
      term="attack-tactic"
      question="Which tactics do the mapped alerts point to, and which technique carries the volume? Click a cell to filter the alerts."
      what="Columns are attacker goals (tactics); each cell is a technique with its alert count printed. A stronger shade means more alerts."
      why="It says what kind of attack the evidence suggests; click a cell to see those alerts."
      legend={[
        { key: 'h1', label: 'fewer alerts', tone: 'heat-1', mark: 'square' },
        { key: 'h4', label: 'more alerts (stronger shade; count printed in each cell)', tone: 'heat-4', mark: 'square' },
      ]}
      table={{
        columns: ['tactic', 'technique', 'name', 'alerts'],
        rows: a.tactics.flatMap((t) => (t.techniques.length ? t.techniques.map((c) => [t.name, c.technique_id, c.name ?? '', c.alerts]) : [[t.name, 'none', '', 0]])),
      }}
      empty={a.mapped_alerts === 0 ? 'No stored alert carries an ATT&CK mapping (Wazuh rule.mitre.id, Sigma tags or the documented rule table).' : undefined}
      actions={
        filter.technique ? (
          <Button icon="close" onClick={() => setFilter({ technique: null })}>
            Clear {filter.technique}
          </Button>
        ) : undefined
      }
      note={`${fmtInt(a.mapped_alerts)} of ${fmtInt(a.alerts)} alerts are mapped (${fmtPct(a.mapped_alerts / Math.max(1, a.alerts))}); deterministic mapping only, nothing guessed. A technique with several tactics is counted under each.${a.kb_loaded ? ` ATT&CK bundle v${a.kb_version ?? '?'}.` : ' No local ATT&CK bundle: tactics unknown.'}`}
    >
      <HeatStrip tactics={a.tactics} selected={filter.technique} onPick={(tid) => setFilter({ technique: filter.technique === tid ? null : tid })} />
    </ChartFrame>
  );
}

function EntityChart({ data, kind, scenario }: { data: Overview; kind: 'host' | 'ip'; scenario: string }) {
  const e = data.entities[kind];
  const rows = e.rows.map((r) => ({
    key: r.value,
    label: <span className="mono">{r.value}</span>,
    text: `${kind === 'host' ? 'Host' : 'Source IP'} ${r.value}`,
    value: r.alerts,
    tone: sevTone(r.severity),
    sev: sevLevel(r.severity),
    detail: [`highest incident severity: ${r.severity ?? 'in no incident'}`, `${fmtInt(r.incidents)} incidents`, ...Object.entries(r.by_detector).map(([d, v]) => `${detectorName(d)}: ${fmtInt(v)}`)],
    onActivate: () => (window.location.hash = buildHash('/entity', { kind, value: r.value })),
  }));
  return (
    <ChartFrame
      id={`ch-ent-${kind}`}
      title={kind === 'host' ? 'Top hosts' : 'Top source IPs'}
      term="entity"
      question={kind === 'host' ? 'Which hosts raise the most alerts, and how severe are the incidents they are in?' : 'Which source addresses appear most, and in how severe incidents?'}
      what={kind === 'host' ? 'The machines with the most alerts; the bar colour and glyph give the worst incident each one is in.' : 'The addresses traffic came from most often; colour and glyph give the worst incident each one is in.'}
      why={kind === 'host' ? 'A host in a High incident is the first place to look.' : 'One source IP behind many alerts usually means one attacker.'}
      legend={[...SEVS.map((s): LegendItem => ({ key: s, label: `highest incident: ${s}`, tone: sevTone(s) })), { key: 'n', label: 'in no incident', tone: 'muted' }]}
      table={{ columns: [kind, 'alerts', 'highest incident severity', 'incidents'], rows: e.rows.map((r) => [r.value, r.alerts, r.severity ?? 'none', r.incidents]) }}
      empty={rows.length === 0 ? (kind === 'ip' ? 'No alert carries a source IP (only Wazuh data.srcip and Suricata src_ip are read).' : 'No alert carries a host IP.') : undefined}
      note={`Top ${rows.length} of ${fmtInt(e.distinct)} ${kind === 'host' ? 'hosts' : 'source IPs'} in ${scenario}. Click a bar to open the entity.`}
    >
      <HBars rows={rows} unit="alerts" />
    </ChartFrame>
  );
}

function ChainChart({ data }: { data: Overview }) {
  const [incident, setIncident] = useState<string>('');
  const loaded = useLoad((signal) => (incident ? api.analysis(incident, signal) : Promise.resolve(null)), [incident]);
  const stages = incident && loaded.data ? loaded.data.kill_chain : data.kill_chain;
  const options = data.incident_starts.markers;
  const observed = stages.filter((s) => s.alerts > 0).length;
  return (
    <ChartFrame
      id="ch-chain"
      title="Attack chain"
      term="kill-chain"
      question="Which kill-chain stages are observed, and where are the gaps?"
      what="The attacker goals in their usual order, with the number of linked alerts under each; choose one incident to see only its chain."
      why="Gaps are stages with no linked alert. A gap means no evidence, not that nothing happened."
      table={{ columns: ['stage', 'tactic', 'alerts', 'techniques'], rows: stages.map((s, i) => [i + 1, s.name, s.alerts, s.techniques.map((t) => t.technique_id).join(' ') || 'gap']) }}
      actions={
        <>
          <label htmlFor="chain-inc" className="label">
            Show
          </label>
          <select id="chain-inc" className="select mono" value={incident} onChange={(e) => setIncident(e.target.value)}>
            <option value="">whole data source</option>
            {options.map((m) => (
              <option key={m.incident_id} value={m.incident_id}>
                {m.severity} {m.incident_id}
              </option>
            ))}
          </select>
        </>
      }
      note={`${observed} of ${stages.length} tactics observed${loaded.error ? ` (incident could not be loaded: ${loaded.error.status})` : ''}. Stages come from the deterministic ATT&CK mapping; an empty cell is a gap: no mapped alert, which does not mean nothing happened.`}
    >
      <ChainStrip stages={stages} />
    </ChartFrame>
  );
}
