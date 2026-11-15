// Incidents: the queue on the left (highest severity, open, most recent first), the selected
// incident on the right: header, time strip, then alerts with their evidence, investigate (agents + copilot), response.

import { useEffect, useMemo, useRef, useState } from 'react';

import { api, ApiError, can, type Approval, type Incident, type IncidentAnalysis, type Recommendation, type Report, type TimelineEntry } from '../api.ts';
import { Lanes } from '../charts/Attack.tsx';
import { ChartFrame } from '../charts/ChartFrame.tsx';
import { EntityGraph, type GraphNode } from '../charts/EntityGraph.tsx';
import { DataTable, type Column } from '../components/DataTable.tsx';
import { EvidencePane } from '../components/EvidencePane.tsx';
import { AskForm, Finding, type AskStore } from '../components/Findings.tsx';
import { InvestigationPanel } from '../components/Investigation.tsx';
import { SplitPane } from '../components/SplitPane.tsx';
import { TimeStrip, type TimeRange } from '../components/TimeStrip.tsx';
import {
  Button,
  DefGrid,
  describeError,
  DetectorTag,
  Dialog,
  EmptyState,
  ErrorNotice,
  ErrorState,
  Id,
  PageHeader,
  SeverityCell,
  SkeletonLines,
  StatusTag,
  Tabs,
  Time,
  type TabItem,
} from '../components/ui.tsx';
import { Term } from '../components/Term.tsx';
import { useApp, useLoad, useScreenContext, type Route } from '../hooks.ts';
import { incidentLabel, mainFromNodes, whatHappened } from '../lib/explain.ts';
import { Icon } from '../icons.tsx';
import { compareQueue, epochSeconds, fmtDuration, fmtInt, parseEntity } from '../lib/format.ts';
import { fitColumns, useNarrow } from '../components/narrow.ts';

const STATUSES = ['open', 'investigating', 'contained', 'closed'];
const SEVERITIES = ['High', 'Medium', 'Low'];

interface Props {
  route: Route & { setParams: (patch: Record<string, string | null>, replace?: boolean) => void };
  askStore: AskStore;
  searchRef: React.RefObject<HTMLInputElement | null>;
}

const duration = (i: Incident) => epochSeconds(i.last_ts) - epochSeconds(i.first_ts);
const entityText = (i: Incident) => (i.detail.entities ?? []).map((e) => parseEntity(e).value).join(' ');

export function IncidentsScreen({ route, askStore, searchRef }: Props) {
  const { scenario, session } = useApp();
  const { data, error, loading, reload } = useLoad((signal) => api.incidents(scenario, signal), [scenario]);
  const [sev, setSev] = useState<string>(route.params.sev ?? 'all');
  const [status, setStatus] = useState<string>(route.params.status ?? 'all');
  const [q, setQ] = useState('');
  const [statusOverride, setStatusOverride] = useState<Record<string, string>>({});
  const [building, setBuilding] = useState(false);
  const { toast } = useApp();

  const all = useMemo(() => {
    const list = (data?.incidents ?? []).map((i) => (statusOverride[i.incident_id] ? { ...i, status: statusOverride[i.incident_id]! } : i));
    return list.sort(compareQueue);
  }, [data, statusOverride]);

  const counts = useMemo(() => {
    const c: Record<string, number> = { High: 0, Medium: 0, Low: 0 };
    for (const i of all) c[i.severity] = (c[i.severity] ?? 0) + 1;
    return c;
  }, [all]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return all.filter(
      (i) =>
        (sev === 'all' || i.severity === sev) &&
        (status === 'all' || i.status === status) &&
        (needle === '' || i.incident_id.toLowerCase().includes(needle) || entityText(i).toLowerCase().includes(needle)),
    );
  }, [all, sev, status, q]);

  const selectedId = route.params.id ?? null;
  const selected = useMemo(() => all.find((i) => i.incident_id === selectedId) ?? null, [all, selectedId]);

  // first load: select the top of the queue, i.e. the highest-severity open incident
  useEffect(() => {
    if (!selectedId && rows.length > 0) route.setParams({ id: rows[0]!.incident_id, ev: null });
  }, [selectedId, rows, route]);

  const columns = useMemo<Column<Incident>[]>(
    () => [
      { id: 'severity', header: 'Severity', width: '76px', render: (i) => <SeverityCell value={i.severity} /> },
      { id: 'status', header: 'Status', width: '58px', sortKey: (i) => STATUSES.indexOf(i.status), render: (i) => <StatusTag value={i.status} /> },
      { id: 'last', header: 'Last seen (UTC)', width: '146px', sortKey: (i) => i.last_ts, render: (i) => <Time ts={i.last_ts} /> },
      { id: 'alerts', header: 'Alerts', width: '46px', align: 'right', sortKey: (i) => i.alert_ids.length, render: (i) => fmtInt(i.alert_ids.length) },
      { id: 'duration', header: 'Duration', width: '76px', align: 'right', sortKey: duration, render: (i) => fmtDuration(duration(i)) },
      {
        id: 'entities',
        header: 'Entities',
        width: 'minmax(0, 1fr)',
        title: entityText,
        render: (i) => {
          const e = i.detail.entities ?? [];
          if (e.length === 0) return <span className="faint">-</span>;
          return (
            <span className="mono">
              {parseEntity(e[0]!).value}
              {e.length > 1 && <span className="faint"> +{e.length - 1}</span>}
            </span>
          );
        },
      },
    ],
    [],
  );

  const narrow = useNarrow();
  const listColumns = useMemo(() => fitColumns(columns, narrow, ['status', 'duration']), [columns, narrow]);

  const build = async () => {
    if (!scenario) return;
    setBuilding(true);
    try {
      await api.buildIncidents(scenario, 300);
      toast(`Triage rebuilt incidents for ${scenario} (gap 300 s).`);
      reload();
    } catch (err) {
      toast(err instanceof ApiError ? describeError(err) : String(err), 'error');
    } finally {
      setBuilding(false);
    }
  };

  const filtered = sev !== 'all' || status !== 'all' || q.trim() !== '';
  const gap = all[0]?.detail.gap_seconds;

  const list = (
    <>
      <div className="toolbar" role="search" aria-label="Filter incidents">
        <div className="segmented" role="group" aria-label="Severity filter">
          <Button aria-pressed={sev === 'all'} onClick={() => setSev('all')}>
            All <span className="seg-count num">{fmtInt(all.length)}</span>
          </Button>
          {SEVERITIES.map((s) => (
            <Button key={s} aria-pressed={sev === s} onClick={() => setSev(sev === s ? 'all' : s)}>
              {s} <span className="seg-count num">{fmtInt(counts[s] ?? 0)}</span>
            </Button>
          ))}
        </div>
        <label className="visually-hidden" htmlFor="inc-status">
          Status filter
        </label>
        <select id="inc-status" className="select" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="all">Any status</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <div className="searchbox">
          <Icon name="search" />
          <label className="visually-hidden" htmlFor="inc-q">
            Filter by incident id, host or IP
          </label>
          <input
            id="inc-q"
            ref={searchRef}
            className="input"
            placeholder="Filter by id, host or IP ( / )"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                setQ('');
                e.currentTarget.blur();
              }
            }}
          />
        </div>
      </div>
      {error && data && <ErrorNotice what="incidents" error={error} onRetry={reload} />}
      {error && !data ? (
        <ErrorState what="incidents" error={error} onRetry={reload} />
      ) : (
        <DataTable
          label="Incidents, highest severity first"
          unit="incidents"
          primary
          rows={rows}
          columns={listColumns}
          rowKey={(i) => i.incident_id}
          selectedKey={selectedId}
          onSelect={(i) => route.setParams({ id: i.incident_id, ev: null })}
          onOpen={() => document.getElementById('incident-detail-title')?.focus()}
          copyText={(i) => i.incident_id}
          loading={loading}
          footer={
            <>
              <span>Order: severity, status, last seen{gap ? ` · triage gap ${gap} s` : ''}</span>
            </>
          }
          empty={
            filtered ? (
              <EmptyState title="No incidents match the filters.">
                <button type="button" className="linklike" onClick={() => (setSev('all'), setStatus('all'), setQ(''))}>
                  Clear filters
                </button>
              </EmptyState>
            ) : (
              <EmptyState title={`No incidents for ${scenario ?? 'this data source'}.`}>
                Incidents are built by triage from the stored alerts.{' '}
                {scenario && can(session.role, 'incident.build') ? (
                  <button type="button" className="linklike" onClick={() => void build()} disabled={building}>
                    {building ? 'Building...' : 'Run triage now (gap 300 s)'}
                  </button>
                ) : (
                  <span className="mono">app.main triage --scenario {scenario ?? '<name>'}</span>
                )}
              </EmptyState>
            )
          }
        />
      )}
    </>
  );

  const detail = selected ? (
    <IncidentDetail
      key={selected.incident_id}
      incident={selected}
      route={route}
      askStore={askStore}
      onStatus={(s) => setStatusOverride((m) => ({ ...m, [selected.incident_id]: s }))}
    />
  ) : loading ? (
    <SkeletonLines lines={5} />
  ) : selectedId && !error ? (
    <EmptyState title="Incident not found in this data source.">
      <span className="mono">{selectedId}</span> is not in {scenario ?? 'the loaded list'}. It may have been replaced by a triage rebuild.
    </EmptyState>
  ) : (
    <EmptyState title="No incident selected.">Select a row to see its timeline, alerts and evidence.</EmptyState>
  );

  return (
    <div className="work">
      <PageHeader
        bar
        title="Incidents"
        purpose="Which incident do I open, and what happened in it?"
        actions={
          <>
            {scenario && can(session.role, 'incident.build') && (
              <Button onClick={() => void build()} disabled={building} title="Run triage again over the stored alerts (gap 300 s)">
                {building ? 'Building...' : 'Build incidents'}
              </Button>
            )}
            <Button icon="refresh" onClick={reload} disabled={loading}>
              Reload
            </Button>
          </>
        }
      />
      <SplitPane id="incidents" left={list} right={detail} initial={50} />
    </div>
  );
}

// ---- detail ----------------------------------------------------------------------------------

type AlertRowT = TimelineEntry & { t: number };
type Tab = 'alerts' | 'attack' | 'graph' | 'investigation' | 'response';

interface RuleGroup {
  key: string;
  rule_id: string | null;
  rule_name: string | null;
  detector: string;
  count: number;
  first: string;
  last: string;
}

function IncidentDetail({
  incident,
  route,
  askStore,
  onStatus,
}: {
  incident: Incident;
  route: Props['route'];
  askStore: AskStore;
  onStatus: (status: string) => void;
}) {
  const { session, toast } = useApp();
  const [tab, setTab] = useState<Tab>('alerts');
  const [range, setRange] = useState<TimeRange | null>(null);
  const [grouped, setGrouped] = useState(false);
  const [rule, setRule] = useState<string | null>(null);
  const [needles, setNeedles] = useState<string[]>([]);
  const [focusEvidence, setFocusEvidence] = useState<number | null>(null);
  const [allEntities, setAllEntities] = useState(false);
  const [node, setNode] = useState<{ id: string; label: string; ids: Set<string> } | null>(null);
  const analysis = useLoad((signal) => api.analysis(incident.incident_id, signal), [incident.incident_id]);
  const d = incident.detail;
  const ev = route.params.ev ?? null;

  const timeline = useMemo<AlertRowT[]>(() => (d.timeline ?? []).map((e) => ({ ...e, t: epochSeconds(e.ts) })), [d.timeline]);
  const t0 = epochSeconds(incident.first_ts);
  const t1 = epochSeconds(incident.last_ts);

  const ruleKey = (e: { detector: string; rule_id: string | null }) => `${e.detector}|${e.rule_id ?? ''}`;
  const visible = useMemo(
    () => timeline.filter((e) => (!range || (e.t >= range.from && e.t < range.to)) && (!rule || ruleKey(e) === rule) && (!node || node.ids.has(e.alert_id))),
    [timeline, range, rule, node],
  );
  const groups = useMemo<RuleGroup[]>(() => {
    const m = new Map<string, RuleGroup>();
    for (const e of timeline) {
      if (range && !(e.t >= range.from && e.t < range.to)) continue;
      const key = ruleKey(e);
      const g = m.get(key);
      if (!g) m.set(key, { key, rule_id: e.rule_id, rule_name: e.rule_name, detector: e.detector, count: 1, first: e.ts, last: e.ts });
      else {
        g.count += 1;
        if (e.ts < g.first) g.first = e.ts;
        if (e.ts > g.last) g.last = e.ts;
      }
    }
    return [...m.values()].sort((a, b) => b.count - a.count);
  }, [timeline, range]);

  const alertColumns = useMemo<Column<AlertRowT>[]>(
    () => [
      { id: 'ts', header: 'Time (UTC, data)', width: '146px', sortKey: (e) => e.t, render: (e) => <Time ts={e.ts} /> },
      { id: 'det', header: 'Detector', width: '74px', sortKey: (e) => e.detector, render: (e) => <DetectorTag value={e.detector} /> },
      { id: 'level', header: 'Level class', width: '74px', sortKey: (e) => ['high', 'medium', 'low', 'none'].indexOf(e.level), render: (e) => <SeverityCell value={e.level} /> },
      { id: 'rule', header: 'Rule id', width: '88px', sortKey: (e) => e.rule_id, render: (e) => <span className="mono">{e.rule_id ?? '-'}</span> },
      { id: 'name', header: 'Rule name', width: 'minmax(0, 1fr)', sortKey: (e) => e.rule_name, title: (e) => e.rule_name ?? '', render: (e) => e.rule_name ?? <span className="faint">-</span> },
    ],
    [],
  );
  const groupColumns = useMemo<Column<RuleGroup>[]>(
    () => [
      { id: 'count', header: 'Alerts', width: '60px', align: 'right', sortKey: (g) => g.count, render: (g) => fmtInt(g.count) },
      { id: 'det', header: 'Detector', width: '80px', sortKey: (g) => g.detector, render: (g) => <DetectorTag value={g.detector} /> },
      { id: 'rule', header: 'Rule id', width: '88px', sortKey: (g) => g.rule_id, render: (g) => <span className="mono">{g.rule_id ?? '-'}</span> },
      { id: 'name', header: 'Rule name', width: 'minmax(0, 1fr)', sortKey: (g) => g.rule_name, title: (g) => g.rule_name ?? '', render: (g) => g.rule_name ?? <span className="faint">-</span> },
      { id: 'first', header: 'First (UTC)', width: '152px', sortKey: (g) => g.first, render: (g) => <Time ts={g.first} /> },
    ],
    [],
  );

  const narrow = useNarrow();
  const alertCols = useMemo(() => fitColumns(alertColumns, narrow, ['level', 'rule']), [alertColumns, narrow]);
  const groupCols = useMemo(() => fitColumns(groupColumns, narrow, ['rule', 'first']), [groupColumns, narrow]);

  const pickNode = async (n: GraphNode | null) => {
    if (!n) return setNode(null);
    try {
      const r = await api.nodeAlerts(incident.incident_id, n.id);
      setNode({ id: n.id, label: `${n.kind === 'host' ? 'host' : 'IP'} ${n.value}`, ids: new Set(r.alert_ids) });
      setTab('alerts');
      setGrouped(false);
    } catch (err) {
      toast(err instanceof ApiError ? describeError(err) : String(err), 'error');
    }
  };

  const openEvidence = (alertId: string, hl: string[] = []) => {
    setNeedles(hl);
    setTab('alerts');
    setGrouped(false);
    if (!visible.some((e) => e.alert_id === alertId)) {
      setRange(null);
      setRule(null);
      setNode(null);
    }
    route.setParams({ ev: alertId });
    setFocusEvidence(Date.now());
  };

  const setStatus = async (status: string) => {
    try {
      await api.setIncidentStatus(incident.incident_id, status);
      onStatus(status);
      toast(`Incident status set to ${status}.`);
    } catch (err) {
      toast(err instanceof ApiError ? describeError(err) : String(err), 'error');
    }
  };

  const entities = d.entities ?? [];
  const shownEntities = allEntities ? entities : entities.slice(0, 3);
  const findings = askStore.entries.filter((e) => e.incidentId === incident.incident_id);
  const activeRule = rule ? groups.find((g) => g.key === rule) ?? null : null;

  const tabs: TabItem<Tab>[] = [
    { id: 'alerts', label: 'Alerts and evidence', count: fmtInt(timeline.length) },
    { id: 'attack', label: 'ATT&CK lanes', count: analysis.data ? analysis.data.lanes.lanes.length : '...' },
    { id: 'graph', label: 'Entity graph', count: analysis.data ? fmtInt(analysis.data.graph.nodes_total) : '...' },
    { id: 'investigation', label: 'Investigate', count: findings.length || undefined },
    { id: 'response', label: 'Response' },
  ];
  const panel = (id: Tab) => ({ role: 'tabpanel', id: `inc-panel-${id}`, 'aria-labelledby': `inc-tab-${id}` }) as const;

  return (
    <div className="inc-detail">
      <IncidentHeader
        incident={incident}
        analysis={analysis.data}
        canUpdate={can(session.role, 'incident.update')}
        onStatus={(s) => void setStatus(s)}
        entities={shownEntities}
        entitiesTotal={entities.length}
        allEntities={allEntities}
        onToggleEntities={() => setAllEntities(!allEntities)}
      />

      {timeline.length > 0 ? (
        <TimeStrip ticks={timeline} t0={t0} t1={t1} selection={range} onSelect={setRange} />
      ) : (
        <div className="notice">This incident was stored without a timeline; the alert list below is not available.</div>
      )}

      <Tabs tabs={tabs} value={tab} onChange={setTab} label="Incident sections" idBase="inc" />

      {tab === 'alerts' && (
        <div className="tabpanel tab-enter inc-alerts" {...panel('alerts')}>
          <div className="toolbar">
            <Button aria-pressed={grouped} onClick={() => setGrouped(!grouped)} title="One row per detector and rule, with counts">
              Group by rule
            </Button>
            {activeRule && (
              <button type="button" className="filter-tag" onClick={() => setRule(null)} title="Remove the rule filter" aria-label={`Remove the rule filter ${activeRule.rule_id ?? ""}`}>
                <span className="k">rule</span> <span className="mono">{activeRule.rule_id ?? '-'}</span>
                <Icon name="close" />
              </button>
            )}
            {range && (
              <button type="button" className="filter-tag" onClick={() => setRange(null)} title="Remove the time range filter" aria-label="Remove the time range filter">
                <span className="k">time range</span>
                <Icon name="close" />
              </button>
            )}
            {node && (
              <button type="button" className="filter-tag" onClick={() => setNode(null)} title="Remove the entity filter" aria-label={`Remove the entity filter ${node.label}`}>
                <span className="mono">{node.label}</span>
                <Icon name="close" />
              </button>
            )}
            <span className="tb-meta num">
              {range || rule || node ? `${fmtInt(visible.length)} of ${fmtInt(timeline.length)} alerts` : `${fmtInt(timeline.length)} alerts`}
              {grouped ? ` in ${fmtInt(groups.length)} rules` : ''}
            </span>
          </div>
          <div className="inc-list-split">
            {grouped ? (
              <DataTable
                label="Alerts grouped by rule"
                unit="rules"
                rows={groups}
                columns={groupCols}
                rowKey={(g) => g.key}
                selectedKey={rule}
                onSelect={(g) => setRule(g.key)}
                onOpen={(g) => (setRule(g.key), setGrouped(false))}
                footer={<span>Enter or double click shows the alerts of a rule</span>}
                empty={<EmptyState title="No alerts in the selected time range." />}
              />
            ) : (
              <DataTable
                label="Alerts of this incident"
                unit="alerts"
                rows={visible}
                columns={alertCols}
                rowKey={(e) => e.alert_id}
                selectedKey={ev}
                onSelect={(e) => (setNeedles([]), route.setParams({ ev: e.alert_id }))}
                onOpen={() => setFocusEvidence(Date.now())}
                copyText={(e) => e.alert_id}
                empty={
                  <EmptyState title="No alerts match the time range, rule or entity filter.">
                    <button type="button" className="linklike" onClick={() => (setRange(null), setRule(null), setNode(null))}>
                      Clear filters
                    </button>
                  </EmptyState>
                }
              />
            )}
          </div>
          {ev && !grouped && (
            <div className="inc-ev-split">
              <EvidencePane alertId={ev} needles={needles} focusKey={focusEvidence} onClose={() => route.setParams({ ev: null })} />
            </div>
          )}
        </div>
      )}

      {tab === 'attack' && (
        <div className="tabpanel tab-enter" {...panel('attack')}>
          <div className="block">
            {analysis.error && !analysis.data && <ErrorState what="the ATT&CK lanes" error={analysis.error} onRetry={analysis.reload} />}
            {!analysis.data && !analysis.error && <SkeletonLines />}
            {analysis.data && analysis.data.lanes.lanes.length === 0 && (
              <EmptyState title="No alert of this incident carries an ATT&CK mapping.">Only Wazuh rule.mitre.id, Sigma tags and the documented rule table are used; nothing is guessed.</EmptyState>
            )}
            {analysis.data && analysis.data.lanes.lanes.length > 0 && (
              <ChartFrame
                className="flat-chart"
                title="ATT&CK tactic lanes"
                question="Which tactics do the mapped alerts point to, and when? Click a tick (or Enter) to see those alerts."
                table={{
                  columns: ['tactic', 'bin start (UTC)', 'alerts'],
                  rows: analysis.data.lanes.lanes.flatMap((l) => l.bins.map(([b, c]) => [l.name, new Date((epochSeconds(analysis.data!.lanes.start) + b * analysis.data!.lanes.bin_seconds) * 1000).toISOString(), c])),
                }}
                note={`${fmtInt(analysis.data.lanes.unmapped_alerts)} of ${fmtInt(analysis.data.summary.alerts_found)} alerts carry no ATT&CK mapping and are not drawn. Same time axis as the detector strip above.`}
              >
                <Lanes
                  lanes={analysis.data.lanes.lanes}
                  bins={analysis.data.lanes.bins}
                  start={epochSeconds(analysis.data.lanes.start)}
                  binSeconds={analysis.data.lanes.bin_seconds}
                  onPick={(from, to) => (setRange({ from, to }), setTab('alerts'))}
                />
              </ChartFrame>
            )}
          </div>
        </div>
      )}

      {tab === 'graph' && (
        <div className="tabpanel tab-enter" {...panel('graph')}>
          <div className="block">
            {analysis.error && !analysis.data && <ErrorState what="the entity graph" error={analysis.error} onRetry={analysis.reload} />}
            {!analysis.data && !analysis.error && <SkeletonLines />}
            {analysis.data && (
              <EntityGraph
                graph={analysis.data.graph}
                title="Hosts and source IPs"
                question="Which addresses talk to which hosts in this incident, and through which detector?"
                selected={node?.id ?? null}
                onPick={(n) => void pickNode(n)}
              />
            )}
          </div>
        </div>
      )}

      {tab === 'investigation' && (
        <div className="tabpanel tab-enter" {...panel('investigation')}>
          <InvestigationPanel incidentId={incident.incident_id} onOpenEvidence={openEvidence} />
          <div className="block">
            <div className="block-title">
              Ask one question <span className="meta">copilot: the single agent answers one question; answers are kept for this session only</span>
            </div>
            <AskForm incidentId={incident.incident_id} store={askStore} />
          </div>
          {findings.length === 0 && !askStore.modelOffline && (
            <EmptyState title="No findings for this incident in this session.">
              The copilot answers one question with the single agent. For a full investigation with every agent step stored, use the Investigation tab. Each cited alert is checked by the verifier; anything it drops is listed with the reason.
            </EmptyState>
          )}
          {findings.map((f) => (
            <div className="block" key={f.id}>
              <Finding entry={f} onOpenEvidence={openEvidence} />
            </div>
          ))}
        </div>
      )}

      {tab === 'response' && (
        <div className="tabpanel tab-enter" {...panel('response')}>
          <ResponsePanel incident={incident} />
        </div>
      )}
    </div>
  );
}

// ---- response: report, techniques, recommendations, approvals -----------------------------------

function ResponsePanel({ incident }: { incident: Incident }) {
  const { session, toast } = useApp();
  const reports = useLoad((signal) => api.reports(incident.incident_id, signal), [incident.incident_id]);
  const approvals = useLoad((signal) => api.approvals(signal), [incident.incident_id]);
  const [creating, setCreating] = useState(false);
  const [requesting, setRequesting] = useState<Recommendation | null>(null);

  const report: Report | null = reports.data?.reports[0] ?? null;
  const mine: Approval[] = (approvals.data?.approvals ?? []).filter((a) => a.incident_id === incident.incident_id);

  const create = async () => {
    setCreating(true);
    try {
      await api.createReport(incident.incident_id);
      toast('Report created.');
      reports.reload();
    } catch (err) {
      toast(err instanceof ApiError ? describeError(err) : String(err), 'error');
    } finally {
      setCreating(false);
    }
  };

  if (reports.error && !reports.data) return <ErrorState what="reports" error={reports.error} onRetry={reports.reload} />;
  if (reports.loading && !reports.data) return <SkeletonLines lines={5} />;

  return (
    <>
      <section className="block" aria-label="Report">
        <h3 className="block-title">Report</h3>
        {report ? (
          <div className="btn-row">
            <Id value={report.report_id} label="Copy report id" />
            <span className="muted">
              created <Time ts={report.created_utc} kind="created" />
            </span>
            <a href={`#/reports?id=${encodeURIComponent(report.report_id)}`}>Open in Reports</a>
            {can(session.role, 'report.create') && (
              <Button onClick={() => void create()} disabled={creating}>
                {creating ? 'Creating...' : 'Create a new report'}
              </Button>
            )}
          </div>
        ) : (
          <div className="btn-row">
            <span className="muted">
              No report for this incident. ATT&amp;CK techniques and playbook recommendations are computed when a report is created.
            </span>
            {can(session.role, 'report.create') && (
              <Button kind="primary" onClick={() => void create()} disabled={creating}>
                {creating ? 'Creating...' : 'Create report'}
              </Button>
            )}
          </div>
        )}
      </section>

      {report && (
        <>
          <section className="block" aria-label="ATT&CK techniques">
            <h3 className="block-title">
              ATT&amp;CK techniques <span className="meta">detector-native ids and the fixed rule table only</span>
            </h3>
            {report.body.techniques.length === 0 ? (
              <p className="muted">No alert of this incident maps to a technique.</p>
            ) : (
              <table className="plain-table">
                <thead>
                  <tr>
                    <th>Technique</th>
                    <th className="right">Alerts</th>
                  </tr>
                </thead>
                <tbody>
                  {report.body.techniques.map((t) => (
                    <tr key={t.technique_id}>
                      <td className="mono">{t.technique_id}</td>
                      <td className="right num">{fmtInt(t.alerts)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
          <section className="block" aria-label="Recommended actions">
            <h3 className="block-title">
              Recommended actions <span className="meta">suggestions; nothing runs without an approved request</span>
            </h3>
            <div className="table-scroll">
            <table className="plain-table">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Type</th>
                  <th>Techniques</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {report.body.recommendations.map((r) => (
                  <tr key={`${r.action_type}|${r.title}`}>
                    <td>{r.title}</td>
                    <td className="mono nowrap">{r.action_type}</td>
                    <td className="mono">{r.techniques.join(', ') || '-'}</td>
                    <td className="right">
                      {!r.requires_approval ? (
                        <span className="faint">no approval needed</span>
                      ) : can(session.role, 'approval.request') ? (
                        <Button onClick={() => setRequesting(r)}>Request approval</Button>
                      ) : (
                        <span className="faint">approval required</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          </section>
        </>
      )}

      <section className="block" aria-label="Approval requests">
        <h3 className="block-title">Approval requests for this incident</h3>
        {approvals.error ? (
          <p className="field-error" role="alert">
            {describeError(approvals.error)}
          </p>
        ) : mine.length === 0 ? (
          <p className="muted">None.</p>
        ) : (
          <div className="table-scroll">
          <table className="plain-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Action</th>
                <th>Target</th>
                <th>Requested by</th>
                <th>Requested (UTC)</th>
              </tr>
            </thead>
            <tbody>
              {mine.map((a) => (
                <tr key={a.id}>
                  <td>
                    <StatusTag value={a.executed_utc ? 'executed' : a.status} />
                  </td>
                  <td className="mono">
                    <a href={`#/approvals?id=${a.id}`}>{a.action.action_type}</a>
                  </td>
                  <td className="mono">{a.action.target ?? '-'}</td>
                  <td>{a.requested_by}</td>
                  <td>
                    <Time ts={a.created_utc} kind="created" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </section>

      {requesting && (
        <RequestApprovalDialog
          incident={incident}
          recommendation={requesting}
          onClose={() => setRequesting(null)}
          onDone={() => {
            setRequesting(null);
            approvals.reload();
          }}
        />
      )}
    </>
  );
}

function RequestApprovalDialog({
  incident,
  recommendation,
  onClose,
  onDone,
}: {
  incident: Incident;
  recommendation: Recommendation;
  onClose: () => void;
  onDone: () => void;
}) {
  const { toast } = useApp();
  const entities = (incident.detail.entities ?? []).map((e) => parseEntity(e));
  const [target, setTarget] = useState(entities[0]?.value ?? '');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const targetRef = useRef<HTMLSelectElement | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await api.requestApproval(incident.incident_id, {
        action_type: recommendation.action_type,
        ...(target ? { target } : {}),
        ...(note.trim() ? { note: note.trim() } : {}),
      });
      toast(`Approval request ${res.id} is pending. Another manager or admin must decide it.`);
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? describeError(err) : String(err));
      setBusy(false);
    }
  };

  return (
    <Dialog
      title="Request approval"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button kind="primary" onClick={() => void submit()} disabled={busy}>
            {busy ? 'Sending...' : 'Send request'}
          </Button>
        </>
      }
    >
      <dl className="kv">
        <dt>Action</dt>
        <dd>
          {recommendation.title} <span className="mono faint">{recommendation.action_type}</span>
        </dd>
        <dt>Incident</dt>
        <dd className="mono">{incident.incident_id}</dd>
      </dl>
      <div className="field">
        <label htmlFor="ap-target">Target (from the incident's entities)</label>
        <select id="ap-target" ref={targetRef} className="select" value={target} onChange={(e) => setTarget(e.target.value)}>
          {entities.map((e) => (
            <option key={`${e.kind}:${e.value}`} value={e.value}>
              {e.kind} {e.value}
            </option>
          ))}
          <option value="">No specific target</option>
        </select>
      </div>
      <div className="field">
        <label htmlFor="ap-note">Note for the reviewer (optional)</label>
        <textarea id="ap-note" className="textarea" rows={3} maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} />
      </div>
      <p className="muted">The executor is simulated: approving and executing records the decision, and no connector is called.</p>
      {error && (
        <p className="field-error" role="alert">
          {error}
        </p>
      )}
    </Dialog>
  );
}

// ---- header: severity, label, id, status; what happened (deterministic); key facts -----------

function IncidentHeader({
  incident,
  analysis,
  canUpdate,
  onStatus,
  entities,
  entitiesTotal,
  allEntities,
  onToggleEntities,
}: {
  incident: Incident;
  analysis: IncidentAnalysis | null;
  canUpdate: boolean;
  onStatus: (status: string) => void;
  entities: readonly string[];
  entitiesTotal: number;
  allEntities: boolean;
  onToggleEntities: () => void;
}) {
  const d = incident.detail;
  const s = analysis?.summary;
  const rule = s?.rule ?? null;
  // the What happened sentence is built from the incident's own data, never from the model
  const main = analysis ? mainFromNodes(analysis.graph.nodes) : null;
  const text = whatHappened(incident, rule, main);
  // the same distinct label as everywhere else; without a main entity it starts with the id, which the kicker already shows
  const label = incidentLabel(incident);
  const title = label.startsWith(incident.incident_id) ? `Incident${label.slice(incident.incident_id.length)}` : label;
  useScreenContext('incident', `Selected incident ${incident.incident_id} (${label}). What happened: ${text} Status: ${incident.status}.`);
  const dets = Object.entries(d.detectors ?? s?.detectors ?? {});
  const inputs = s?.inputs;
  const triage = [
    `gap ${d.gap_seconds ?? '?'} s`,
    d.max_span_seconds ? `span cap ${fmtInt(d.max_span_seconds)}\u00a0s` : null,
    d.segment && d.segment[1] > 1 ? `segment ${d.segment[0]} of ${d.segment[1]}` : null,
  ].filter(Boolean);

  return (
    <header className="inc-head">
      <div className="inc-title-row">
        <div className="inc-title">
          <div className="inc-kicker">
            <SeverityCell value={incident.severity} />
            <Id value={incident.incident_id} label="Copy incident id" />
          </div>
          <h2 id="incident-detail-title" tabIndex={-1}>
            {title}
          </h2>
        </div>
        <div className="inc-status">
          {canUpdate ? (
            <>
              <label className="tb-label" htmlFor="inc-set-status">
                Status
              </label>
              <select id="inc-set-status" className="select" value={incident.status} onChange={(e) => onStatus(e.target.value)}>
                {STATUSES.map((st) => (
                  <option key={st} value={st}>
                    {st}
                  </option>
                ))}
              </select>
            </>
          ) : (
            <StatusTag value={incident.status} />
          )}
        </div>
      </div>

      <div className="inc-what" aria-label="What happened">
        <p>{text}</p>
        <span className="quiet-note">What happened: built from this incident's stored data, not by the AI.</span>
      </div>

      <div className="inc-facts">
        <DefGrid
          items={[
            {
              label: (
                <>
                  First seen (UTC, <Term id="data-date">data date</Term>)
                </>
              ),
              value: <Time ts={incident.first_ts} />,
            },
            { label: 'Last seen (UTC)', value: <Time ts={incident.last_ts} /> },
            { label: 'Duration', value: <span className="num">{fmtDuration(epochSeconds(incident.last_ts) - epochSeconds(incident.first_ts))}</span> },
            { label: 'Alerts', value: <span className="num">{fmtInt(incident.alert_ids.length)}</span> },
            {
              label: (
                <>
                  <Term id="detector">Detectors</Term> agreeing
                </>
              ),
              value: (
                <span className="det-counts">
                  <span className="num">
                    {dets.length} of 3
                  </span>
                  {dets.map(([det, n]) => (
                    <span key={det}>
                      <DetectorTag value={det} /> <span className="num">{fmtInt(n)}</span>
                    </span>
                  ))}
                </span>
              ),
            },
            { label: 'Triage', value: <span className="num">{triage.join(', ')}</span> },
            {
              label: (
                <>
                  Why this severity{rule ? <> (<Term id="triage-rule">triage rule {rule.row}</Term>)</> : ''}
                </>
              ),
              value: (
                <span className="def-span">
                  {rule ? `${rule.severity} because ${rule.rule}.` : d.severity_row ? `Triage rule ${d.severity_row}.` : 'No triage rule recorded.'}
                  {inputs && (
                    <span className="faint">
                      {' '}
                      Inputs: {inputs.detectors ?? '?'} detector{inputs.detectors === 1 ? '' : 's'}, max level {inputs.max_level ?? '?'}, ATT&amp;CK{' '}
                      {inputs.attack_mapped ? 'mapped' : 'not mapped'}, <Term id="ioc">IOC</Term> {inputs.ioc_match ? 'match' : 'no match'},{' '}
                      {fmtInt(inputs.size ?? incident.alert_ids.length)} alerts.
                    </span>
                  )}
                </span>
              ),
            },
            {
              label: 'Entities',
              value: (
                <span className="def-span entity-list">
                  {entitiesTotal === 0 && <span className="faint">none recorded</span>}
                  {entities.map((e) => {
                    const p = parseEntity(e);
                    return (
                      <span key={e}>
                        <span className="kind">{p.kind}</span>
                        <Id value={p.value} label={`Copy ${p.kind} ${p.value}`} />
                      </span>
                    );
                  })}
                  {entitiesTotal > 3 && (
                    <button type="button" className="linklike" onClick={onToggleEntities} aria-expanded={allEntities}>
                      {allEntities ? 'Show fewer' : `Show all ${fmtInt(entitiesTotal)}`}
                    </button>
                  )}
                </span>
              ),
            },
          ]}
        />
      </div>
    </header>
  );
}
