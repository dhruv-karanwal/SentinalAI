// Reports: stored incident reports. The body is the JSON the API built (timeline, citations,
// techniques, recommendations); CSV and PDF are downloads of the same body.

import { Term } from '../components/Term.tsx';
import { useEffect, useMemo, useState } from 'react';

import { api, ApiError, downloadReport, type Report, type ReportBody } from '../api.ts';
import { ChartFrame, DETECTOR_ORDER, detectorTone } from '../charts/ChartFrame.tsx';
import { EntityGraph } from '../charts/EntityGraph.tsx';
import { TimeBars } from '../charts/TimeBars.tsx';
import { DataTable, type Column } from '../components/DataTable.tsx';
import { EvidencePane } from '../components/EvidencePane.tsx';
import { SplitPane } from '../components/SplitPane.tsx';
import { Button, DefGrid, describeError, DetectorTag, detectorName, EmptyState, ErrorNotice, ErrorState, Id, PageHeader, SeverityCell, SkeletonLines, Tabs, Time, TruncatedText } from '../components/ui.tsx';
import { Icon } from '../icons.tsx';
import { useApp, useLoad, type Route } from '../hooks.ts';
import { epochSeconds, fmtDuration, fmtInt, isoUtc } from '../lib/format.ts';
import { fitColumns, useNarrow } from '../components/narrow.ts';

interface Props {
  route: Route & { setParams: (patch: Record<string, string | null>, replace?: boolean) => void };
}

type TimelineRow = ReportBody['timeline'][number];

export function ReportsScreen({ route }: Props) {
  const { scenario } = useApp();
  const { data, error, loading, reload } = useLoad((signal) => api.reports(null, signal), []);
  const rows = useMemo(() => (data?.reports ?? []).filter((r) => !scenario || r.body.incident.scenario === scenario), [data, scenario]);
  const selectedId = route.params.id ?? null;
  const selected = (data?.reports ?? []).find((r) => r.report_id === selectedId) ?? null;

  useEffect(() => {
    if (!selectedId && rows.length > 0) route.setParams({ id: rows[0]!.report_id });
  }, [selectedId, rows, route]);

  const columns = useMemo<Column<Report>[]>(
    () => [
      { id: 'created', header: 'Created (UTC, console)', width: '152px', sortKey: (r) => r.created_utc, render: (r) => <Time ts={r.created_utc} /> },
      { id: 'sev', header: 'Severity', width: '82px', render: (r) => <SeverityCell value={r.body.incident.severity} /> },
      { id: 'alerts', header: 'Alerts', width: '56px', align: 'right', sortKey: (r) => r.body.incident.alerts, render: (r) => fmtInt(r.body.incident.alerts) },
      { id: 'incident', header: 'Incident', width: 'minmax(0, 1fr)', sortKey: (r) => r.incident_id, title: (r) => r.incident_id, render: (r) => <span className="mono">…{r.incident_id.slice(-8)}</span> },
    ],
    [],
  );

  const list = (
    <>
      {error && data && <ErrorNotice what="reports" error={error} onRetry={reload} />}
      {error && !data ? (
        <ErrorState what="reports" error={error} onRetry={reload} />
      ) : (
        <DataTable
          label="Reports, newest first"
          unit="reports"
          primary
          rows={rows}
          columns={columns}
          rowKey={(r) => r.report_id}
          selectedKey={selectedId}
          onSelect={(r) => route.setParams({ id: r.report_id, ev: null })}
          onOpen={() => document.getElementById('report-detail-title')?.focus()}
          copyText={(r) => r.report_id}
          loading={loading}
          empty={
            <EmptyState title={`No reports for ${scenario ?? 'any data source'}.`}>
              A report is created from an incident: Incidents, Response, Create report.
            </EmptyState>
          }
        />
      )}
    </>
  );

  const detail = selected ? (
    <ReportDetail key={selected.report_id} report={selected} route={route} />
  ) : loading && !data ? (
    <SkeletonLines lines={5} />
  ) : (
    <EmptyState title="No report selected.">Select a report to preview it and download it.</EmptyState>
  );
  return (
    <div className="work">
      <PageHeader
        bar
        title="Reports"
        purpose="What was written up?"
        actions={
          <Button icon="refresh" className="no-print" onClick={reload} disabled={loading}>
            Reload
          </Button>
        }
      />
      <SplitPane id="reports" left={list} right={detail} initial={34} />
    </div>
  );
}

function ReportDetail({ report, route }: { report: Report; route: Props['route'] }) {
  const { toast } = useApp();
  const [tab, setTab] = useState<'preview' | 'timeline' | 'citations' | 'summary'>('preview');
  const [focusEvidence, setFocusEvidence] = useState<number | null>(null);
  const b = report.body;
  const ev = route.params.ev ?? null;

  const download = async (format: 'json' | 'csv' | 'pdf') => {
    try {
      await downloadReport(report.report_id, format);
    } catch (err) {
      toast(err instanceof ApiError ? describeError(err) : String(err), 'error');
    }
  };

  const panel = (id: string) => ({ role: 'tabpanel', id: `rp-panel-${id}`, 'aria-labelledby': `rp-tab-${id}` }) as const;

  const columns = useMemo<Column<TimelineRow>[]>(
    () => [
      { id: 'ts', header: 'Time (UTC, data date)', width: '152px', sortKey: (r) => r.ts, render: (r) => <Time ts={r.ts} /> },
      { id: 'det', header: 'Detector', width: '80px', sortKey: (r) => r.detector, render: (r) => <DetectorTag value={r.detector} /> },
      { id: 'rule', header: 'Rule id', width: '88px', sortKey: (r) => r.rule_id, render: (r) => <span className="mono">{r.rule_id ?? '-'}</span> },
      { id: 'name', header: 'Rule name', width: 'minmax(0, 1fr)', sortKey: (r) => r.rule_name, title: (r) => r.rule_name ?? '', render: (r) => r.rule_name ?? <span className="faint">-</span> },
      { id: 'tech', header: 'Techniques', width: '104px', sortKey: (r) => r.techniques.join(','), render: (r) => <span className="mono">{r.techniques.join(', ') || '-'}</span> },
    ],
    [],
  );

  const narrow = useNarrow();
  const cols = useMemo(() => fitColumns(columns, narrow, ['rule', 'tech']), [columns, narrow]);

  return (
    <>
      <div className="pane-bar">
        <h2 id="report-detail-title" tabIndex={-1}>
          Report
        </h2>
        <Id value={report.report_id} label="Copy report id" />
        <span className="spacer" />
        <div className="btn-row no-print">
          <Button
            icon="print"
            onClick={() => {
              setTab('preview');
              window.setTimeout(() => window.print(), 50);
            }}
            title="Print the executive summary of this report (light theme)"
          >
            Print summary
          </Button>
          {(['json', 'csv', 'pdf'] as const).map((f) => (
            <Button key={f} icon="download" onClick={() => void download(f)} title={`Download the report as ${f.toUpperCase()}`}>
              {f.toUpperCase()}
            </Button>
          ))}
        </div>
      </div>
      <section className="block" aria-label="Report facts">
        <DefGrid
          items={[
            {
              label: 'Incident',
              value: (
                <span className="def-span">
                  <a className="mono" href={`#/incidents?id=${encodeURIComponent(report.incident_id)}`}>
                    {report.incident_id}
                  </a>
                </span>
              ),
            },
            { label: 'Severity', value: <SeverityCell value={b.incident.severity} /> },
            { label: 'Alerts', value: <span className="num">{fmtInt(b.incident.alerts)}</span> },
            { label: 'Created (UTC)', value: <Time ts={report.created_utc} kind="created" /> },
            { label: 'First seen (UTC)', value: <Time ts={b.incident.first_ts} kind="data" /> },
            { label: 'Last seen (UTC)', value: <Time ts={b.incident.last_ts} kind="data" /> },
            {
              label: 'Detectors',
              value: (
                <span className="det-counts">
                  {Object.entries(b.incident.detectors).map(([d, n]) => (
                    <span key={d}>
                      <DetectorTag value={d} /> <span className="num">{fmtInt(n)}</span>
                    </span>
                  ))}
                </span>
              ),
            },
          ]}
        />
      </section>
      {b.timeline_rows_omitted > 0 && (
        <div className="notice" role="status">
          <Icon name="warning" />
          <span>
            Showing {fmtInt(b.timeline.length)} of {fmtInt(b.incident.alerts)} rows ({fmtInt(b.timeline_rows_omitted)} omitted by the report limit). Technique counts
            cover all alerts.
          </span>
        </div>
      )}
      <Tabs
        tabs={[
          { id: 'preview', label: 'Preview' },
          { id: 'summary', label: 'Techniques and actions', count: fmtInt(b.techniques.length) },
          { id: 'timeline', label: 'Timeline', count: fmtInt(b.timeline.length) },
          { id: 'citations', label: 'Citations', count: fmtInt(b.citations.length) },
        ]}
        value={tab}
        onChange={setTab}
        label="Report sections"
        idBase="rp"
      />

      {tab === 'preview' && (
        <div className="tabpanel detail-scroll report-preview tab-enter" {...panel('preview')}>
          <ReportPreview report={report} />
        </div>
      )}

      {tab === 'summary' && (
        <div className="tabpanel detail-scroll tab-enter" {...panel('summary')}>
          <section className="block" aria-label="ATT&CK techniques">
            <h3 className="block-title">
              <Term id="attack-technique">ATT&amp;CK techniques</Term>
            </h3>
            {b.techniques.length === 0 ? (
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
                  {b.techniques.map((t) => (
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
              Recommended actions <span className="meta"><Term id="playbook">playbooks</Term></span>
            </h3>
            <div className="table-scroll">
            <table className="plain-table">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Type</th>
                  <th>Techniques</th>
                  <th>Approval</th>
                </tr>
              </thead>
              <tbody>
                {b.recommendations.map((r) => (
                  <tr key={`${r.action_type}|${r.title}`}>
                    <td>{r.title}</td>
                    <td className="mono nowrap">{r.action_type}</td>
                    <td className="mono">{r.techniques.join(', ') || '-'}</td>
                    <td>{r.requires_approval ? 'required' : 'not needed'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
            <p className="quiet-note">Request an approval from the incident's Response tab.</p>
          </section>
          {b.notice && (
            <section className="block">
              <p className="muted">{b.notice}</p>
            </section>
          )}
        </div>
      )}

      {tab === 'timeline' && (
        <div className="tabpanel tab-enter" {...panel('timeline')}>
          <div className="inc-list-split">
          <DataTable
            label="Report timeline"
            unit="rows"
            rows={b.timeline}
            columns={cols}
            rowKey={(r) => r.alert_id}
            selectedKey={ev}
            onSelect={(r) => route.setParams({ ev: r.alert_id })}
            onOpen={() => setFocusEvidence(Date.now())}
            copyText={(r) => r.alert_id}
          />
          </div>
          {ev && (
            <div className="inc-ev-split">
              <EvidencePane alertId={ev} focusKey={focusEvidence} onClose={() => route.setParams({ ev: null })} />
            </div>
          )}
        </div>
      )}

      {tab === 'citations' && (
        <div className="tabpanel detail-scroll tab-enter" {...panel('citations')}>
          <div className="block">
            {b.citations.length === 0 && <EmptyState title="No citations.">This report cites no alert.</EmptyState>}
            <div>
            {b.citations.slice(0, 200).map((c) => (
              <div className="rp-cite" key={c.alert_id}>
                <span className="head">
                  <button type="button" className="linklike mono" onClick={() => {
                      setTab('timeline');
                      setFocusEvidence(Date.now());
                      route.setParams({ ev: c.alert_id });
                    }}>
                    {c.alert_id}
                  </button>{' '}
                  <DetectorTag value={c.detector} /> <span className="faint">rule {c.rule_id ?? '-'}</span>
                </span>
                <span className="text">
                  {c.evidence_excerpt ? <TruncatedText text={c.evidence_excerpt} limit={300} /> : <span className="faint">no log line</span>}
                  {c.excerpt_truncated && <span className="faint"> (excerpt cut by the report)</span>}
                </span>
              </div>
            ))}
            </div>
            {b.citations.length > 200 && (
              <p className="muted">
                Showing 200 of {fmtInt(b.citations.length)} citations. The Timeline tab lists every row; the JSON download has all of them.
              </p>
            )}
          </div>
        </div>
      )}

    </>
  );
}

/** The report as a reader sees it: summary, the two stored charts, techniques, actions. */
function ReportPreview({ report }: { report: Report }) {
  const b = report.body;
  const c = b.charts;
  const ts = c?.timeseries;
  const start = ts?.start ? epochSeconds(ts.start) : 0;
  const dets = ts ? DETECTOR_ORDER.filter((d) => ts.series[d]) : [];
  const span = epochSeconds(b.incident.last_ts) - epochSeconds(b.incident.first_ts);
  return (
    <div className="block">
      <div className="inc-what">
        <h3 className="block-title">Executive summary</h3>
        <p className="rp-summary">
          <SeverityCell value={b.incident.severity} /> incident <span className="mono">{b.incident.incident_id}</span> in {b.incident.scenario}: {fmtInt(b.incident.alerts)} alerts over{' '}
          {fmtDuration(span)} ({isoUtc(b.incident.first_ts)} to {isoUtc(b.incident.last_ts)}, UTC), from {Object.keys(b.incident.detectors).length} detector
          {Object.keys(b.incident.detectors).length === 1 ? '' : 's'}, involving {fmtInt(b.incident.entities.length)} hosts and addresses.{' '}
          {b.techniques.length > 0 ? `Mapped ATT&CK techniques: ${b.techniques.map((t) => `${t.technique_id} (${fmtInt(t.alerts)})`).join(', ')}.` : 'No alert is mapped to ATT&CK.'}{' '}
          {b.recommendations.length > 0 ? `${b.recommendations.length} playbook suggestion${b.recommendations.length === 1 ? '' : 's'}; nothing runs without an approved request.` : ''}
        </p>
        <p className="quiet-note">
          Report {report.report_id}, created {isoUtc(report.created_utc)}. Platform output on replayed demo data; no labels.
        </p>
      </div>
      {!c ? (
        <div className="notice" role="status">This report was stored before charts were added (report version {String(b.report_version ?? 'd1')}). Create a new report from the incident to get the timeline and entity graph.</div>
      ) : (
        <>
          <ChartFrame
            className="flat-chart"
            title="Alert timeline"
            question="When did the incident's alerts arrive, and from which detector?"
            legend={dets.map((d) => ({ key: d, label: detectorName(d), tone: detectorTone(d), value: fmtInt(ts!.series[d]!.reduce((x, y) => x + y, 0)) }))}
            table={{ columns: ['bin start (UTC)', ...dets], rows: Array.from({ length: ts!.bins }, (_, i) => [new Date((start + i * (ts!.bin_seconds ?? 1)) * 1000).toISOString(), ...dets.map((d) => ts!.series[d]![i] ?? 0)]) }}
            empty={!ts || ts.total === 0 ? 'No alerts in the stored chart.' : undefined}
            note="The same bins are drawn in the PDF."
          >
            <TimeBars series={ts!.series} start={start} binSeconds={ts!.bin_seconds ?? 1} height={140} label="Report alert timeline" />
          </ChartFrame>
          <EntityGraph graph={c.graph} fixed title="Entity graph snapshot" question="Which addresses and hosts are involved? (positions stored with the report; the PDF draws the same picture)" />
        </>
      )}
    </div>
  );
}
