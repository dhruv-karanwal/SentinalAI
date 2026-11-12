// Entity view: one host or source IP. Activity over time by detector, top rules, and the
// incidents that contain it; the alert table below is filtered to the entity.

import { api, ApiError } from '../api.ts';
import { HBars } from '../charts/Bars.tsx';
import { ChartFrame, DETECTOR_ORDER, detectorTone, sevTone } from '../charts/ChartFrame.tsx';
import { TimeBars } from '../charts/TimeBars.tsx';
import { AlertQueryTable } from '../components/AlertQueryTable.tsx';
import { ErrorState, SeverityCell, SkeletonLines, StatusTag, Time, detectorName } from '../components/ui.tsx';
import { buildHash, useLoad } from '../hooks.ts';
import { epochSeconds, fmtDuration, fmtInt } from '../lib/format.ts';

export function EntityScreen({ scenario, kind, value }: { scenario: string; kind: string; value: string }) {
  const { data, error, reload } = useLoad((signal) => api.entity(kind, value, scenario, signal), [scenario, kind, value]);
  if (!value || (kind !== 'host' && kind !== 'ip')) return <ErrorState what="the entity" error={new ApiError(422, '/entities', 'the link needs kind=host|ip and a value')} />;
  if (error && !data) return <ErrorState what={`${kind} ${value}`} error={error} onRetry={reload} />;
  if (!data) return <SkeletonLines lines={6} />;
  const ts = data.timeseries;
  const start = ts.start ? epochSeconds(ts.start) : 0;
  const dets = DETECTOR_ORDER.filter((d) => data.by_detector[d]);
  return (
    <div className="page">
      <div className="page-head">
        <h1>
          {kind === 'host' ? 'Host' : 'Source IP'} <span className="mono">{value}</span>
        </h1>
        <span className="muted num">
          {fmtInt(data.alerts)} alerts in {scenario}
          {data.first_ts && (
            <>
              {' '}
              · first <Time ts={data.first_ts} /> · last <Time ts={data.last_ts} />
            </>
          )}
        </span>
        <span className="spacer" />
        <a className="btn" href={buildHash('/alerts', kind === 'host' ? { host: value } : { ip: value })}>
          Open in Alerts
        </a>
      </div>
      <div className="page-body">
        <ChartFrame
          title="Activity"
          question="When was this entity active, and which detectors saw it?"
          legend={dets.map((d) => ({ key: d, label: detectorName(d), tone: detectorTone(d), value: fmtInt(data.by_detector[d] ?? 0) }))}
          table={{ columns: ['bin start (UTC)', ...dets.map(detectorName)], rows: Array.from({ length: ts.bins }, (_, i) => [new Date((start + i * (ts.bin_seconds ?? 1)) * 1000).toISOString(), ...dets.map((d) => ts.series[d]?.[i] ?? 0)]) }}
          empty={data.alerts === 0 ? `No stored alert has ${kind === 'host' ? 'host_ip' : 'source IP'} ${value}.` : undefined}
          note={`Bins of ${fmtDuration(ts.bin_seconds ?? 1)}.${kind === 'ip' ? ' An IP counts when it is the alert source or the host.' : ''}`}
        >
          <TimeBars series={ts.series} start={start} binSeconds={ts.bin_seconds ?? 1} height={150} label={`Activity of ${value}`} />
        </ChartFrame>
        <div className="grid-2">
          <ChartFrame
            title="Top rules"
            question="What is being reported about it?"
            table={{ columns: ['rule id', 'rule name', 'alerts'], rows: data.top_rules.map((r) => [r.rule_id, r.rule_name ?? '', r.alerts]) }}
            empty={data.top_rules.length === 0 ? 'No rules.' : undefined}
          >
            <HBars
              unit="alerts"
              rows={data.top_rules.map((r) => ({
                key: r.rule_id + (r.rule_name ?? ''),
                label: (
                  <span>
                    <span className="mono faint">{r.rule_id}</span> {r.rule_name}
                  </span>
                ),
                text: `${r.rule_id} ${r.rule_name ?? ''}`,
                value: r.alerts,
                tone: 'accent',
                onActivate: () => (window.location.hash = buildHash('/alerts', { rule_id: r.rule_id, ...(kind === 'host' ? { host: value } : { ip: value }) })),
              }))}
            />
          </ChartFrame>
          <ChartFrame
            title="Incidents that contain it"
            question="Is it part of something already in the queue?"
            table={{ columns: ['incident', 'severity', 'status', 'alerts'], rows: data.incidents.map((i) => [i.incident_id, i.severity, i.status ?? 'open', i.alerts]) }}
            empty={data.incidents.length === 0 ? 'In no incident.' : undefined}
            note={data.incidents_total > data.incidents.length ? `First ${data.incidents.length} of ${fmtInt(data.incidents_total)}.` : undefined}
          >
            <HBars
              unit="alerts"
              rows={data.incidents.slice(0, 12).map((i) => ({
                key: i.incident_id,
                label: (
                  <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                    <SeverityCell value={i.severity} /> <StatusTag value={i.status ?? 'open'} /> <span className="mono">{i.incident_id.slice(0, 16)}</span>
                  </span>
                ),
                text: `${i.severity} incident ${i.incident_id}`,
                value: i.alerts,
                tone: sevTone(i.severity),
                onActivate: () => (window.location.hash = buildHash('/incidents', { id: i.incident_id })),
              }))}
            />
          </ChartFrame>
        </div>
        <section className="chart" style={{ padding: 0 }}>
          <div className="pane-head">
            <h2 style={{ fontSize: 'var(--fs-14)' }}>Alerts of {value}</h2>
          </div>
          <div style={{ height: 360, display: 'flex', flexDirection: 'column' }}>
            <AlertQueryTable scenario={scenario} filter={kind === 'host' ? { host: value } : { ip: value }} label={`Alerts of ${value}`} onOpen={(a) => (window.location.hash = buildHash('/alerts', { id: a.alert_id }))} />
          </div>
        </section>
      </div>
    </div>
  );
}
