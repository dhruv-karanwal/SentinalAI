// Entity view: one host or source IP. Activity over time by detector, top rules, and the
// incidents that contain it; the alert table below is filtered to the entity.

import { api, ApiError } from '../api.ts';
import { HBars } from '../charts/Bars.tsx';
import { ChartFrame, DETECTOR_ORDER, detectorTone, sevTone } from '../charts/ChartFrame.tsx';
import { TimeBars } from '../charts/TimeBars.tsx';
import { AlertQueryTable } from '../components/AlertQueryTable.tsx';
import { DefGrid, DetectorTag, ErrorState, Page, PageHeader, Section, SeverityCell, SkeletonLines, StatusTag, Time, detectorName } from '../components/ui.tsx';
import { buildHash, useLoad } from '../hooks.ts';
import { epochSeconds, fmtDuration, fmtInt } from '../lib/format.ts';

export function EntityScreen({ scenario, kind, value }: { scenario: string; kind: string; value: string }) {
  const { data, error, reload } = useLoad((signal) => api.entity(kind, value, scenario, signal), [scenario, kind, value]);
  const noun = kind === 'host' ? 'Host' : 'Source IP';
  const crumbs = [{ label: 'Alerts', href: '#/alerts' }, { label: `${noun} ${value}` }];
  const header = (
    <PageHeader
      crumbs={crumbs}
      title={
        <>
          {noun} <span className="mono">{value}</span>
        </>
      }
      purpose="What has this address done, and is it part of an incident already?"
      actions={
        value ? (
          <a className="btn" href={buildHash('/alerts', kind === 'host' ? { host: value } : { ip: value })}>
            Open in Alerts
          </a>
        ) : undefined
      }
    />
  );
  if (!value || (kind !== 'host' && kind !== 'ip'))
    return (
      <Page label="Entity">
        {header}
        <ErrorState what="the entity" error={new ApiError(422, '/entities', 'the link needs kind=host|ip and a value')} />
      </Page>
    );
  if (error && !data)
    return (
      <Page label="Entity">
        {header}
        <ErrorState what={`${kind} ${value}`} error={error} onRetry={reload} />
      </Page>
    );
  if (!data)
    return (
      <Page label="Entity">
        {header}
        <SkeletonLines lines={6} />
      </Page>
    );
  const ts = data.timeseries;
  const start = ts.start ? epochSeconds(ts.start) : 0;
  const dets = DETECTOR_ORDER.filter((d) => data.by_detector[d]);
  return (
    <Page label={`${noun} ${value}`}>
      {header}
      <div className="card">
        <DefGrid
          items={[
            { label: 'Alerts', value: <span className="num">{fmtInt(data.alerts)}</span> },
            { label: 'Data source', value: <span className="mono">{scenario}</span> },
            { label: 'First seen (UTC)', value: <Time ts={data.first_ts} /> },
            { label: 'Last seen (UTC)', value: <Time ts={data.last_ts} /> },
            {
              label: 'Detectors',
              value:
                dets.length === 0 ? (
                  <span className="faint">none</span>
                ) : (
                  <span className="det-counts">
                    {dets.map((d) => (
                      <span key={d}>
                        <DetectorTag value={d} /> <span className="num">{fmtInt(data.by_detector[d] ?? 0)}</span>
                      </span>
                    ))}
                  </span>
                ),
            },
            { label: 'Incidents', value: <span className="num">{fmtInt(data.incidents_total)}</span> },
          ]}
        />
      </div>

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

      <div className="grid-12">
        <div className="col-6">
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
                tone: 'ref',
                onActivate: () => (window.location.hash = buildHash('/alerts', { rule_id: r.rule_id, ...(kind === 'host' ? { host: value } : { ip: value }) })),
              }))}
            />
          </ChartFrame>
        </div>
        <div className="col-6">
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
                  <span className="det-counts">
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
      </div>

      <Section id="en-alerts" title={`Alerts of ${value}`} description="In time order. Enter or double click opens an alert in Alerts.">
        <div className="card flush entity-table">
          <AlertQueryTable scenario={scenario} filter={kind === 'host' ? { host: value } : { ip: value }} label={`Alerts of ${value}`} onOpen={(a) => (window.location.hash = buildHash('/alerts', { id: a.alert_id }))} />
        </div>
      </Section>
    </Page>
  );
}
