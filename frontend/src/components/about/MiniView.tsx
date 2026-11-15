// The hero's live mini-view (DESIGN.md 7): a small, non-interactive frame of the real product for the
// selected data source, built from the product's own components (Kpi, TimeBars, SeverityCell) and fed
// by /overview and /incidents/summary. Skeleton while loading, a quiet notice on error, never fake data.
// The frame is `inert` (no tab stops, out of the accessibility tree); the figure's label carries the numbers.

import { useMemo } from 'react';

import type { ApiError, IncidentSummaryRow, Overview } from '../../api.ts';
import { TimeBars } from '../../charts/TimeBars.tsx';
import { distinctLabels } from '../../lib/explain.ts';
import { compareQueue, epochSeconds, fmtInt } from '../../lib/format.ts';
import { Kpi, SeverityCell } from '../ui.tsx';

interface Props {
  scenario: string | null;
  overview: Overview | null;
  overviewError: ApiError | null;
  incidents: IncidentSummaryRow[] | null;
}

export function lookFirst(rows: IncidentSummaryRow[] | null, n: number): IncidentSummaryRow[] {
  return (rows ?? [])
    .filter((r) => (r.status ?? 'open') !== 'closed')
    .map((r) => ({ ...r, status: r.status ?? 'open' }))
    .sort(compareQueue)
    .slice(0, n);
}

export function MiniView({ scenario, overview, overviewError, incidents }: Props) {
  const top = useMemo(() => lookFirst(incidents, 3), [incidents]);
  const labels = useMemo(() => distinctLabels(top), [top]);

  if (!scenario) return <p className="ab-mini-note">No data source is selected, so there is no live view. Pick one in the top bar.</p>;
  if (overviewError && !overview)
    return (
      <p className="ab-mini-note" role="status">
        The live view could not load ({overviewError.status || 'API unreachable'}). The rest of this page does not depend on it.
      </p>
    );
  if (!overview)
    return (
      <div className="ab-mini card flush" aria-busy="true" aria-label="Loading the live view">
        <div className="ab-mini-head">
          <span className="skeleton-bar ab-skel-s" />
        </div>
        <div className="ab-mini-kpis">
          {[0, 1, 2].map((i) => (
            <div key={i} className="kpi">
              <span className="skeleton-bar ab-skel-s" />
              <span className="skeleton-bar ab-skel-m" />
            </div>
          ))}
        </div>
        <div className="ab-mini-chart">
          <div className="skel-block" />
        </div>
      </div>
    );

  const ts = overview.timeseries;
  const detectorsWithAlerts = overview.detectors.filter((d) => d.alerts > 0).length;
  const summary = `Live view of ${overview.scenario}: ${fmtInt(overview.alerts)} alerts stored, ${fmtInt(overview.status.incidents)} incidents built by triage, ${fmtInt(detectorsWithAlerts)} detectors with alerts.${top.length ? ` First incident to look at: ${labels.get(top[0]!.incident_id)} (${top[0]!.severity}).` : ''}`;
  return (
    <figure className="ab-mini card flush" aria-label={summary}>
      <figcaption className="ab-mini-head">
        <span>Overview</span>
        <span className="mono faint">{overview.scenario}</span>
        <span className="ab-live faint">Live from the API</span>
      </figcaption>
      <div className="ab-mini-body" inert>
        <div className="ab-mini-kpis">
          <Kpi label="Alerts stored" value={fmtInt(overview.alerts)} />
          <Kpi label="Incidents" value={fmtInt(overview.status.incidents)} />
          <Kpi label="Detectors with alerts" value={fmtInt(detectorsWithAlerts)} />
        </div>
        <div className="ab-mini-chart">
          <div className="ab-mini-label">Alerts over time, by detector</div>
          {ts.total > 0 && ts.start ? (
            <TimeBars series={ts.series} start={epochSeconds(ts.start)} binSeconds={ts.bin_seconds ?? 1} height={112} label="Alerts over time" />
          ) : (
            <p className="faint">No stored alerts for this data source.</p>
          )}
        </div>
        <div className="ab-mini-list">
          <div className="ab-mini-label">Incidents to look at first</div>
          {!incidents ? (
            <span className="skeleton-bar ab-skel-m" />
          ) : top.length === 0 ? (
            <p className="faint">No open incident.</p>
          ) : (
            <ul>
              {top.map((r) => (
                <li key={r.incident_id}>
                  <SeverityCell value={r.severity} />
                  <span className="mono ab-mini-name">{labels.get(r.incident_id)}</span>
                  <span className="num faint">{fmtInt(r.alerts)} alerts</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </figure>
  );
}
