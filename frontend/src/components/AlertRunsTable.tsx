// Alerts with repeats folded (GET /alerts/runs): consecutive alerts with the same detector, rule,
// level, host and source IP are one row, "x14,436 same rule, same host", so a burst no longer
// looks like a page of identical rows. Expanding a row loads its first alerts inline (the current
// filter plus the run's time window, which selects exactly that run); "Show all" turns the run
// into a filter. Nothing is dropped: the folded counts add up to the filter's total.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { api, ApiError, type AlertFilter, type AlertRun, type QueryRow } from '../api.ts';
import { useLoad } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { fmtInt } from '../lib/format.ts';
import { describeFilter, filterKey } from './AlertQueryTable.tsx';
import { DataTable, type Column } from './DataTable.tsx';
import { DetectorTag, ErrorNotice, ErrorState, Time, describeError } from './ui.tsx';

const PAGE = 200;
const CHILDREN = 50;

type Row = { kind: 'run'; key: string; run: AlertRun } | { kind: 'alert'; key: string; alert: QueryRow; parent: string };

interface Props {
  scenario: string;
  filter: AlertFilter;
  label: string;
  selectedId: string | null;
  onSelect: (alertId: string) => void;
  onFilter: (patch: Partial<AlertFilter>) => void;
  primary?: boolean;
}

function untilAfter(ts: string): string {
  return new Date(Date.parse(ts) + 1).toISOString();
}

export function AlertRunsTable({ scenario, filter, label, selectedId, onSelect, onFilter, primary = false }: Props) {
  const key = filterKey(filter);
  const first = useLoad((signal) => api.alertRuns(scenario, filter, PAGE, 0, signal), [scenario, key]);
  const [more, setMore] = useState<AlertRun[]>([]);
  const [moreError, setMoreError] = useState<ApiError | null>(null);
  const [open, setOpen] = useState<Record<string, QueryRow[] | 'loading'>>({});
  const loading = useRef(false);
  useEffect(() => {
    setMore([]);
    setOpen({});
  }, [scenario, key]);
  const runs = useMemo(() => [...(first.data?.runs ?? []), ...more], [first.data, more]);
  const totalRuns = first.data?.total_runs ?? 0;
  const totalAlerts = first.data?.total_alerts ?? 0;

  const loadMore = useCallback(() => {
    if (loading.current || runs.length >= totalRuns || !first.data) return;
    loading.current = true;
    api.alertRuns(scenario, filter, PAGE, runs.length).then(
      (r) => {
        setMore((m) => [...m, ...r.runs]);
        loading.current = false;
      },
      (e: unknown) => {
        setMoreError(e instanceof ApiError ? e : new ApiError(0, '/alerts/runs', String(e)));
        loading.current = false;
      },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runs.length, totalRuns, first.data, scenario, key]);

  const toggle = useCallback(
    (run: AlertRun) => {
      const id = run.first_alert_id;
      if (open[id]) {
        setOpen((o) => {
          const n = { ...o };
          delete n[id];
          return n;
        });
        return;
      }
      setOpen((o) => ({ ...o, [id]: 'loading' }));
      api.queryAlerts(scenario, { ...filter, since: run.first_ts, until: untilAfter(run.last_ts) }, Math.min(CHILDREN, run.count), 0).then(
        (r) => setOpen((o) => (o[id] ? { ...o, [id]: r.alerts.slice(0, run.count) } : o)),
        (e: unknown) => {
          setOpen((o) => {
            const n = { ...o };
            delete n[id];
            return n;
          });
          setMoreError(e instanceof ApiError ? e : new ApiError(0, '/alerts/query', String(e)));
        },
      );
    },
    [open, scenario, filter],
  );

  const rows = useMemo<Row[]>(() => {
    const out: Row[] = [];
    for (const run of runs) {
      out.push({ kind: 'run', key: `run:${run.first_alert_id}`, run });
      const kids = open[run.first_alert_id];
      if (Array.isArray(kids)) for (const a of kids) if (run.count > 1) out.push({ kind: 'alert', key: `al:${a.alert_id}`, alert: a, parent: run.first_alert_id });
    }
    return out;
  }, [runs, open]);

  const selectedKey = useMemo(() => {
    if (!selectedId) return null;
    if (rows.some((r) => r.kind === 'alert' && r.alert.alert_id === selectedId)) return `al:${selectedId}`;
    return `run:${selectedId}`;
  }, [rows, selectedId]);

  const columns = useMemo<Column<Row>[]>(
    () => [
      {
        id: 'ts',
        header: 'Time (UTC, data date)',
        width: '146px',
        render: (r) => <Time ts={r.kind === 'run' ? r.run.first_ts : r.alert.ts} />,
      },
      { id: 'det', header: 'Detector', width: '74px', render: (r) => <DetectorTag value={r.kind === 'run' ? r.run.detector : r.alert.detector} /> },
      {
        id: 'sev',
        header: 'Own level',
        width: '60px',
        align: 'right',
        render: (r) => {
          const v = r.kind === 'run' ? r.run.severity : r.alert.severity;
          return v ?? <span className="faint">-</span>;
        },
      },
      {
        id: 'rule',
        header: 'Rule (repeats folded)',
        width: 'minmax(0, 1fr)',
        title: (r) =>
          r.kind === 'run'
            ? `${r.run.count > 1 ? `${fmtInt(r.run.count)} alerts in a row, same rule, level, host and source IP: ` : ''}${r.run.rule_id ?? ''} ${r.run.rule_name ?? ''}`
            : `one alert of the run: ${r.alert.rule_id ?? ''} ${r.alert.rule_name ?? ''}`,
        render: (r) => {
          if (r.kind === 'alert')
            return (
              <span className="fold-child">
                <span className="fold-indent" aria-hidden="true" />
                <span className="mono faint">{r.alert.rule_id ?? '-'}</span> {r.alert.rule_name}
              </span>
            );
          const st = open[r.run.first_alert_id];
          return (
            <span>
              {r.run.count > 1 && (
                <button
                  type="button"
                  className="fold-btn"
                  aria-expanded={!!st}
                  aria-label={`${st ? 'Collapse' : 'Expand'} ${fmtInt(r.run.count)} repeated alerts`}
                  onClick={(e) => {
                    e.stopPropagation();
                    toggle(r.run);
                  }}
                >
                  <Icon name={st ? 'chevronDown' : 'chevronRight'} />×{fmtInt(r.run.count)}
                </button>
              )}{' '}
              <span className="mono faint">{r.run.rule_id ?? '-'}</span> {r.run.rule_name}
              {r.run.count > 1 && <span className="faint"> · same rule, same host</span>}
            </span>
          );
        },
      },
      { id: 'host', header: 'Host', width: '104px', render: (r) => <span className="mono">{(r.kind === 'run' ? r.run.host_ip : r.alert.host_ip) ?? '-'}</span> },
    ],
    [open, toggle],
  );

  if (first.error && !first.data) return <ErrorState what="alerts" error={first.error} onRetry={first.reload} />;
  const pick = (r: Row) => onSelect(r.kind === 'run' ? r.run.first_alert_id : r.alert.alert_id);
  return (
    <>
      {first.error && first.data && <ErrorNotice what="alerts" error={first.error} onRetry={first.reload} />}
      {moreError && (
        <div className="notice" data-kind="error" role="alert">
          Rows could not be loaded: {describeError(moreError)}
        </div>
      )}
      <DataTable
        label={label}
        unit="rows"
        rows={rows}
        columns={columns}
        rowKey={(r) => r.key}
        selectedKey={selectedKey}
        onSelect={pick}
        onOpen={(r) => (r.kind === 'run' && r.run.count > 1 ? toggle(r.run) : pick(r))}
        copyText={(r) => (r.kind === 'run' ? r.run.first_alert_id : r.alert.alert_id)}
        primary={primary}
        loading={first.loading && !first.data}
        onEndReached={loadMore}
        empty={`No alerts match ${describeFilter(filter)} in ${scenario}.`}
        footer={
          <span className="num">
            {fmtInt(runs.length)} of {fmtInt(totalRuns)} rows = {fmtInt(totalAlerts)} alerts with repeats folded · {describeFilter(filter)}
            {Object.keys(open).length > 0 && ` · expanded rows show at most ${CHILDREN} alerts; `}
            {Object.keys(open).length > 0 && (
              <button
                type="button"
                className="linklike"
                onClick={() => {
                  const id = Object.keys(open)[0]!;
                  const run = runs.find((x) => x.first_alert_id === id);
                  if (run) onFilter({ since: run.first_ts, until: untilAfter(run.last_ts) });
                }}
              >
                show all of the first expanded run as a filter
              </button>
            )}
          </span>
        }
      />
    </>
  );
}
