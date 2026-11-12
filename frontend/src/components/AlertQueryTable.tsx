// The alert table under the charts: GET /alerts/query with the chart's filter, 200 rows a page,
// loaded on scroll. The total comes from the API, so the footer is exact for any filter.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { api, ApiError, type AlertFilter, type QueryRow } from '../api.ts';
import { useLoad } from '../hooks.ts';
import { fmtInt } from '../lib/format.ts';
import { DataTable, type Column } from './DataTable.tsx';
import { DetectorTag, ErrorNotice, ErrorState, Time, describeError } from './ui.tsx';

const PAGE = 200;

export function filterKey(f: AlertFilter): string {
  return JSON.stringify(Object.entries(f).filter(([, v]) => v !== null && v !== undefined && v !== '').sort());
}

export function describeFilter(f: AlertFilter): string {
  const parts = Object.entries(f)
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => `${k === 'ip' ? 'IP' : k.replace('_', ' ')} = ${String(v)}`);
  return parts.length ? parts.join(', ') : 'no filter';
}

interface Props {
  scenario: string;
  filter: AlertFilter;
  label: string;
  selectedId?: string | null;
  onSelect?: (row: QueryRow) => void;
  onOpen?: (row: QueryRow) => void;
  primary?: boolean;
  onTotal?: (n: number) => void;
  /** narrow pane: drop source IP and ATT&CK columns, keep the rule */
  compact?: boolean;
}

export function AlertQueryTable({ scenario, filter, label, selectedId = null, onSelect, onOpen, primary = false, onTotal, compact = false }: Props) {
  const key = filterKey(filter);
  const first = useLoad((signal) => api.queryAlerts(scenario, filter, PAGE, 0, signal), [scenario, key]);
  const [more, setMore] = useState<QueryRow[]>([]);
  const [moreError, setMoreError] = useState<ApiError | null>(null);
  const loadingMore = useRef(false);
  useEffect(() => setMore([]), [scenario, key]);
  useEffect(() => {
    if (first.data) onTotal?.(first.data.total);
  }, [first.data, onTotal]);
  const rows = useMemo(() => [...(first.data?.alerts ?? []), ...more], [first.data, more]);
  const total = first.data?.total ?? 0;
  const loadMore = useCallback(() => {
    if (loadingMore.current || rows.length >= total || !first.data) return;
    loadingMore.current = true;
    api.queryAlerts(scenario, filter, PAGE, rows.length).then(
      (r) => {
        setMore((m) => [...m, ...r.alerts]);
        loadingMore.current = false;
      },
      (e: unknown) => {
        setMoreError(e instanceof ApiError ? e : new ApiError(0, '/alerts/query', String(e)));
        loadingMore.current = false;
      },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows.length, total, first.data, scenario, key]);

  const columns = useMemo<Column<QueryRow>[]>(() => {
    const cols: Column<QueryRow>[] = [
      { id: 'ts', header: 'Time (UTC, data date)', width: '146px', render: (a) => <Time ts={a.ts} /> },
      { id: 'det', header: 'Detector', width: '78px', render: (a) => <DetectorTag value={a.detector} /> },
      { id: 'sev', header: 'Own severity', width: '52px', align: 'right', render: (a) => (a.severity ?? <span className="faint">-</span>) },
      { id: 'rule', header: 'Rule', width: 'minmax(0, 1fr)', title: (a) => `${a.rule_id ?? ''} ${a.rule_name ?? ''}`, render: (a) => (
        <span>
          <span className="mono faint">{a.rule_id ?? '-'}</span> {a.rule_name}
        </span>
      ) },
      { id: 'host', header: 'Host', width: '112px', render: (a) => <span className="mono">{a.host_ip ?? '-'}</span> },
      { id: 'src', header: 'Source IP', width: '112px', render: (a) => <span className="mono">{a.src_ip ?? '-'}</span> },
      { id: 'tech', header: 'ATT&CK', width: '84px', title: (a) => a.techniques.join(', ') || 'no ATT&CK technique', render: (a) => <span className="mono" title={a.techniques.join(', ')}>{a.techniques.join(', ') || '-'}</span> },
    ];
    return compact ? cols.filter((c) => c.id !== 'src' && c.id !== 'tech') : cols;
  }, [compact]);

  if (first.error && !first.data) return <ErrorState what="alerts" error={first.error} onRetry={first.reload} />;
  return (
    <>
      {first.error && first.data && <ErrorNotice what="alerts" error={first.error} onRetry={first.reload} />}
      {moreError && <div className="notice" data-kind="error" role="alert">More rows could not be loaded: {describeError(moreError)}</div>}
      <DataTable
        label={label}
        unit="alerts loaded"
        rows={rows}
        columns={columns}
        rowKey={(a) => a.alert_id}
        selectedKey={selectedId}
        onSelect={onSelect}
        onOpen={onOpen}
        copyText={(a) => a.alert_id}
        primary={primary}
        loading={first.loading && !first.data}
        onEndReached={loadMore}
        empty={`No alerts match ${describeFilter(filter)} in ${scenario}.`}
        footer={
          <span className="num">
            {fmtInt(rows.length)} of {fmtInt(total)} alerts · {describeFilter(filter)}
          </span>
        }
      />
    </>
  );
}
