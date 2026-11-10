// Alerts: every stored alert of the data source in time order, loaded 500 at a time as the
// list is scrolled, or the full-text search hits. The selected alert's evidence is on the right.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { api, ApiError, type AlertRow, type SearchHit } from '../api.ts';
import { DataTable, type Column } from '../components/DataTable.tsx';
import { EvidencePane } from '../components/EvidencePane.tsx';
import { SplitPane } from '../components/SplitPane.tsx';
import { Button, DetectorTag, detectorName, EmptyState, ErrorNotice, ErrorState, Time } from '../components/ui.tsx';
import { useApp, useLoad, type Route } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { fmtInt } from '../lib/format.ts';
import { needlesFromQuery } from '../lib/highlight.ts';

const PAGE = 500;

/** FTS snippet: the index marks matches with [ and ]. Start near the first match and mark it. */
function Snippet({ text }: { text: string }) {
  const first = text.indexOf('[');
  const start = first > 24 ? first - 24 : 0;
  const parts = text.slice(start).split(/\[([^\]]*)\]/);
  return (
    <span className="mono">
      {start > 0 && <span className="faint">...</span>}
      {parts.map((p, i) => (i % 2 === 1 ? <mark key={i}>{p}</mark> : <span key={i}>{p}</span>))}
    </span>
  );
}
const DETECTORS = ['wazuh', 'suricata', 'aminer'];

interface Props {
  route: Route & { setParams: (patch: Record<string, string | null>, replace?: boolean) => void };
  searchRef: React.RefObject<HTMLInputElement | null>;
}

export function AlertsScreen({ route, searchRef }: Props) {
  const { scenario } = useApp();
  const [detector, setDetector] = useState<string | null>(null);
  const [host, setHost] = useState('');
  const [hostApplied, setHostApplied] = useState('');
  const [query, setQuery] = useState('');
  const [queryApplied, setQueryApplied] = useState('');

  const stats = useLoad((signal) => api.alertStats(scenario, signal), [scenario]);
  const total = useMemo(() => {
    const by = stats.data?.by_detector;
    if (!by || hostApplied) return null;
    return detector ? (by[detector] ?? 0) : Object.values(by).reduce((a, b) => a + b, 0);
  }, [stats.data, detector, hostApplied]);

  // ---- paged list -----------------------------------------------------------------------------
  const [rows, setRows] = useState<AlertRow[]>([]);
  const [done, setDone] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const generation = useRef(0);
  const busy = useRef(false);

  const loadPage = useCallback(
    async (offset: number, gen: number) => {
      if (busy.current) return;
      busy.current = true;
      setLoading(true);
      setError(null);
      try {
        const res = await api.alerts({ scenario, detector, host_ip: hostApplied || null, limit: PAGE, offset });
        if (gen !== generation.current) return;
        setRows((prev) => (offset === 0 ? res.alerts : [...prev, ...res.alerts]));
        setDone(res.alerts.length < PAGE);
      } catch (err) {
        if (gen === generation.current) setError(err instanceof ApiError ? err : new ApiError(0, '/alerts', String(err)));
      } finally {
        busy.current = false;
        if (gen === generation.current) setLoading(false);
      }
    },
    [scenario, detector, hostApplied],
  );

  useEffect(() => {
    generation.current += 1;
    busy.current = false;
    setRows([]);
    setDone(false);
    void loadPage(0, generation.current);
  }, [loadPage]);

  const onEndReached = useCallback(() => {
    if (!done && !busy.current && !error) void loadPage(rows.length, generation.current);
  }, [done, error, loadPage, rows.length]);

  // ---- search ---------------------------------------------------------------------------------
  const search = useLoad(
    (signal) => (queryApplied ? api.searchAlerts(queryApplied, scenario, signal) : Promise.resolve({ hits: [] as SearchHit[] })),
    [queryApplied, scenario],
  );
  const searching = queryApplied !== '';
  const needles = useMemo(() => needlesFromQuery(queryApplied), [queryApplied]);

  const selectedId = route.params.id ?? null;
  const select = (id: string) => route.setParams({ id });

  const columns = useMemo<Column<AlertRow>[]>(
    () => [
      { id: 'ts', header: 'Time (UTC)', width: '146px', render: (a) => <Time ts={a.ts} /> },
      { id: 'det', header: 'Detector', width: '74px', render: (a) => <DetectorTag value={a.detector} /> },
      {
        id: 'sev',
        header: 'Sev.',
        width: '32px',
        align: 'right',
        title: () => 'Severity as the detector reports it (Wazuh level 0-15, Suricata 1-3 with 1 most severe); not rescaled',
        render: (a) => (a.severity === null ? <span className="faint">-</span> : <span className="mono">{a.severity}</span>),
      },
      { id: 'rule', header: 'Rule id', width: '88px', render: (a) => <span className="mono">{a.rule_id ?? '-'}</span> },
      { id: 'name', header: 'Rule name', width: 'minmax(0, 1fr)', title: (a) => a.rule_name ?? '', render: (a) => a.rule_name ?? <span className="faint">-</span> },
      { id: 'host', header: 'Host', width: '100px', render: (a) => <span className="mono">{a.host_ip ?? '-'}</span> },
    ],
    [],
  );
  const hitColumns = useMemo<Column<SearchHit>[]>(
    () => [
      { id: 'ts', header: 'Time (UTC)', width: '146px', sortKey: (h) => h.ts, render: (h) => <Time ts={h.ts} /> },
      { id: 'det', header: 'Detector', width: '74px', sortKey: (h) => h.detector, render: (h) => <DetectorTag value={h.detector} /> },
      { id: 'name', header: 'Rule name', width: 'minmax(0, 1fr)', sortKey: (h) => h.rule_name, title: (h) => h.rule_name ?? '', render: (h) => h.rule_name ?? <span className="faint">-</span> },
      { id: 'snip', header: 'Match', width: 'minmax(0, 2fr)', title: (h) => h.snippet ?? '', render: (h) => <Snippet text={h.snippet ?? ''} /> },
    ],
    [],
  );

  const filterText = [detector ? `detector = ${detector}` : null, hostApplied ? `host = ${hostApplied}` : null].filter(Boolean).join(', ');

  const list = (
    <>
      <div className="pane-head">
        <h1>Alerts</h1>
        <span className="spacer" />
        <span className="muted num" style={{ fontSize: 'var(--fs-12)' }}>
          {scenario ?? 'all data sources'}
        </span>
      </div>
      <form
        className="filters"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          setHostApplied(host.trim());
          setQueryApplied(query.trim());
        }}
      >
        <div className="group" role="group" aria-label="Detector filter">
          <Button aria-pressed={detector === null} onClick={() => setDetector(null)} disabled={searching}>
            All
          </Button>
          {DETECTORS.map((d) => (
            <Button key={d} aria-pressed={detector === d} onClick={() => setDetector(detector === d ? null : d)} disabled={searching}>
              {detectorName(d)} <span className="num faint">{stats.data ? fmtInt(stats.data.by_detector[d] ?? 0) : ''}</span>
            </Button>
          ))}
        </div>
        <label className="visually-hidden" htmlFor="al-host">
          Host IP, exact
        </label>
        <input
          id="al-host"
          className="input mono"
          style={{ width: 128 }}
          placeholder="Host IP (exact)"
          value={host}
          onChange={(e) => setHost(e.target.value)}
          disabled={searching}
        />
        <div className="search">
          <Icon name="search" />
          <label className="visually-hidden" htmlFor="al-q">
            Search log lines and rule names
          </label>
          <input
            id="al-q"
            ref={searchRef}
            className="input"
            placeholder="Search log text, all words ( / )"
            value={query}
            maxLength={200}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                setQuery('');
                setQueryApplied('');
                e.currentTarget.blur();
              }
            }}
          />
        </div>
        <Button type="submit">Apply</Button>
        {(searching || hostApplied) && (
          <Button
            kind="ghost"
            icon="close"
            onClick={() => {
              setQuery('');
              setQueryApplied('');
              setHost('');
              setHostApplied('');
            }}
          >
            Clear
          </Button>
        )}
      </form>

      {searching ? (
        search.error && !search.data ? (
          <ErrorState what="search results" error={search.error} onRetry={search.reload} />
        ) : (
          <DataTable
            label={`Search hits for ${queryApplied}`}
            unit="hits"
            primary
            rows={search.data?.hits ?? []}
            columns={hitColumns}
            rowKey={(h) => h.alert_id}
            selectedKey={selectedId}
            onSelect={(h) => select(h.alert_id)}
            copyText={(h) => h.alert_id}
            loading={search.loading}
            footer={<span>Best matches first; at most 200 hits are returned</span>}
            empty={<EmptyState title={`No alert contains all of: ${needles.join(', ') || queryApplied}.`}>The search covers log lines and rule names of {scenario ?? 'all data sources'}.</EmptyState>}
          />
        )
      ) : (
        <>
          {error && rows.length > 0 && <ErrorNotice what="alerts" error={error} onRetry={() => void loadPage(rows.length, generation.current)} />}
          {error && rows.length === 0 ? (
            <ErrorState what="alerts" error={error} onRetry={() => void loadPage(0, generation.current)} />
          ) : (
            <DataTable
              label="Alerts in time order"
              unit="alerts loaded"
              primary
              rows={rows}
              columns={columns}
              rowKey={(a) => a.alert_id}
              selectedKey={selectedId}
              onSelect={(a) => select(a.alert_id)}
              copyText={(a) => a.alert_id}
              loading={loading}
              onEndReached={onEndReached}
              footer={
                <span className="num">
                  {total !== null ? `of ${fmtInt(total)}` : done ? 'all loaded' : 'more on scroll'} · oldest first{loading && rows.length > 0 ? ' · loading next 500' : ''}
                </span>
              }
              empty={
                filterText ? (
                  <EmptyState title={`No alerts match ${filterText}.`}>The host filter is an exact match on the alert's host IP.</EmptyState>
                ) : (
                  <EmptyState title={`No alerts stored for ${scenario ?? 'any data source'}.`}>
                    Replay a scenario into the stores: <span className="mono">app.main platform-ingest --scenario {scenario ?? '<name>'}</span>
                  </EmptyState>
                )
              }
            />
          )}
        </>
      )}
    </>
  );

  const detail = selectedId ? (
    <EvidencePane key={selectedId} alertId={selectedId} needles={needles} />
  ) : (
    <EmptyState title="No alert selected.">Select a row to read its fields and raw log lines.</EmptyState>
  );

  return <SplitPane id="alerts" left={list} right={detail} initial={60} />;
}
