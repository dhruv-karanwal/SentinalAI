// Alerts: facet sidebar (detector, level, rule id, ATT&CK technique, host; counts and thin bars),
// the filtered table (GET /alerts/query, exact total), saved filters (this browser only), CSV
// export of the filtered view, full-text search, and the evidence of the selected alert.
// Filters live in the URL so charts elsewhere can link to a filtered view.

import { useMemo, useState } from 'react';

import { api, ApiError, downloadAlertsCsv, type AlertFilter, type FacetName, type SearchHit } from '../api.ts';
import { TimeBars } from '../charts/TimeBars.tsx';
import { ChartFrame, DETECTOR_ORDER, detectorTone } from '../charts/ChartFrame.tsx';
import { AlertQueryTable, describeFilter, filterKey } from '../components/AlertQueryTable.tsx';
import { AlertRunsTable } from '../components/AlertRunsTable.tsx';
import { Term } from '../components/Term.tsx';
import { DataTable, type Column } from '../components/DataTable.tsx';
import { EvidencePane } from '../components/EvidencePane.tsx';
import { SplitPane } from '../components/SplitPane.tsx';
import { Button, DetectorTag, Dialog, EmptyState, ErrorState, PageHeader, Time, describeError, detectorName } from '../components/ui.tsx';
import { storageGet, storageSet, useApp, useLoad, useScreenContext, type RouteApi } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { epochSeconds, fmtInt } from '../lib/format.ts';
import { needlesFromQuery } from '../lib/highlight.ts';
import { fitColumns, useNarrow } from '../components/narrow.ts';

const KEYS: Array<keyof AlertFilter> = ['detector', 'level', 'rule_id', 'technique', 'host', 'ip', 'since', 'until'];
const FACETS: Array<[FacetName, string, string]> = [
  ['detector', 'Detector', 'detector'],
  ['level', "Detector's own severity", 'severity'],
  ['rule_id', 'Rule id', 'alert'],
  ['technique', 'ATT&CK technique', 'attack-technique'],
  ['host', 'Host', 'entity'],
];

interface Saved {
  name: string;
  params: Record<string, string>;
}

function loadSaved(): Saved[] {
  try {
    const v = JSON.parse(storageGet('sentinel.savedFilters') ?? '[]') as unknown;
    return Array.isArray(v) ? (v as Saved[]).filter((s) => s && typeof s.name === 'string') : [];
  } catch {
    return [];
  }
}

export function AlertsScreen({ scenario, route, searchRef }: { scenario: string; route: RouteApi; searchRef: React.RefObject<HTMLInputElement | null> }) {
  const { toast, session } = useApp();
  const filter = useMemo<AlertFilter>(() => Object.fromEntries(KEYS.map((k) => [k, route.params[k] ?? null])), [route.params]);
  const fkey = filterKey(filter);
  const facets = useLoad((signal) => api.facets(scenario, filter, signal), [scenario, fkey]);
  const [query, setQuery] = useState(route.params.q ?? '');
  const queryApplied = route.params.q ?? '';
  const search = useLoad((signal) => (queryApplied ? api.searchAlerts(queryApplied, scenario, signal) : Promise.resolve(null)), [queryApplied, scenario]);
  const [saved, setSaved] = useState<Saved[]>(loadSaved);
  const [exporting, setExporting] = useState(false);
  const selectedId = route.params.id ?? null;
  const needles = useMemo(() => needlesFromQuery(queryApplied), [queryApplied]);
  const active = KEYS.filter((k) => filter[k]);
  const fold = route.params.fold !== '0';
  useScreenContext(
    'alerts',
    `Alerts of ${scenario}, ${describeFilter(filter)}${facets.data ? `: ${facets.data.total} match. By detector: ${facets.data.facets.detector.values.map((v) => `${v.value} ${v.count}`).join(', ')}. Top rules: ${facets.data.facets.rule_id.values.slice(0, 5).map((v) => `${v.value}${v.label ? ` (${v.label})` : ''} ${v.count}`).join(', ')}` : ''}. Repeated identical rows are ${fold ? 'folded into one row with a count' : 'shown one by one'}. "Own severity" is the detector's own level, not rescaled.${selectedId ? ` Selected alert ${selectedId}.` : ''}`,
  );

  const set = (patch: Partial<Record<keyof AlertFilter | 'q' | 'id' | 'fold', string | null>>) => route.setParams(patch as Record<string, string | null>);
  const toggle = (facet: FacetName, value: string) => set({ [facet]: filter[facet] === value ? null : value });
  const clearAll = () => route.setParams(Object.fromEntries(KEYS.map((k) => [k, null])));

  const [naming, setNaming] = useState<string | null>(null);
  const save = () => setNaming(describeFilter(filter));
  const commitSave = (raw: string) => {
    const name = raw.trim();
    setNaming(null);
    if (!name) return;
    const params = Object.fromEntries(KEYS.filter((k) => filter[k]).map((k) => [k, String(filter[k])]));
    const next = [...saved.filter((s) => s.name !== name), { name, params }];
    setSaved(next);
    storageSet('sentinel.savedFilters', JSON.stringify(next));
  };
  const removeSaved = (name: string) => {
    const next = saved.filter((s) => s.name !== name);
    setSaved(next);
    storageSet('sentinel.savedFilters', JSON.stringify(next));
  };
  const exportCsv = async () => {
    setExporting(true);
    try {
      const r = await downloadAlertsCsv(scenario, filter);
      toast(r.rows < r.total ? `Exported ${fmtInt(r.rows)} of ${fmtInt(r.total)} alerts (export limit).` : `Exported ${fmtInt(r.rows)} alerts as CSV.`);
    } catch (err) {
      toast(err instanceof ApiError ? describeError(err) : String(err), 'error');
    } finally {
      setExporting(false);
    }
  };

  const hitColumns = useMemo<Column<SearchHit>[]>(
    () => [
      { id: 'ts', header: 'Time (UTC)', width: '146px', render: (h) => <Time ts={h.ts} /> },
      { id: 'det', header: 'Detector', width: '78px', render: (h) => <DetectorTag value={h.detector} /> },
      { id: 'rule', header: 'Rule', width: 'minmax(0, 1fr)', title: (h) => h.rule_name ?? '', render: (h) => h.rule_name ?? '-' },
      { id: 'id', header: 'Alert id', width: '150px', render: (h) => <span className="mono">{h.alert_id}</span> },
    ],
    [],
  );

  const narrow = useNarrow();
  const hitCols = useMemo(() => fitColumns(hitColumns, narrow, ['id']), [hitColumns, narrow]);

  const sidebar = (
    <aside className="facets" aria-label="Facets">
      {facets.error && !facets.data && <ErrorState what="facets" error={facets.error} onRetry={facets.reload} />}
      {!facets.data && !facets.error && (
        <div className="fc-group" aria-busy="true" aria-label="Counting facets">
          {[70, 50, 85, 40, 60].map((w, i) => (
            <div key={i} className="fc-v" aria-hidden="true">
              <span />
              <span className="fc-label">
                <span className="skeleton-bar" style={{ display: 'block', width: `${w}%` }} />
              </span>
            </div>
          ))}
        </div>
      )}
      {facets.data &&
        FACETS.map(([name, label, term]) => {
          const f = facets.data!.facets[name];
          const max = Math.max(1, ...f.values.map((v) => v.count));
          return (
            <section key={name} className="fc-group" aria-labelledby={`fc-${name}`}>
              <h3 id={`fc-${name}`} className="fc-head">
                <span>
                  <Term id={term}>{label}</Term>
                </span>
                <span className="faint num">{fmtInt(f.distinct)}</span>
              </h3>
              {f.values.length === 0 && <div className="fc-empty">No value in the filtered alerts.</div>}
              <ul>
                {f.values.map((v) => {
                  const pressed = filter[name] === v.value;
                  const text = name === 'detector' ? detectorName(v.value) : v.value;
                  return (
                    <li key={v.value}>
                      <button
                        type="button"
                        className="fc-v"
                        aria-pressed={pressed}
                        onClick={() => toggle(name, v.value)}
                        title={`${text}${v.label ? ` ${v.label}` : ''}: ${fmtInt(v.count)} alerts${pressed ? ' (click to remove)' : ''}`}
                      >
                        {pressed ? <Icon name="check" /> : <span aria-hidden="true" />}
                        <span className="fc-label">
                          {name === 'detector' ? <DetectorTag value={v.value} /> : <span className="mono">{text}</span>}
                          {v.label && <span className="faint"> {v.label}</span>}
                        </span>
                        <span className="fc-count num">{fmtInt(v.count)}</span>
                        <span className="fc-bar" aria-hidden="true">
                          <span style={{ width: `${Math.max(2, (v.count / max) * 100)}%` }} />
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
              {f.distinct > f.shown && (
                <div className="fc-more num">
                  top {f.shown} of {fmtInt(f.distinct)}
                </div>
              )}
            </section>
          );
        })}
      <section className="fc-group" aria-labelledby="fc-saved">
        <h3 id="fc-saved" className="fc-head">
          <span>Saved filters</span>
          <span className="faint">this browser</span>
        </h3>
        {saved.length === 0 && <div className="fc-empty">None yet. Set a filter, then Save filter.</div>}
        <ul>
          {saved.map((s) => (
            <li key={s.name} className="fc-saved">
              <button type="button" className="fc-v" onClick={() => route.setParams({ ...Object.fromEntries(KEYS.map((k) => [k, null])), ...s.params })} title={JSON.stringify(s.params)}>
                <span className="fc-label">{s.name}</span>
              </button>
              <Button kind="ghost" icon="close" aria-label={`Delete saved filter ${s.name}`} title="Delete this saved filter" onClick={() => removeSaved(s.name)} />
            </li>
          ))}
        </ul>
      </section>
    </aside>
  );

  const ts = facets.data?.timeseries;
  const list = (
    <div className="al-list">
      <form
        className="toolbar"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          set({ q: query.trim() || null, id: null });
        }}
      >
        <div className="searchbox">
          <Icon name="search" />
          <label className="visually-hidden" htmlFor="al-q">
            Search log text
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
                set({ q: null });
                e.currentTarget.blur();
              }
            }}
          />
        </div>
        <Button type="submit">Search</Button>
        <Button aria-pressed={fold} onClick={() => set({ fold: fold ? '0' : null })} title="Fold consecutive alerts with the same rule, level, host and source IP into one row">
          Fold repeats
        </Button>
        {active.length > 0 && <Button onClick={save}>Save filter</Button>}
        <Button icon="download" onClick={() => void exportCsv()} disabled={exporting || !facets.data || facets.data.total === 0} title="CSV of the filtered view (no raw records)">
          {exporting ? 'Exporting...' : 'Export CSV'}
        </Button>
        {active.map((k) => (
          <button key={k} type="button" className="filter-tag" onClick={() => set({ [k]: null })} aria-label={`Remove filter ${k} = ${filter[k]}`}>
            <span className="k">{k === 'ip' ? 'IP' : k.replace('_', ' ')}</span>
            <span className="mono">{k === 'detector' ? detectorName(String(filter[k])) : String(filter[k])}</span>
            <Icon name="close" />
          </button>
        ))}
        {active.length > 1 && (
          <Button kind="ghost" onClick={clearAll}>
            Clear all
          </Button>
        )}
      </form>
      {!queryApplied && ts && ts.total > 0 && (
        <div className="al-chart">
          <ChartFrame
            className="flat-chart compact-chart"
            title="Matching alerts over time"
            question="Drag to narrow the time range."
            legend={DETECTOR_ORDER.filter((d) => ts.series[d]).map((d) => ({ key: d, label: detectorName(d), tone: detectorTone(d) }))}
            table={{ columns: ['bin', ...Object.keys(ts.series)], rows: Array.from({ length: ts.bins }, (_, i) => [i, ...Object.values(ts.series).map((v) => v[i] ?? 0)]) }}
          >
            <TimeBars
              series={ts.series}
              start={ts.start ? epochSeconds(ts.start) : 0}
              binSeconds={ts.bin_seconds ?? 1}
              height={80}
              label="Matching alerts over time"
              onSelect={(b) => {
                const s0 = ts.start ? epochSeconds(ts.start) : 0;
                const st = ts.bin_seconds ?? 1;
                set(b ? { since: new Date((s0 + b[0] * st) * 1000).toISOString(), until: new Date((s0 + (b[1] + 1) * st) * 1000).toISOString() } : { since: null, until: null });
              }}
            />
          </ChartFrame>
        </div>
      )}
      <div className="al-table">
        {queryApplied ? (
          search.error && !search.data ? (
            <ErrorState what="search results" error={search.error} onRetry={search.reload} />
          ) : (
            <DataTable
              label={`Search hits for ${queryApplied}`}
              unit="hits"
              primary
              rows={search.data?.hits ?? []}
              columns={hitCols}
              rowKey={(h) => h.alert_id}
              selectedKey={selectedId}
              onSelect={(h) => set({ id: h.alert_id })}
              copyText={(h) => h.alert_id}
              loading={search.loading}
              footer={<span>Best matches first; at most 200 hits. Facet filters do not apply to text search.</span>}
              empty={
                <EmptyState title={`No alert contains all of: ${needles.join(', ') || queryApplied}.`}>
                  The search covers log lines and rule names of {scenario}.{' '}
                  <button type="button" className="linklike" onClick={() => (setQuery(''), set({ q: null }))}>
                    Clear the search
                  </button>
                </EmptyState>
              }
            />
          )
        ) : fold ? (
          <AlertRunsTable scenario={scenario} filter={filter} primary onClear={active.length > 0 ? clearAll : undefined} label="Alerts in time order, repeats folded" selectedId={selectedId} onSelect={(id) => set({ id })} onFilter={(p) => set({ ...p, fold: '0' })} />
        ) : (
          <AlertQueryTable scenario={scenario} filter={filter} primary compact onClear={active.length > 0 ? clearAll : undefined} label="Alerts in time order" selectedId={selectedId} onSelect={(a) => set({ id: a.alert_id })} />
        )}
      </div>
    </div>
  );

  const detail = selectedId ? (
    <EvidencePane key={selectedId} alertId={selectedId} needles={needles} />
  ) : (
    <EmptyState title="No alert selected.">
      Select a row to read its fields and raw log lines.{session.role === 'executive' ? ' Your role cannot read raw records.' : ''}
    </EmptyState>
  );

  return (
    <div className="work">
      <PageHeader bar title="Alerts" purpose="Which alerts match?" actions={facets.data ? <span className="tb-meta num">{fmtInt(facets.data.total)} match</span> : undefined} />
      <div className="al-layout">
        {sidebar}
        <SplitPane id="alerts" left={list} right={detail} initial={64} />
      </div>
      {naming !== null && (
        <Dialog
          title="Save filter"
          onClose={() => setNaming(null)}
          footer={
            <>
              <Button onClick={() => setNaming(null)}>Cancel</Button>
              <Button kind="primary" onClick={() => commitSave(naming)} disabled={!naming.trim()}>
                Save
              </Button>
            </>
          }
        >
          <form
            className="field"
            onSubmit={(e) => {
              e.preventDefault();
              commitSave(naming);
            }}
          >
            <label htmlFor="sf-name">Name (kept in this browser only)</label>
            <input id="sf-name" className="input" autoFocus value={naming} maxLength={80} onChange={(e) => setNaming(e.target.value)} />
            <span className="faint">{describeFilter(filter)}</span>
          </form>
        </Dialog>
      )}
    </div>
  );
}
