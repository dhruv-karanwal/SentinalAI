// Alerts: facet sidebar (detector, level, rule id, ATT&CK technique, host; counts and inline bars),
// the filtered table (GET /alerts/query, exact total), saved filters (this browser only), CSV
// export of the filtered view, full-text search, and the evidence of the selected alert.
// Filters live in the URL so charts elsewhere can link to a filtered view.

import { useMemo, useState } from 'react';

import { api, ApiError, downloadAlertsCsv, type AlertFilter, type FacetName, type SearchHit } from '../api.ts';
import { MiniBar } from '../charts/Bars.tsx';
import { TimeBars } from '../charts/TimeBars.tsx';
import { ChartFrame, DETECTOR_ORDER, detectorTone, type Tone } from '../charts/ChartFrame.tsx';
import { AlertQueryTable, describeFilter, filterKey } from '../components/AlertQueryTable.tsx';
import { AlertRunsTable } from '../components/AlertRunsTable.tsx';
import { Term } from '../components/Term.tsx';
import { DataTable, type Column } from '../components/DataTable.tsx';
import { EvidencePane } from '../components/EvidencePane.tsx';
import { SplitPane } from '../components/SplitPane.tsx';
import { Button, DetectorTag, Dialog, EmptyState, ErrorState, Time, describeError, detectorName } from '../components/ui.tsx';
import { storageGet, storageSet, useApp, useLoad, useScreenContext, type RouteApi } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { epochSeconds, fmtInt } from '../lib/format.ts';
import { needlesFromQuery } from '../lib/highlight.ts';

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

  const sidebar = (
    <aside className="facets" aria-label="Facets">
      {facets.error && !facets.data && <ErrorState what="facets" error={facets.error} onRetry={facets.reload} />}
      {!facets.data && !facets.error && <div className="facet faint">Counting...</div>}
      {facets.data &&
        FACETS.map(([name, label, term]) => {
          const f = facets.data!.facets[name];
          const max = Math.max(1, ...f.values.map((v) => v.count));
          return (
            <section key={name} className="facet" aria-labelledby={`fc-${name}`}>
              <h3 id={`fc-${name}`}>
                <span>
                  <Term id={term}>{label}</Term>
                </span>
                <span className="faint num">{fmtInt(f.distinct)}</span>
              </h3>
              <ul>
                {f.values.map((v) => {
                  const tone: Tone = name === 'detector' ? detectorTone(v.value) : 'ref';
                  const pressed = filter[name] === v.value;
                  const text = name === 'detector' ? detectorName(v.value) : v.value;
                  return (
                    <li key={v.value}>
                      <button
                        type="button"
                        aria-pressed={pressed}
                        onClick={() => toggle(name, v.value)}
                        title={`${text}${v.label ? ` ${v.label}` : ''}: ${fmtInt(v.count)} alerts${pressed ? ' (click to remove)' : ''}`}
                      >
                        <span className="fv">
                          <span className={name === 'detector' ? '' : 'mono'}>{text}</span>
                          {v.label && <span className="faint"> {v.label}</span>}
                        </span>
                        <MiniBar value={v.count} max={max} tone={tone} />
                        <span className="fc">{fmtInt(v.count)}</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
              {f.distinct > f.shown && <div className="faint" style={{ fontSize: 'var(--fs-11)', padding: '2px 4px' }}>top {f.shown} of {fmtInt(f.distinct)}</div>}
            </section>
          );
        })}
      <section className="facet" aria-labelledby="fc-saved">
        <h3 id="fc-saved">
          <span>Saved filters</span>
          <span className="faint">this browser</span>
        </h3>
        {saved.length === 0 && <div className="faint">None yet. Set a filter, then Save.</div>}
        <ul>
          {saved.map((s) => (
            <li key={s.name} style={{ display: 'flex' }}>
              <button type="button" onClick={() => route.setParams({ ...Object.fromEntries(KEYS.map((k) => [k, null])), ...s.params })} title={JSON.stringify(s.params)}>
                <span className="fv">{s.name}</span>
              </button>
              <button type="button" aria-label={`Delete saved filter ${s.name}`} style={{ width: 24, gridTemplateColumns: '1fr' }} onClick={() => removeSaved(s.name)}>
                <Icon name="close" />
              </button>
            </li>
          ))}
        </ul>
      </section>
    </aside>
  );

  const ts = facets.data?.timeseries;
  const list = (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <div className="pane-head">
        <h1>Alerts</h1>
        <span className="muted num">{facets.data ? `${fmtInt(facets.data.total)} match` : ''}</span>
        <span className="spacer" />
        <Button aria-pressed={fold} onClick={() => set({ fold: fold ? '0' : null })} title="Fold consecutive alerts with the same rule, level, host and source IP into one row">
          Fold repeats
        </Button>
        {active.length > 0 && <Button onClick={save}>Save filter</Button>}
        <Button icon="download" onClick={() => void exportCsv()} disabled={exporting || !facets.data || facets.data.total === 0} title="CSV of the filtered view (no raw records)">
          {exporting ? 'Exporting...' : 'Export CSV'}
        </Button>
      </div>
      <form
        className="filters"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          set({ q: query.trim() || null, id: null });
        }}
      >
        <div className="search">
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
        {active.map((k) => (
          <button key={k} type="button" className="chip" onClick={() => set({ [k]: null })} aria-label={`Remove filter ${k} = ${filter[k]}`}>
            {k.replace('_', ' ')} = <span className="mono">{k === 'detector' ? detectorName(String(filter[k])) : String(filter[k])}</span>
            <Icon name="close" />
          </button>
        ))}
        {active.length > 1 && (
          <Button kind="ghost" onClick={() => route.setParams(Object.fromEntries(KEYS.map((k) => [k, null])))}>
            Clear all
          </Button>
        )}
      </form>
      {!queryApplied && ts && ts.total > 0 && (
        <div style={{ padding: '0 var(--sp-12)' }}>
          <ChartFrame
            className="compact-chart"
            title="Matching alerts over time"
            question="Drag to narrow the time range."
            legend={DETECTOR_ORDER.filter((d) => ts.series[d]).map((d) => ({ key: d, label: detectorName(d), tone: detectorTone(d) }))}
            table={{ columns: ['bin', ...Object.keys(ts.series)], rows: Array.from({ length: ts.bins }, (_, i) => [i, ...Object.values(ts.series).map((v) => v[i] ?? 0)]) }}
          >
            <TimeBars
              series={ts.series}
              start={ts.start ? epochSeconds(ts.start) : 0}
              binSeconds={ts.bin_seconds ?? 1}
              height={96}
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
      <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        {queryApplied ? (
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
              onSelect={(h) => set({ id: h.alert_id })}
              copyText={(h) => h.alert_id}
              loading={search.loading}
              footer={<span>Best matches first; at most 200 hits. Facet filters do not apply to text search.</span>}
              empty={<EmptyState title={`No alert contains all of: ${needles.join(', ') || queryApplied}.`}>The search covers log lines and rule names of {scenario}.</EmptyState>}
            />
          )
        ) : (
          fold ? (
            <AlertRunsTable scenario={scenario} filter={filter} primary label="Alerts in time order, repeats folded" selectedId={selectedId} onSelect={(id) => set({ id })} onFilter={(p) => set({ ...p, fold: '0' })} />
          ) : (
            <AlertQueryTable scenario={scenario} filter={filter} primary compact label="Alerts in time order" selectedId={selectedId} onSelect={(a) => set({ id: a.alert_id })} />
          )
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
    <div className="alerts-layout">
      {sidebar}
      <SplitPane id="alerts" left={list} right={detail} initial={62} />
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
