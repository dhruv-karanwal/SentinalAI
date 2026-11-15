// Global search (alert id, IP, rule id, incident id, and full text from 3 characters), used by the
// command palette. Results come from GET /search; every result is a link into the screen that
// shows it. The palette owns the input; this module owns the request and the result rows.

import { useEffect, useMemo, useState } from 'react';

import { api, ApiError, type SearchResult } from '../api.ts';
import { buildHash } from '../hooks.ts';
import type { IconName } from '../icons.tsx';
import { fmtInt } from '../lib/format.ts';
import { detectorName } from './ui.tsx';

export interface SearchItem {
  key: string;
  href: string;
  kind: string;
  icon: IconName;
  main: string;
  sub: string;
}

export function searchItems(r: SearchResult): SearchItem[] {
  return [
    ...r.incidents.map((i) => ({ key: `i:${i.incident_id}`, href: buildHash('/incidents', { id: i.incident_id }), kind: 'Incident', icon: 'incidents' as const, main: i.incident_id, sub: `${i.severity}, ${i.status ?? 'open'}, ${fmtInt(i.alerts)} alerts` })),
    ...r.alerts.map((a) => ({ key: `a:${a.alert_id}`, href: buildHash('/alerts', { id: a.alert_id }), kind: 'Alert', icon: 'alerts' as const, main: a.alert_id, sub: `${detectorName(a.detector)} · ${a.rule_name ?? ''}` })),
    ...r.ips.map((ip) => ({ key: `ip:${ip.value}`, href: buildHash('/entity', { kind: 'ip', value: ip.value }), kind: 'IP', icon: 'entity' as const, main: ip.value, sub: `${fmtInt(ip.alerts)} alerts (host or source)` })),
    ...r.rules.map((x) => ({ key: `r:${x.value}`, href: buildHash('/alerts', { rule_id: x.value }), kind: 'Rule', icon: 'filter' as const, main: x.value, sub: `${x.label ?? ''} · ${fmtInt(x.alerts)} alerts` })),
    ...r.text.slice(0, 6).map((h) => ({ key: `t:${h.alert_id}`, href: buildHash('/alerts', { id: h.alert_id }), kind: 'Text', icon: 'search' as const, main: h.alert_id, sub: h.rule_name ?? '' })),
  ];
}

/** Debounced GET /search for `q` (200 ms); the previous request is aborted on every keystroke. */
export function useGlobalSearch(q: string, scenario: string | null): { needle: string; result: SearchResult | null; error: ApiError | null; items: SearchItem[] } {
  const [result, setResult] = useState<SearchResult | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const needle = q.trim();

  useEffect(() => {
    setResult(null);
    setError(null);
    if (!needle) return;
    const ctl = new AbortController();
    const t = window.setTimeout(() => {
      api.search(needle, scenario, ctl.signal).then(
        (r) => {
          setResult(r);
          setError(null);
        },
        (e: unknown) => {
          if (!ctl.signal.aborted) setError(e instanceof ApiError ? e : new ApiError(0, '/search', String(e)));
        },
      );
    }, 200);
    return () => {
      window.clearTimeout(t);
      ctl.abort();
    };
  }, [needle, scenario]);

  const items = useMemo(() => (result ? searchItems(result) : []), [result]);
  return { needle, result, error, items };
}
