// Global search in the top bar: alert id, IP, rule id, incident id (and full text from 3 characters).
// Results come from GET /search; every result is a link into the screen that shows it.

import { useEffect, useMemo, useRef, useState, type RefObject } from 'react';

import { api, ApiError, type SearchResult } from '../api.ts';
import { buildHash } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { fmtInt } from '../lib/format.ts';
import { describeError, detectorName } from './ui.tsx';

interface Item {
  key: string;
  href: string;
  kind: string;
  main: string;
  sub: string;
}

function items(r: SearchResult): Item[] {
  return [
    ...r.incidents.map((i) => ({ key: `i:${i.incident_id}`, href: buildHash('/incidents', { id: i.incident_id }), kind: 'Incident', main: i.incident_id, sub: `${i.severity}, ${i.status ?? 'open'}, ${fmtInt(i.alerts)} alerts` })),
    ...r.alerts.map((a) => ({ key: `a:${a.alert_id}`, href: buildHash('/alerts', { id: a.alert_id }), kind: 'Alert', main: a.alert_id, sub: `${detectorName(a.detector)} · ${a.rule_name ?? ''}` })),
    ...r.ips.map((ip) => ({ key: `ip:${ip.value}`, href: buildHash('/entity', { kind: 'ip', value: ip.value }), kind: 'IP', main: ip.value, sub: `${fmtInt(ip.alerts)} alerts (host or source)` })),
    ...r.rules.map((x) => ({ key: `r:${x.value}`, href: buildHash('/alerts', { rule_id: x.value }), kind: 'Rule', main: x.value, sub: `${x.label ?? ''} · ${fmtInt(x.alerts)} alerts` })),
    ...r.text.slice(0, 6).map((h) => ({ key: `t:${h.alert_id}`, href: buildHash('/alerts', { id: h.alert_id }), kind: 'Text', main: h.alert_id, sub: h.rule_name ?? '' })),
  ];
}

export function GlobalSearch({ inputRef, scenario }: { inputRef: RefObject<HTMLInputElement | null>; scenario: string | null }) {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<SearchResult | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const needle = q.trim();
    if (!needle) {
      setResult(null);
      setError(null);
      return;
    }
    const ctl = new AbortController();
    const t = window.setTimeout(() => {
      api.search(needle, scenario, ctl.signal).then(
        (r) => {
          setResult(r);
          setError(null);
          setActive(0);
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
  }, [q, scenario]);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, []);

  const list = useMemo(() => (result ? items(result) : []), [result]);
  const go = (it: Item) => {
    window.location.hash = it.href;
    setOpen(false);
    inputRef.current?.blur();
  };

  return (
    <div className="gsearch" ref={box} role="search">
      <Icon name="search" />
      <label htmlFor="gsearch" className="visually-hidden">
        Search alert id, IP, rule id or incident id
      </label>
      <input
        id="gsearch"
        ref={inputRef}
        className="input mono"
        placeholder="Search id, IP, rule (Ctrl+K)"
        value={q}
        autoComplete="off"
        role="combobox"
        aria-expanded={open && q.trim() !== ''}
        aria-controls="gsearch-list"
        aria-activedescendant={open && list[active] ? `gs-${active}` : undefined}
        onFocus={() => setOpen(true)}
        onChange={(e) => {
          setQ(e.target.value);
          setOpen(true);
        }}
        onKeyDown={(e) => {
          if (e.key === 'Escape') {
            setOpen(false);
            e.currentTarget.blur();
          } else if (e.key === 'ArrowDown') {
            setActive((a) => Math.min(list.length - 1, a + 1));
            e.preventDefault();
          } else if (e.key === 'ArrowUp') {
            setActive((a) => Math.max(0, a - 1));
            e.preventDefault();
          } else if (e.key === 'Enter' && list[active]) {
            go(list[active]!);
            e.preventDefault();
          }
        }}
      />
      {open && q.trim() !== '' && (
        <div className="popover" id="gsearch-list">
          {error && (
            <div className="empty field-error" role="alert">
              {describeError(error)}
            </div>
          )}
          {!error && !result && <div className="empty">Searching...</div>}
          {!error && result && list.length === 0 && <div className="empty">Nothing matches "{q.trim()}" in {scenario ?? 'the stores'}. Ids match exactly or by prefix; text search needs 3 characters.</div>}
          {list.length > 0 && (
            <ul role="listbox" aria-label="Search results">
              {list.map((it, i) => (
                <li key={it.key}>
                  <a id={`gs-${i}`} role="option" aria-selected={i === active} href={it.href} onClick={() => setOpen(false)} onMouseEnter={() => setActive(i)}>
                    <span className="tag">{it.kind}</span>
                    <span className="mono" style={{ overflowWrap: 'anywhere' }}>
                      {it.main}
                    </span>
                    <span className="faint" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {it.sub}
                    </span>
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
