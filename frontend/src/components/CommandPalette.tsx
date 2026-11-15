// Command palette (DESIGN.md 5): Ctrl+K or `s`. One input over three groups: screens the role can
// open, global search results (GET /search: alert id, IP, rule id, incident id, text) and actions.
// WAI-ARIA combobox + listbox; a modal <dialog> traps focus and Esc closes; focus returns to the
// element that opened it. Filtering / ranking is pure (lib/nav.ts).

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';

import { Icon, type IconName } from '../icons.tsx';
import { filterRank, type NavItem } from '../lib/nav.ts';
import { useGlobalSearch } from './GlobalSearch.tsx';
import { describeError } from './ui.tsx';

export interface PaletteAction {
  id: string;
  label: string;
  icon: IconName;
  keywords?: string;
  /** shortcut shown at the right */
  hint?: string;
  run: () => void;
}

interface Option {
  id: string;
  icon: IconName;
  label: string;
  sub?: string;
  tag?: string;
  hint?: string;
  mono?: boolean;
  href?: string;
  run?: () => void;
}

interface Group {
  label: string;
  options: Option[];
  status?: ReactNode;
}

export function CommandPalette({ screens, actions, scenario, currentPath, onClose }: { screens: readonly NavItem[]; actions: readonly PaletteAction[]; scenario: string | null; currentPath: string; onClose: () => void }) {
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const dialog = useRef<HTMLDialogElement | null>(null);
  const input = useRef<HTMLInputElement | null>(null);
  const opener = useRef<Element | null>(document.activeElement);
  const search = useGlobalSearch(q, scenario);

  useEffect(() => {
    const el = dialog.current;
    if (el && !el.open) el.showModal();
    input.current?.focus();
  }, []);

  const groups = useMemo<Group[]>(() => {
    const out: Group[] = [];
    const nav = filterRank(screens, q);
    out.push({
      label: 'Go to',
      options: nav.map((n) => ({ id: `nav:${n.path}`, icon: n.icon, label: n.label, sub: n.path === currentPath ? 'current screen' : undefined, hint: n.key ? `g ${n.key}` : undefined, href: `#${n.path}` })),
    });
    if (search.needle) {
      const status = search.error ? (
        <span className="field-error" role="alert">
          {describeError(search.error)}
        </span>
      ) : !search.result ? (
        'Searching...'
      ) : search.items.length === 0 ? (
        `Nothing matches "${search.needle}" in ${scenario ?? 'the stores'}. Ids match exactly or by prefix; text search needs 3 characters.`
      ) : undefined;
      out.push({
        label: `Search ${scenario ?? 'the stores'}`,
        status,
        options: search.items.map((it) => ({ id: `s:${it.key}`, icon: it.icon, label: it.main, sub: it.sub, tag: it.kind, mono: true, href: it.href })),
      });
    }
    out.push({ label: 'Actions', options: filterRank(actions, q).map((a) => ({ id: `act:${a.id}`, icon: a.icon, label: a.label, hint: a.hint, run: a.run })) });
    return out.filter((g) => g.options.length > 0 || g.status);
  }, [screens, actions, q, search.needle, search.result, search.error, search.items, scenario, currentPath]);

  const flat = useMemo(() => groups.flatMap((g) => g.options), [groups]);
  useEffect(() => setActive(0), [q, search.result]);
  const cur = flat[Math.min(active, flat.length - 1)];
  const optId = (o: Option) => `cmdk-${o.id.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
  const curId = cur ? optId(cur) : null;
  useEffect(() => {
    if (curId) document.getElementById(curId)?.scrollIntoView({ block: 'nearest' });
  }, [curId]);

  const finish = (then?: () => void) => {
    dialog.current?.close();
    onClose();
    if (opener.current instanceof HTMLElement && opener.current.isConnected) opener.current.focus();
    if (then) window.setTimeout(then, 0);
  };
  const choose = (o: Option) => {
    if (o.href) finish(() => (window.location.hash = o.href!));
    else finish(o.run);
  };

  return (
    <dialog
      ref={dialog}
      className="cmdk"
      aria-label="Command palette"
      onCancel={(e) => {
        e.preventDefault();
        finish();
      }}
      onClick={(e) => e.target === dialog.current && finish()}
    >
      <div className="cmdk-box">
        <div className="cmdk-field">
          <Icon name="search" />
          <input
            ref={input}
            className="cmdk-input"
            placeholder="Go to a screen, search an id, IP or rule, or run an action"
            aria-label="Search screens, alerts, incidents, IPs, rules and actions"
            value={q}
            autoComplete="off"
            spellCheck={false}
            role="combobox"
            aria-expanded="true"
            aria-controls="cmdk-list"
            aria-autocomplete="list"
            aria-activedescendant={curId ?? undefined}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                const n = flat.length;
                if (n) setActive((a) => (Math.min(a, n - 1) + (e.key === 'ArrowDown' ? 1 : n - 1)) % n);
                e.preventDefault();
              } else if (e.key === 'Enter' && cur) {
                choose(cur);
                e.preventDefault();
              } else if (e.key === 'Tab') {
                e.preventDefault(); // the input is the only stop: arrows move through the results
              }
            }}
          />
          <span className="kbd">Esc</span>
        </div>
        <div className="cmdk-list" id="cmdk-list" role="listbox" aria-label="Results">
          {groups.map((g, gi) => (
            <div key={g.label} role="group" aria-labelledby={`cmdk-g${gi}`} className="cmdk-group">
              <div id={`cmdk-g${gi}`} className="cmdk-glabel" role="presentation">
                {g.label}
              </div>
              {g.status && (
                <div className="cmdk-status" role="presentation">
                  {g.status}
                </div>
              )}
              {g.options.map((o) => (
                <div
                  key={o.id}
                  id={optId(o)}
                  role="option"
                  aria-selected={o === cur}
                  className="cmdk-opt"
                  onClick={() => choose(o)}
                  onMouseMove={() => o !== cur && setActive(flat.indexOf(o))}
                >
                  <Icon name={o.icon} />
                  {o.tag && <span className="tag">{o.tag}</span>}
                  <span className={o.mono ? 'cmdk-label mono' : 'cmdk-label'}>{o.label}</span>
                  {o.sub && <span className="cmdk-sub">{o.sub}</span>}
                  {o.hint && <span className="cmdk-hint mono">{o.hint}</span>}
                </div>
              ))}
            </div>
          ))}
          {groups.length === 0 && (
            <div className="cmdk-status" role="presentation">
              Nothing matches "{q.trim()}".
            </div>
          )}
        </div>
        <div className="cmdk-foot" aria-hidden="true">
          <span>
            <span className="kbd">↑</span> <span className="kbd">↓</span> move
          </span>
          <span>
            <span className="kbd">Enter</span> open
          </span>
          <span>
            <span className="kbd">Esc</span> close
          </span>
        </div>
      </div>
    </dialog>
  );
}
