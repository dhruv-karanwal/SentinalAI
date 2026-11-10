// Shell: left rail, slim top bar, the current screen, global shortcuts, toasts.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { api, can, setToken, setUnauthorizedHandler, type Session } from './api.ts';
import type { AskEntry, AskStore } from './components/Findings.tsx';
import { Button, Dialog, ScreenBoundary } from './components/ui.tsx';
import { AppContext, buildHash, isTypingTarget, sendNav, storageGet, storageSet, useLoad, useRoute, type AppState } from './hooks.ts';
import { Icon, type IconName } from './icons.tsx';
import { fmtInt } from './lib/format.ts';
import { AlertsScreen } from './screens/Alerts.tsx';
import { ApprovalsScreen } from './screens/Approvals.tsx';
import { AskScreen } from './screens/Ask.tsx';
import { AuditScreen } from './screens/Audit.tsx';
import { IncidentsScreen } from './screens/Incidents.tsx';
import { ReportsScreen } from './screens/Reports.tsx';
import { SignIn } from './screens/SignIn.tsx';

interface NavItem {
  path: string;
  label: string;
  icon: IconName;
  key: string;
  permission?: string;
}

const NAV: NavItem[] = [
  { path: '/incidents', label: 'Incidents', icon: 'incidents', key: 'i' },
  { path: '/alerts', label: 'Alerts', icon: 'alerts', key: 'a' },
  { path: '/approvals', label: 'Approvals', icon: 'approvals', key: 'p' },
  { path: '/reports', label: 'Reports', icon: 'reports', key: 'r' },
  { path: '/ask', label: 'Ask', icon: 'ask', key: 'k', permission: 'copilot.ask' },
  { path: '/audit', label: 'Audit', icon: 'audit', key: 'u', permission: 'audit.read' },
];

const SHORTCUTS: Array<[string, string]> = [
  ['j / k, arrow keys', 'Move the row selection'],
  ['Enter', 'Open the selected row (focus moves to the detail)'],
  ['Esc', 'Close the evidence pane, a dialog or a search field'],
  ['/', 'Focus the search or filter field'],
  ['c', 'Copy the selected id'],
  ['g then i / a / p / r', 'Go to Incidents / Alerts / Approvals / Reports'],
  ['d', 'Compact or comfortable rows'],
  ['t', 'Dark or light theme'],
  ['?', 'This list'],
];

type Theme = 'dark' | 'light';
type Density = 'compact' | 'comfortable';

interface Toast {
  id: number;
  text: string;
  kind: 'info' | 'error';
}

export function App() {
  const route = useRoute();
  const [session, setSession] = useState<Session | null>(null);
  const [expired, setExpired] = useState(false);
  const [theme, setTheme] = useState<Theme>(() => (document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'));
  const [density, setDensity] = useState<Density>(() => (document.documentElement.dataset.density === 'comfortable' ? 'comfortable' : 'compact'));
  const [scenario, setScenario] = useState<string | null>(() => storageGet('sentinel.scenario'));
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [help, setHelp] = useState(false);
  const [askEntries, setAskEntries] = useState<AskEntry[]>([]);
  const [modelOffline, setModelOffline] = useState(false);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const pendingG = useRef(0);

  // The document attribute is set before the state change so that children that read tokens
  // while rendering or in effects (the canvas strip) already see the new theme.
  const toggleTheme = useCallback(() => {
    const next: Theme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = next;
    storageSet('sentinel.theme', next);
    setTheme(next);
  }, []);
  const toggleDensity = useCallback(() => {
    const next: Density = document.documentElement.dataset.density === 'comfortable' ? 'compact' : 'comfortable';
    document.documentElement.dataset.density = next;
    storageSet('sentinel.density', next);
    setDensity(next);
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setToken(null);
      setSession(null);
      setExpired(true);
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  const toast = useCallback((text: string, kind: 'info' | 'error' = 'info') => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-3), { id, text, kind }]);
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === 'error' ? 8000 : 4000);
  }, []);

  const scenarios = useLoad((signal) => (session ? api.scenarios(signal) : Promise.resolve(null)), [session?.username]);
  useEffect(() => {
    const list = scenarios.data?.scenarios;
    if (!list) return;
    if (list.length > 0 && !list.some((s) => s.scenario === scenario)) setScenario(list[0]!.scenario);
  }, [scenarios.data, scenario]);

  const chooseScenario = (value: string) => {
    setScenario(value);
    storageSet('sentinel.scenario', value);
    window.location.hash = buildHash(route.path, {});
  };

  const signOut = () => {
    setToken(null);
    setSession(null);
    setExpired(false);
    setAskEntries([]);
  };

  // ---- global shortcuts ------------------------------------------------------------------------
  useEffect(() => {
    if (!session) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (document.querySelector('dialog[open]')) return;
      if (e.key === 'Escape') {
        if (route.params.ev) {
          route.setParams({ ev: null });
          e.preventDefault();
        }
        return;
      }
      if (isTypingTarget(e.target)) return;
      const inGrid = e.target instanceof HTMLElement && e.target.getAttribute('role') === 'grid';
      const now = Date.now();
      if (now - pendingG.current < 1200) {
        pendingG.current = 0;
        const item = NAV.find((n) => n.key === e.key && (!n.permission || can(session.role, n.permission)));
        if (item) {
          window.location.hash = `#${item.path}`;
          e.preventDefault();
          return;
        }
      }
      switch (e.key) {
        case 'j':
          sendNav({ type: 'move', delta: 1 });
          break;
        case 'k':
          sendNav({ type: 'move', delta: -1 });
          break;
        case 'Enter':
          // a focused table, button or link handles its own Enter
          if (inGrid || (e.target instanceof HTMLElement && e.target !== document.body && e.target.id !== 'main')) return;
          sendNav({ type: 'open' });
          break;
        case 'c':
          sendNav({ type: 'copy' });
          break;
        case '/':
          searchRef.current?.focus();
          searchRef.current?.select();
          break;
        case '?':
          setHelp(true);
          break;
        case 'g':
          pendingG.current = now;
          break;
        case 'd':
          toggleDensity();
          break;
        case 't':
          toggleTheme();
          break;
        default:
          return;
      }
      e.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [session, route, toggleDensity, toggleTheme]);

  const askStore = useMemo<AskStore>(
    () => ({
      entries: askEntries,
      modelOffline,
      add: (entry) => setAskEntries((list) => [entry, ...list]),
      setOffline: () => setModelOffline(true),
    }),
    [askEntries, modelOffline],
  );

  const ctx = useMemo<AppState | null>(
    () => (session ? { session, scenario, theme, density, rowHeight: density === 'compact' ? 24 : 32, toast } : null),
    [session, scenario, theme, density, toast],
  );

  if (!session || !ctx) {
    return (
      <SignIn
        expired={expired}
        onSignedIn={(s) => {
          setExpired(false);
          setSession(s);
        }}
      />
    );
  }

  const items = NAV.filter((n) => !n.permission || can(session.role, n.permission));
  const current = items.find((n) => n.path === route.path) ?? null;
  const scenarioRow = scenarios.data?.scenarios.find((s) => s.scenario === scenario);

  let screen;
  if (!current) {
    screen = (
      <div className="state" data-kind="error" role="alert">
        <div className="state-title">No such screen: {route.path}</div>
        <p>
          <a href="#/incidents">Go to Incidents</a>
        </p>
      </div>
    );
  } else if (current.path === '/incidents') screen = <IncidentsScreen key={scenario} route={route} askStore={askStore} searchRef={searchRef} />;
  else if (current.path === '/alerts') screen = <AlertsScreen key={scenario} route={route} searchRef={searchRef} />;
  else if (current.path === '/approvals') screen = <ApprovalsScreen route={route} />;
  else if (current.path === '/reports') screen = <ReportsScreen route={route} />;
  else if (current.path === '/ask') screen = <AskScreen route={route} askStore={askStore} />;
  else screen = <AuditScreen route={route} searchRef={searchRef} />;

  return (
    <AppContext.Provider value={ctx}>
      <a className="skip-link" href="#main" onClick={(e) => (e.preventDefault(), document.getElementById('main')?.focus())}>
        Skip to main content
      </a>
      <div className="shell">
        <header className="topbar">
          <span className="product">SentinelAI</span>
          <label className="label" htmlFor="scenario">
            Data source
          </label>
          <select
            id="scenario"
            className="select mono"
            value={scenario ?? ''}
            onChange={(e) => chooseScenario(e.target.value)}
            disabled={!scenarios.data || scenarios.data.scenarios.length === 0}
          >
            {(scenarios.data?.scenarios ?? []).map((s) => (
              <option key={s.scenario} value={s.scenario}>
                {s.scenario}
              </option>
            ))}
            {!scenarios.data && <option value={scenario ?? ''}>{scenario ?? (scenarios.error ? 'unavailable' : 'loading')}</option>}
            {scenarios.data?.scenarios.length === 0 && <option value="">no stored alerts</option>}
          </select>
          {scenarioRow && <span className="muted num">{fmtInt(scenarioRow.alerts)} alerts stored · dataset replay</span>}
          {scenarios.error && <span className="field-error">data sources: {scenarios.error.status || 'API unreachable'}</span>}
          <span className="spacer" />
          <span className="who">
            <Icon name="user" />
            {session.username} <span className="faint">({session.role})</span>
          </span>
          <Button kind="ghost" icon="density" aria-pressed={density === 'comfortable'} onClick={toggleDensity} title="Row density (d)">
            {density === 'compact' ? 'Compact' : 'Comfortable'}
          </Button>
          <Button kind="ghost" icon={theme === 'dark' ? 'moon' : 'sun'} onClick={toggleTheme} title="Theme (t)">
            {theme === 'dark' ? 'Dark' : 'Light'}
          </Button>
          <Button kind="ghost" icon="keyboard" onClick={() => setHelp(true)} title="Keyboard shortcuts (?)">
            Keys
          </Button>
          <Button kind="ghost" icon="signOut" onClick={signOut}>
            Sign out
          </Button>
        </header>
        <nav className="rail" aria-label="Screens">
          <ul>
            {items.map((n) => (
              <li key={n.path}>
                <a href={`#${n.path}`} aria-current={route.path === n.path ? 'page' : undefined}>
                  <Icon name={n.icon} />
                  <span>{n.label}</span>
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <main className="main" id="main" tabIndex={-1}>
          <ScreenBoundary resetKey={`${route.path}|${scenario}`}>{screen}</ScreenBoundary>
        </main>
      </div>
      <div className="toasts">
        {toasts.map((t) => (
          <div key={t.id} className="toast" data-kind={t.kind} role={t.kind === 'error' ? 'alert' : 'status'}>
            {t.text}
          </div>
        ))}
      </div>
      {help && (
        <Dialog title="Keyboard shortcuts" onClose={() => setHelp(false)}>
          <dl className="shortcuts">
            {SHORTCUTS.map(([keys, what]) => (
              <div key={keys} style={{ display: 'contents' }}>
                <dt className="mono">{keys}</dt>
                <dd>{what}</dd>
              </div>
            ))}
          </dl>
        </Dialog>
      )}
    </AppContext.Provider>
  );
}
