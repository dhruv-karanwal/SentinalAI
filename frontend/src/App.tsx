// Shell (DESIGN.md 11.1): left rail, top bar (brand, data source, environment badge, global
// search, notifications, user), footer, the current screen, global shortcuts, toasts, help.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { api, can, setToken, setUnauthorizedHandler, type Session } from './api.ts';
import type { AskEntry, AskStore } from './components/Findings.tsx';
import { GlobalSearch } from './components/GlobalSearch.tsx';
import { Notifications } from './components/Notifications.tsx';
import { Button, Dialog, ScreenBoundary } from './components/ui.tsx';
import { AppContext, buildHash, isTypingTarget, sendNav, storageGet, storageSet, useLoad, useRoute, type AppState, type TimeFormat } from './hooks.ts';
import { BrandMark, FAVICON_SVG, Icon, type IconName } from './icons.tsx';
import { fmtInt } from './lib/format.ts';
import { AlertsScreen } from './screens/Alerts.tsx';
import { ApprovalsScreen } from './screens/Approvals.tsx';
import { AskScreen } from './screens/Ask.tsx';
import { AuditScreen } from './screens/Audit.tsx';
import { EntityScreen } from './screens/Entity.tsx';
import { ErrorPage } from './screens/ErrorPage.tsx';
import { ExecutiveScreen } from './screens/Executive.tsx';
import { IncidentsScreen } from './screens/Incidents.tsx';
import { OverviewScreen } from './screens/Overview.tsx';
import { ReportsScreen } from './screens/Reports.tsx';
import { SecurityNotes, SettingsScreen } from './screens/Settings.tsx';
import { SignIn } from './screens/SignIn.tsx';
import { StudyScreen } from './screens/Study.tsx';
import { UsersScreen } from './screens/Users.tsx';

export const VERSION = '0.2.0';

interface NavItem {
  path: string;
  label: string;
  icon: IconName;
  key?: string;
  permission?: string;
  roles?: Session['role'][];
  hidden?: boolean;
  about: string;
}

const NAV: NavItem[] = [
  { path: '/overview', label: 'Overview', icon: 'overview', key: 'o', about: 'Charts over the stored alerts and incidents; each chart filters the alert table under it.' },
  { path: '/incidents', label: 'Incidents', icon: 'incidents', key: 'i', about: 'The triage queue: incident table, detail with the detector strip, ATT&CK lanes, entity graph, evidence and findings.' },
  { path: '/alerts', label: 'Alerts', icon: 'alerts', key: 'a', about: 'Every stored alert with facet counts, saved filters and CSV export.' },
  { path: '/approvals', label: 'Approvals', icon: 'approvals', key: 'p', about: 'Requested response actions; managers decide with a reason (four-eyes) and execute once (simulated).' },
  { path: '/reports', label: 'Reports', icon: 'reports', key: 'r', about: 'Incident reports with their charts; JSON, CSV and PDF downloads; printable summary.' },
  { path: '/ask', label: 'Ask', icon: 'ask', key: 'k', permission: 'copilot.ask', about: 'Questions to the copilot about an incident, with verified citations (needs a model endpoint).' },
  { path: '/executive', label: 'Executive', icon: 'executive', key: 'e', about: 'One printable page: severity trend, top risks, ATT&CK coverage, time to review, open approvals.' },
  { path: '/study', label: 'Study', icon: 'study', key: 's', permission: 'read.raw', about: 'Matched-budget pilot results rendered from the result files (dev scenarios, pilot numbers).' },
  { path: '/audit', label: 'Audit', icon: 'audit', key: 'u', permission: 'audit.read', about: 'Every write and every denied request, with an activity chart.' },
  { path: '/users', label: 'Users', icon: 'users', permission: 'user.manage', about: 'Accounts and roles (admin): create, deactivate, reset with the environment-supplied password.' },
  { path: '/security', label: 'Security notes', icon: 'help', hidden: true, about: 'docs/security-notes.md as plain text.' },
  { path: '/entity', label: 'Entity', icon: 'entity', hidden: true, about: 'One host or source IP: activity, rules and the incidents that contain it.' },
];

const BOTTOM: NavItem[] = [{ path: '/settings', label: 'Settings', icon: 'settings', about: 'Theme, row density, time format, default data source.' }];

const SHORTCUTS: Array<[string, string]> = [
  ['j / k, arrow keys', 'Move the row selection'],
  ['Enter', 'Open the selected row (focus moves to the detail)'],
  ['Esc', 'Close the evidence pane, a dialog, a popover or a search field'],
  ['/', 'Focus the screen filter'],
  ['Ctrl+K', 'Global search (alert id, IP, rule id, incident id)'],
  ['c', 'Copy the selected id'],
  ['g then o / i / a / p / r / e / s / u', 'Overview / Incidents / Alerts / Approvals / Reports / Executive / Study / Audit'],
  ['Left / Right on a chart', 'Read the bins; Shift selects a range, Enter filters, Esc clears'],
  ['d', 'Compact or comfortable rows'],
  ['t', 'Dark or light theme'],
  ['?', 'This help'],
];

type Theme = 'dark' | 'light';
type Density = 'compact' | 'comfortable';

interface Toast {
  id: number;
  text: string;
  kind: 'info' | 'error';
}

function visible(n: NavItem, role: Session['role']): boolean {
  if (n.permission && !can(role, n.permission)) return false;
  if (n.roles && !n.roles.includes(role)) return false;
  return true;
}

function homeFor(role: Session['role']): string {
  return role === 'executive' ? '/executive' : '/overview';
}

/** Favicon from the brand mark in the current accent colour (read from the tokens, no hex here). */
function setFavicon(): void {
  const accent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();
  const svg = FAVICON_SVG.replaceAll('%23', encodeURIComponent(accent || 'currentColor'));
  let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
  if (!link) {
    link = document.createElement('link');
    link.rel = 'icon';
    document.head.appendChild(link);
  }
  link.type = 'image/svg+xml';
  link.href = `data:image/svg+xml,${svg}`;
}

export function App() {
  const route = useRoute();
  const [session, setSession] = useState<Session | null>(null);
  const [expired, setExpired] = useState(false);
  const [theme, setTheme] = useState<Theme>(() => (document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'));
  const [density, setDensity] = useState<Density>(() => (document.documentElement.dataset.density === 'comfortable' ? 'comfortable' : 'compact'));
  const [timeFormat, setTimeFormatState] = useState<TimeFormat>(() => (storageGet('sentinel.timefmt') === 'short' ? 'short' : 'iso'));
  const [scenario, setScenario] = useState<string | null>(() => storageGet('sentinel.scenario') ?? storageGet('sentinel.defaultScenario'));
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [help, setHelp] = useState(false);
  const [askEntries, setAskEntries] = useState<AskEntry[]>([]);
  const [modelOffline, setModelOffline] = useState(false);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const globalRef = useRef<HTMLInputElement | null>(null);
  const pendingG = useRef(0);
  const returnTo = useRef<string | null>(null);

  // The document attribute is set before the state change so that children that read tokens
  // while rendering or in effects (the canvas strip) already see the new theme.
  const applyTheme = useCallback((next: Theme) => {
    document.documentElement.dataset.theme = next;
    storageSet('sentinel.theme', next);
    setTheme(next);
    setFavicon();
  }, []);
  const toggleTheme = useCallback(() => applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light'), [applyTheme]);
  const applyDensity = useCallback((next: Density) => {
    document.documentElement.dataset.density = next;
    storageSet('sentinel.density', next);
    setDensity(next);
  }, []);
  const toggleDensity = useCallback(() => applyDensity(document.documentElement.dataset.density === 'comfortable' ? 'compact' : 'comfortable'), [applyDensity]);
  const setTimeFormat = useCallback((f: TimeFormat) => {
    storageSet('sentinel.timefmt', f);
    setTimeFormatState(f);
  }, []);

  useEffect(() => setFavicon(), []);

  // Print the executive page and report summaries in the light theme, then restore.
  useEffect(() => {
    let before: string | undefined;
    const pre = () => {
      before = document.documentElement.dataset.theme;
      document.documentElement.dataset.theme = 'light';
    };
    const post = () => {
      if (before) document.documentElement.dataset.theme = before;
    };
    window.addEventListener('beforeprint', pre);
    window.addEventListener('afterprint', post);
    return () => {
      window.removeEventListener('beforeprint', pre);
      window.removeEventListener('afterprint', post);
    };
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      returnTo.current = window.location.hash;
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
  const health = useLoad((signal) => (session ? api.health(signal) : Promise.resolve(null)), [session?.username]);
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
    returnTo.current = null;
  };

  // Landing route: the role's home page when the hash is empty.
  useEffect(() => {
    if (!session) return;
    const raw = window.location.hash.replace(/^#\/?/, '');
    if (!raw) window.location.replace(`#${homeFor(session.role)}`);
  }, [session]);

  // ---- global shortcuts ------------------------------------------------------------------------
  useEffect(() => {
    if (!session) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        globalRef.current?.focus();
        globalRef.current?.select();
        e.preventDefault();
        return;
      }
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
      const inChart = e.target instanceof Element && e.target.closest('.chart-svg, .graph');
      const now = Date.now();
      if (now - pendingG.current < 1200) {
        pendingG.current = 0;
        const item = NAV.find((n) => n.key === e.key && visible(n, session.role));
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
          // a focused table, chart, button or link handles its own Enter
          if (inGrid || inChart || (e.target instanceof HTMLElement && e.target !== document.body && e.target.id !== 'main')) return;
          sendNav({ type: 'open' });
          break;
        case 'c':
          sendNav({ type: 'copy' });
          break;
        case '/':
          (searchRef.current ?? globalRef.current)?.focus();
          (searchRef.current ?? globalRef.current)?.select();
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
    () => (session ? { session, scenario, theme, density, timeFormat, rowHeight: density === 'compact' ? 24 : 32, toast } : null),
    [session, scenario, theme, density, timeFormat, toast],
  );

  const items = session ? NAV.filter((n) => visible(n, session.role)) : [];
  const current = [...items, ...BOTTOM].find((n) => n.path === route.path) ?? null;

  useEffect(() => {
    document.title = session ? `${current?.label ?? 'Not found'} · SentinelAI` : 'Sign in · SentinelAI';
  }, [session, current?.label]);

  if (!session || !ctx) {
    return (
      <SignIn
        expired={expired}
        onSignedIn={(s) => {
          setExpired(false);
          setSession(s);
          if (returnTo.current) window.location.hash = returnTo.current;
        }}
      />
    );
  }

  const scenarioRow = scenarios.data?.scenarios.find((s) => s.scenario === scenario);
  const sc = scenario ?? '';
  let screen;
  if (!current) screen = <ErrorPage title={`No such page: ${route.path || '/'}`} detail="The address does not match a screen your role can open." home={homeFor(session.role)} />;
  else if (!scenario && !['/settings', '/security', '/users', '/study', '/approvals', '/audit', '/reports', '/ask'].includes(current.path))
    screen = scenarios.error ? (
      <ErrorPage title="No data source" detail={`The list of stored scenarios could not be loaded (${scenarios.error.status || 'API unreachable'}: ${scenarios.error.message}).`} home={homeFor(session.role)} onRetry={scenarios.reload} />
    ) : (
      <ErrorPage title={scenarios.loading ? 'Loading data sources' : 'No stored alerts'} detail={scenarios.loading ? 'Reading the stored scenarios.' : 'Replay a dev scenario first: app.main platform-ingest --scenario russellmitchell.'} home={homeFor(session.role)} />
    );
  else if (current.path === '/overview') screen = <OverviewScreen key={sc} scenario={sc} route={route} />;
  else if (current.path === '/incidents') screen = <IncidentsScreen key={sc} route={route} askStore={askStore} searchRef={searchRef} />;
  else if (current.path === '/alerts') screen = <AlertsScreen key={sc} scenario={sc} route={route} searchRef={searchRef} />;
  else if (current.path === '/approvals') screen = <ApprovalsScreen route={route} />;
  else if (current.path === '/reports') screen = <ReportsScreen route={route} />;
  else if (current.path === '/ask') screen = <AskScreen route={route} askStore={askStore} />;
  else if (current.path === '/executive') screen = <ExecutiveScreen key={sc} scenario={sc} />;
  else if (current.path === '/study') screen = <StudyScreen />;
  else if (current.path === '/audit') screen = <AuditScreen route={route} searchRef={searchRef} />;
  else if (current.path === '/users') screen = <UsersScreen />;
  else if (current.path === '/security') screen = <SecurityNotes />;
  else if (current.path === '/entity') screen = <EntityScreen key={`${sc}|${route.params.kind}|${route.params.value}`} scenario={sc} kind={route.params.kind ?? ''} value={route.params.value ?? ''} />;
  else
    screen = (
      <SettingsScreen
        theme={theme}
        density={density}
        timeFormat={timeFormat}
        scenarios={scenarios.data?.scenarios.map((s) => s.scenario) ?? []}
        onTheme={applyTheme}
        onDensity={applyDensity}
        onTimeFormat={setTimeFormat}
      />
    );

  const link = (n: NavItem) => (
    <li key={n.path}>
      <a href={`#${n.path}`} aria-current={route.path === n.path ? 'page' : undefined}>
        <Icon name={n.icon} />
        <span>{n.label}</span>
      </a>
    </li>
  );

  return (
    <AppContext.Provider value={ctx}>
      <a className="skip-link" href="#main" onClick={(e) => (e.preventDefault(), document.getElementById('main')?.focus())}>
        Skip to main content
      </a>
      <div className="shell">
        <header className="topbar">
          <a className="brand" href={`#${homeFor(session.role)}`} aria-label="SentinelAI home">
            <BrandMark size={18} />
            SentinelAI
          </a>
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
          {scenarioRow && <span className="muted num">{fmtInt(scenarioRow.alerts)} alerts</span>}
          <span className="env-badge" title="Alerts are replayed from the AIT-ADS dataset (dev scenarios). Nothing here is live traffic.">
            Dataset replay: demo data
          </span>
          {scenarios.error && <span className="field-error">data sources: {scenarios.error.status || 'API unreachable'}</span>}
          <span className="spacer" />
          <GlobalSearch inputRef={globalRef} scenario={scenario} />
          <Notifications />
          <Button kind="ghost" icon="help" onClick={() => setHelp(true)} title="Help and keyboard shortcuts (?)">
            Help
          </Button>
          <span className="who">
            <Icon name="user" />
            {session.username} <span className="faint">({session.role})</span>
          </span>
          <Button kind="ghost" icon="signOut" onClick={signOut}>
            Sign out
          </Button>
        </header>
        <nav className="rail" aria-label="Screens">
          <ul>{items.filter((n) => !n.hidden).map(link)}</ul>
          <ul>{BOTTOM.map(link)}</ul>
        </nav>
        <main className="main" id="main" tabIndex={-1}>
          <ScreenBoundary resetKey={`${route.path}|${scenario}`}>{screen}</ScreenBoundary>
        </main>
        <footer className="footer">
          <span>SentinelAI console {VERSION}</span>
          <span>Data: AIT-ADS replay{scenario ? `, ${scenario}` : ''} (dev scenario)</span>
          <span>
            API:{' '}
            {health.data ? `ok, ${health.data.database}` : health.error ? `unreachable (${health.error.status || 'no answer'})` : 'checking'}
          </span>
          <span className="spacer" />
          <a href="#/security">Security notes</a>
        </footer>
      </div>
      <div className="toasts">
        {toasts.map((t) => (
          <div key={t.id} className="toast" data-kind={t.kind} role={t.kind === 'error' ? 'alert' : 'status'}>
            {t.text}
          </div>
        ))}
      </div>
      {help && (
        <Dialog title="Help" onClose={() => setHelp(false)}>
          <h3 className="section-title">Keyboard shortcuts</h3>
          <dl className="shortcuts">
            {SHORTCUTS.map(([keys, what]) => (
              <div key={keys} style={{ display: 'contents' }}>
                <dt className="mono">{keys}</dt>
                <dd>{what}</dd>
              </div>
            ))}
          </dl>
          <h3 className="section-title" style={{ marginTop: 'var(--sp-12)' }}>
            Screens for your role ({session.role})
          </h3>
          <dl className="shortcuts">
            {[...items.filter((n) => !n.hidden), ...BOTTOM].map((n) => (
              <div key={n.path} style={{ display: 'contents' }}>
                <dt>{n.label}</dt>
                <dd>{n.about}</dd>
              </div>
            ))}
          </dl>
          <p className="faint" style={{ fontSize: 'var(--fs-12)' }}>
            All data is a replay of the AIT-ADS dev scenarios. The console shows platform outputs (alerts, incidents, reports, approvals); it shows no labels.
          </p>
        </Dialog>
      )}
    </AppContext.Provider>
  );
}
