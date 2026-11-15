// Shell (DESIGN.md 5): grouped, collapsible rail (an off-canvas drawer on phones), top bar
// (brand, data source, command palette, tour, help, notifications, user menu), the current
// screen, global shortcuts, toasts, help dialog. The footer facts live at the bottom of the rail.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { api, can, setToken, setUnauthorizedHandler, type Session } from './api.ts';
import type { AskEntry, AskStore } from './components/Findings.tsx';
import { CommandPalette, type PaletteAction } from './components/CommandPalette.tsx';
import { HelpChat, openHelpChat } from './components/HelpChat.tsx';
import { TourPanel } from './components/Tour.tsx';
import { AboutScreen } from './screens/About.tsx';
import { Notifications } from './components/Notifications.tsx';
import { Button, Dialog, ScreenBoundary } from './components/ui.tsx';
import { AppContext, buildHash, isTypingTarget, sendNav, storageGet, storageSet, useLoad, useRoute, type AppState, type TimeFormat } from './hooks.ts';
import { BrandMark, FAVICON_SVG, Icon } from './icons.tsx';
import { fmtInt } from './lib/format.ts';
import { groupNav, NAV, railMove, type NavItem } from './lib/nav.ts';
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

const SHORTCUTS: Array<[string, string]> = [
  ['Ctrl+K, s', 'Command palette: screens, search (alert id, IP, rule id, incident id) and actions'],
  ['j / k, arrow keys', 'Move the row selection'],
  ['Enter', 'Open the selected row (focus moves to the detail)'],
  ['Esc', 'Close the evidence pane, a dialog, a popover or a search field'],
  ['/', 'Focus the screen filter (the command palette where a screen has none)'],
  ['c', 'Copy the selected id'],
  ['g then h / s / o / e / i / a / k / p / r / u', 'About / Study / Overview / Executive / Incidents / Alerts / Ask / Approvals / Reports / Audit'],
  ['Up / Down in the navigation', 'Move between screens'],
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

/** Professor demo mode (Settings, per browser): land on About instead of the role's home. */
function landingFor(role: Session['role'], demo: boolean): string {
  return demo ? '/about' : homeFor(role);
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
  const [demo, setDemoState] = useState(() => storageGet('sentinel.demo') !== '0');
  const [tour, setTour] = useState<number | null>(null);
  const [collapsed, setCollapsedState] = useState(() => storageGet('sentinel.rail') === 'collapsed');
  const [drawer, setDrawer] = useState(false);
  const [palette, setPalette] = useState(false);
  const [userMenu, setUserMenu] = useState(false);
  const railRef = useRef<HTMLElement | null>(null);
  const menuBtn = useRef<HTMLButtonElement | null>(null);
  const userBtn = useRef<HTMLButtonElement | null>(null);
  const userBox = useRef<HTMLDivElement | null>(null);
  const setCollapsed = useCallback((on: boolean) => {
    storageSet('sentinel.rail', on ? 'collapsed' : 'expanded');
    setCollapsedState(on);
  }, []);
  // the drawer closes on navigation; the user menu on an outside click
  useEffect(() => {
    const onHash = () => setDrawer(false);
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  useEffect(() => {
    if (!userMenu) return;
    const onDoc = (e: MouseEvent) => {
      if (userBox.current && !userBox.current.contains(e.target as Node)) setUserMenu(false);
    };
    const onEsc = (e: KeyboardEvent) => e.key === 'Escape' && setUserMenu(false);
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onEsc);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onEsc);
    };
  }, [userMenu]);
  useEffect(() => {
    if (drawer) (railRef.current?.querySelector<HTMLElement>('a[aria-current="page"]') ?? railRef.current?.querySelector<HTMLElement>('a.rail-link'))?.focus();
  }, [drawer]);
  const setDemo = useCallback((on: boolean) => {
    storageSet('sentinel.demo', on ? '1' : '0');
    setDemoState(on);
  }, []);
  const searchRef = useRef<HTMLInputElement | null>(null);
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
    setUserMenu(false);
    setPalette(false);
    returnTo.current = null;
  };

  // Landing route: the role's home page when the hash is empty.
  useEffect(() => {
    if (!session) return;
    const raw = window.location.hash.replace(/^#\/?/, '');
    if (!raw) window.location.replace(`#${landingFor(session.role, demo)}`);
    // demo mode: land on About once per sign-in
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  // ---- global shortcuts ------------------------------------------------------------------------
  useEffect(() => {
    if (!session) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        if (!document.querySelector('dialog[open]')) setPalette(true);
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
          if (searchRef.current) {
            searchRef.current.focus();
            searchRef.current.select();
          } else setPalette(true);
          break;
        case 's':
          setPalette(true);
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
    () => (session ? { session, scenario, theme, density, timeFormat, rowHeight: density === 'compact' ? 28 : 36, toast } : null),
    [session, scenario, theme, density, timeFormat, toast],
  );

  const items = session ? NAV.filter((n) => visible(n, session.role)) : [];
  const current = items.find((n) => n.path === route.path) ?? null;

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
  else if (current.path === '/about') screen = <AboutScreen onTour={() => setTour(0)} />;
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
        demo={demo}
        onDemo={setDemo}
      />
    );

  const groups = groupNav(items);
  const screens = groups.flatMap((g) => g.items);
  const apiText = health.data ? `ok, ${health.data.database}` : health.error ? `unreachable (${health.error.status || 'no answer'})` : 'checking';
  const apiState = health.data ? 'ok' : health.error ? 'down' : 'checking';
  const startTour = () => setTour(0);

  const actions: PaletteAction[] = [
    { id: 'theme', label: theme === 'dark' ? 'Switch to the light theme' : 'Switch to the dark theme', icon: theme === 'dark' ? 'sun' : 'moon', keywords: 'toggle theme dark light colour', hint: 't', run: toggleTheme },
    { id: 'density', label: density === 'compact' ? 'Comfortable rows' : 'Compact rows', icon: 'density', keywords: 'toggle density rows compact comfortable', hint: 'd', run: toggleDensity },
    { id: 'tour', label: 'Start the guided tour', icon: 'play', keywords: 'start here walkthrough tour', run: startTour },
    { id: 'chat', label: 'Open the help chat', icon: 'chat', keywords: 'explain glossary question help chat', run: openHelpChat },
    { id: 'help', label: 'Keyboard shortcuts and help', icon: 'keyboard', keywords: 'shortcuts keys help', hint: '?', run: () => setHelp(true) },
    { id: 'demo', label: demo ? 'Turn professor demo mode off' : 'Turn professor demo mode on', icon: 'about', keywords: 'professor demo mode landing about', run: () => setDemo(!demo) },
    { id: 'signout', label: 'Sign out', icon: 'signOut', keywords: 'log out sign out leave', run: signOut },
  ];

  const sourceControl = (id: string) => (
    <div className="tb-source">
      <label className="tb-source-label" htmlFor={id}>
        Data source
      </label>
      <select id={id} className="select mono" value={scenario ?? ''} onChange={(e) => chooseScenario(e.target.value)} disabled={!scenarios.data || scenarios.data.scenarios.length === 0}>
        {(scenarios.data?.scenarios ?? []).map((s) => (
          <option key={s.scenario} value={s.scenario}>
            {s.scenario}
          </option>
        ))}
        {!scenarios.data && <option value={scenario ?? ''}>{scenario ?? (scenarios.error ? 'unavailable' : 'loading')}</option>}
        {scenarios.data?.scenarios.length === 0 && <option value="">no stored alerts</option>}
      </select>
      {scenarioRow && (
        <span className="tb-source-meta" title="Alerts are replayed from the AIT-ADS dataset (dev scenarios). Nothing here is live traffic.">
          {fmtInt(scenarioRow.alerts)} alerts · dataset replay
        </span>
      )}
      {scenarios.error && <span className="field-error">data sources: {scenarios.error.status || 'API unreachable'}</span>}
    </div>
  );

  const closeDrawer = () => {
    setDrawer(false);
    menuBtn.current?.focus();
  };
  const onRailKey = (e: React.KeyboardEvent<HTMLElement>) => {
    const nav = railRef.current;
    if (!nav) return;
    if (drawer && e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      closeDrawer();
      return;
    }
    if (drawer && e.key === 'Tab') {
      // focus stays inside the open drawer
      const all = Array.from(nav.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), select:not([disabled])')).filter((el) => el.offsetParent !== null);
      const i = all.indexOf(document.activeElement as HTMLElement);
      const next = e.shiftKey ? (i <= 0 ? all.length - 1 : i - 1) : i === all.length - 1 ? 0 : i + 1;
      all[next]?.focus();
      e.preventDefault();
      return;
    }
    if (!(e.target instanceof HTMLElement) || !e.target.classList.contains('rail-link')) return;
    const links = Array.from(nav.querySelectorAll<HTMLElement>('a.rail-link'));
    const next = railMove(links.length, links.indexOf(e.target), e.key);
    if (next === null) return;
    links[next]?.focus();
    e.preventDefault();
  };
  const closeUserMenu = () => {
    setUserMenu(false);
    userBtn.current?.focus();
  };

  return (
    <AppContext.Provider value={ctx}>
      <a className="skip-link" href="#main" onClick={(e) => (e.preventDefault(), document.getElementById('main')?.focus())}>
        Skip to main content
      </a>
      <div className="shell" data-collapsed={collapsed || undefined} data-drawer={drawer || undefined}>
        <header className="topbar">
          <button
            ref={menuBtn}
            type="button"
            className="btn ghost icon-only tb-menu"
            aria-label="Open the navigation"
            aria-expanded={drawer}
            aria-controls="rail"
            onClick={() => setDrawer(true)}
          >
            <Icon name="menu" />
          </button>
          <a className="brand" href={`#${homeFor(session.role)}`} aria-label="SentinelAI home">
            <BrandMark size={18} />
            <span className="brand-name">SentinelAI</span>
          </a>
          <span className="tb-wide tb-contents">{sourceControl('scenario')}</span>
          <button type="button" className="cmdk-trigger" onClick={() => setPalette(true)} aria-label="Search or jump to (Ctrl+K)" aria-keyshortcuts="Control+K s" aria-haspopup="dialog">
            <Icon name="search" />
            <span className="cmdk-trigger-text">Search or jump to</span>
            <span className="kbd">Ctrl K</span>
          </button>
          <span className="spacer" />
          <Button kind="ghost" icon="play" className="tb-wide" onClick={startTour} title="A 6-stop walkthrough of the console">
            Start here
          </Button>
          <Button kind="ghost" icon="help" className="tb-wide" onClick={() => setHelp(true)} title="Help and keyboard shortcuts (?)">
            Help
          </Button>
          <Notifications />
          <div className="user" ref={userBox}>
            <button
              ref={userBtn}
              type="button"
              className="btn ghost user-btn"
              aria-expanded={userMenu}
              aria-controls="user-menu"
              aria-label={`Account: ${session.username} (${session.role})`}
              onClick={() => setUserMenu(!userMenu)}
              onKeyDown={(e) => e.key === 'Escape' && userMenu && closeUserMenu()}
            >
              <Icon name="user" />
              <span className="user-name">{session.username}</span>
              <Icon name="chevronDown" />
            </button>
            {userMenu && (
              <div className="menu-pop user-pop" id="user-menu" role="region" aria-label="Account" onKeyDown={(e) => e.key === 'Escape' && closeUserMenu()}>
                <div className="menu-head">
                  <span className="user-pop-name">{session.username}</span>
                  <span className="user-pop-role">Role: {session.role}</span>
                </div>
                <ul className="menu-list">
                  <li className="tb-narrow">
                    <button type="button" onClick={() => (setUserMenu(false), startTour())}>
                      <Icon name="play" /> Start here
                    </button>
                  </li>
                  <li className="tb-narrow">
                    <button type="button" onClick={() => (setUserMenu(false), setHelp(true))}>
                      <Icon name="help" /> Help and shortcuts
                    </button>
                  </li>
                  <li>
                    <a href="#/settings" onClick={() => setUserMenu(false)}>
                      <Icon name="settings" /> Settings
                    </a>
                  </li>
                  <li>
                    <button type="button" onClick={signOut}>
                      <Icon name="signOut" /> Sign out
                    </button>
                  </li>
                </ul>
              </div>
            )}
          </div>
        </header>
        <div className="rail-scrim" aria-hidden="true" onClick={closeDrawer} />
        <nav className="rail" id="rail" aria-label="Screens" ref={railRef} onKeyDown={onRailKey}>
          <div className="rail-drawer-head">
            <span className="brand">
              <BrandMark size={18} />
              SentinelAI
            </span>
            <button type="button" className="btn ghost icon-only" aria-label="Close the navigation (Esc)" onClick={closeDrawer}>
              <Icon name="close" />
            </button>
          </div>
          <div className="rail-drawer-source">{sourceControl('scenario-drawer')}</div>
          <div className="rail-groups">
            {groups.map((g, gi) => (
              <div key={g.label} className="rail-group" role="group" aria-labelledby={`rail-g${gi}`}>
                <h2 className="rail-label" id={`rail-g${gi}`}>
                  {g.label}
                </h2>
                <ul>
                  {g.items.map((n) => (
                    <li key={n.path}>
                      <a className="rail-link" href={`#${n.path}`} aria-current={route.path === n.path ? 'page' : undefined} data-tip={n.label}>
                        <Icon name={n.icon} />
                        <span className="rail-text">{n.label}</span>
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <div className="rail-foot">
            <dl className="rail-facts">
              <div>
                <dt>Console</dt>
                <dd>{VERSION}</dd>
              </div>
              <div>
                <dt>Data</dt>
                <dd>AIT-ADS replay{scenario ? `, ${scenario}` : ''} (dev scenario)</dd>
              </div>
              <div>
                <dt>API</dt>
                <dd>
                  <span className="api-dot" data-state={apiState} aria-hidden="true" />
                  {apiText}
                </dd>
              </div>
            </dl>
            <span className="rail-api-mini" data-state={apiState} role="img" aria-label={`API: ${apiText}`} title={`API: ${apiText}`} />
            <a className="rail-security" href="#/security">
              Security notes
            </a>
            <button
              type="button"
              className="btn ghost rail-toggle"
              onClick={() => setCollapsed(!collapsed)}
              aria-expanded={!collapsed}
              aria-controls="rail"
              aria-label={collapsed ? 'Expand the navigation' : 'Collapse the navigation'}
              title={collapsed ? 'Expand the navigation' : 'Collapse the navigation'}
            >
              <Icon name={collapsed ? 'chevronRight' : 'chevronLeft'} />
              <span className="rail-text">Collapse</span>
            </button>
          </div>
        </nav>
        <main className="main" id="main" tabIndex={-1}>
          <ScreenBoundary resetKey={`${route.path}|${scenario}`}>
            <div className="screen-enter" key={route.path}>
              {screen}
            </div>
          </ScreenBoundary>
        </main>
        {tour !== null && <TourPanel step={tour} onStep={setTour} onClose={() => setTour(null)} />}
        <HelpChat path={route.path} screenName={current?.label ?? 'Unknown page'} incidentId={route.path === '/incidents' ? (route.params.id ?? null) : null} />
        <div className="toasts">
          {toasts.map((t) => (
            <div key={t.id} className="toast" data-kind={t.kind} role={t.kind === 'error' ? 'alert' : 'status'}>
              {t.text}
            </div>
          ))}
        </div>
      </div>
      {palette && <CommandPalette screens={screens} actions={actions} scenario={scenario} currentPath={route.path} onClose={() => setPalette(false)} />}
      {help && (
        <Dialog title="Help" onClose={() => setHelp(false)}>
          <section className="help-sec" aria-labelledby="help-keys">
            <h3 id="help-keys">Keyboard shortcuts</h3>
            <dl className="help-list">
              {SHORTCUTS.map(([keys, what]) => (
                <div key={keys}>
                  <dt className="mono">{keys}</dt>
                  <dd>{what}</dd>
                </div>
              ))}
            </dl>
          </section>
          <section className="help-sec" aria-labelledby="help-screens">
            <h3 id="help-screens">Screens for your role ({session.role})</h3>
            <dl className="help-list">
              {screens.map((n) => (
                <div key={n.path}>
                  <dt>{n.label}</dt>
                  <dd>{n.about}</dd>
                </div>
              ))}
            </dl>
          </section>
          <p className="help-note">All data is a replay of the AIT-ADS dev scenarios. The console shows platform outputs (alerts, incidents, reports, approvals); it shows no labels.</p>
        </Dialog>
      )}
    </AppContext.Provider>
  );
}
