import { createContext, useCallback, useContext, useEffect, useRef, useState, type RefObject } from 'react';

import { ApiError, type Session } from './api.ts';

// ---- app context ---------------------------------------------------------------------------

export interface AppState {
  session: Session;
  scenario: string | null;
  theme: 'dark' | 'light';
  density: 'compact' | 'comfortable';
  rowHeight: number;
  toast: (text: string, kind?: 'info' | 'error') => void;
}

export const AppContext = createContext<AppState | null>(null);

export function useApp(): AppState {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('AppContext is missing');
  return ctx;
}

// ---- hash routing ----------------------------------------------------------------------------
// #/incidents?id=inc-1&ev=1685715378.241  (no router package; deep links work, no page reloads)

export interface Route {
  path: string;
  params: Record<string, string>;
}

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#/, '');
  const q = raw.indexOf('?');
  const path = (q < 0 ? raw : raw.slice(0, q)) || '/incidents';
  const params: Record<string, string> = {};
  if (q >= 0) for (const [k, v] of new URLSearchParams(raw.slice(q + 1))) params[k] = v;
  return { path, params };
}

export function buildHash(path: string, params: Record<string, string | null | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) p.set(k, v);
  const s = p.toString();
  return `#${path}${s ? `?${s}` : ''}`;
}

export function useRoute(): Route & { setParams: (patch: Record<string, string | null>, replace?: boolean) => void } {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  const setParams = useCallback((patch: Record<string, string | null>, replace = true) => {
    const cur = parseHash(window.location.hash);
    const next = buildHash(cur.path, { ...cur.params, ...patch });
    if (next === (window.location.hash || '#/incidents')) return;
    if (replace) {
      window.history.replaceState(null, '', next);
      setRoute(parseHash(next));
    } else {
      window.location.hash = next;
    }
  }, []);
  return { ...route, setParams };
}

// ---- data loading ----------------------------------------------------------------------------

export interface Loaded<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  reload: () => void;
}

/** Runs `load` when `deps` change; keeps the previous data visible while reloading and on error. */
export function useLoad<T>(load: (signal: AbortSignal) => Promise<T>, deps: readonly unknown[]): Loaded<T> {
  const [state, setState] = useState<{ data: T | null; error: ApiError | null; loading: boolean }>({
    data: null,
    error: null,
    loading: true,
  });
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    const ctl = new AbortController();
    setState((s) => ({ ...s, loading: true, error: null }));
    loadRef.current(ctl.signal).then(
      (data) => setState({ data, error: null, loading: false }),
      (err: unknown) => {
        if (ctl.signal.aborted) return;
        const error = err instanceof ApiError ? err : new ApiError(0, '', err instanceof Error ? err.message : String(err));
        setState((s) => ({ ...s, error, loading: false }));
      },
    );
    return () => ctl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { ...state, reload };
}

// ---- keyboard --------------------------------------------------------------------------------

export type NavCommand = { type: 'move'; delta: number } | { type: 'open' } | { type: 'copy' };

const NAV_EVENT = 'sentinel:nav';

export function sendNav(cmd: NavCommand): void {
  window.dispatchEvent(new CustomEvent<NavCommand>(NAV_EVENT, { detail: cmd }));
}

/** The screen's primary table listens here, so j / k / Enter work wherever the focus is. */
export function useNav(handler: (cmd: NavCommand) => void, enabled: boolean): void {
  const ref = useRef(handler);
  ref.current = handler;
  useEffect(() => {
    if (!enabled) return;
    const on = (e: Event) => ref.current((e as CustomEvent<NavCommand>).detail);
    window.addEventListener(NAV_EVENT, on);
    return () => window.removeEventListener(NAV_EVENT, on);
  }, [enabled]);
}

export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable;
}

export function useElementSize<T extends HTMLElement>(): [RefObject<T | null>, { width: number; height: number }] {
  const ref = useRef<T | null>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const r = el.getBoundingClientRect();
      setSize((s) => (s.width === r.width && s.height === r.height ? s : { width: r.width, height: r.height }));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, size];
}

export function storageGet(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function storageSet(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // private window or blocked storage: the setting lasts for this page only
  }
}
