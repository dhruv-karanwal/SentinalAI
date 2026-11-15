// Small shared pieces: tags, time, copy, truncation, states, dialog.

import { Component, useEffect, useRef, useState, type ErrorInfo, type ReactNode } from 'react';

import { ApiError } from '../api.ts';
import { Icon, SeverityGlyph, type IconName } from '../icons.tsx';
import { useAppMaybe } from '../hooks.ts';
import { fmtTime, relTime } from '../lib/format.ts';
import { splitHighlight } from '../lib/highlight.ts';

// ---- tags ------------------------------------------------------------------------------------

/** Severity as glyph + word (never colour alone). Accepts "High" / "high" / triage levels. */
export function SeverityCell({ value }: { value: string | null | undefined }) {
  const v = (value ?? '').toLowerCase();
  const level = v === 'high' ? 3 : v === 'medium' ? 2 : v === 'low' ? 1 : 0;
  if (level === 0) return <span className="faint">{value || 'none'}</span>;
  return (
    <span className="sev" data-sev={v}>
      <SeverityGlyph level={level} />
      {v.charAt(0).toUpperCase() + v.slice(1)}
    </span>
  );
}

const DETECTOR_NAMES: Record<string, string> = { wazuh: 'Wazuh', suricata: 'Suricata', aminer: 'AMiner', sigma: 'Sigma' };

export function detectorName(det: string): string {
  return DETECTOR_NAMES[det] ?? det;
}

export function DetectorTag({ value }: { value: string }) {
  return (
    <span className="det" data-det={value}>
      {detectorName(value)}
    </span>
  );
}

export function StatusTag({ value }: { value: string }) {
  return (
    <span className="tag" data-tone={value}>
      {value}
    </span>
  );
}

// ---- time, ids -------------------------------------------------------------------------------

/**
 * Absolute UTC time; the relative time is in the hover text. `kind` labels the date where 2022
 * dataset times and console creation times appear together: "data date" or "created".
 */
export function Time({ ts, kind }: { ts: string | null | undefined; kind?: 'data' | 'created' }) {
  const app = useAppMaybe();
  if (!ts) return <span className="faint">-</span>;
  const what = kind === 'data' ? 'data date: when it happened in the 2022 dataset' : kind === 'created' ? 'created: when this console stored it' : '';
  return (
    <>
      <time className="mono num" dateTime={ts} title={`${relTime(ts)} (UTC)${what ? `; ${what}` : ''}`}>
        {fmtTime(ts, app?.timeFormat ?? 'iso')}
      </time>
      {kind && <span className="date-kind"> {kind === 'data' ? 'data date' : 'created'}</span>}
    </>
  );
}

export function CopyButton({ text, label }: { text: string; label: string }) {
  const [state, setState] = useState<'idle' | 'ok' | 'failed'>('idle');
  useEffect(() => {
    if (state === 'idle') return;
    const t = window.setTimeout(() => setState('idle'), 1500);
    return () => window.clearTimeout(t);
  }, [state]);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setState('ok');
    } catch {
      setState('failed');
    }
  };
  return (
    <button
      type="button"
      className="copy-btn"
      onClick={(e) => {
        e.stopPropagation();
        void copy();
      }}
      title={state === 'ok' ? 'Copied' : state === 'failed' ? 'Copy failed: clipboard not available' : label}
      aria-label={label}
    >
      <Icon name={state === 'ok' ? 'check' : state === 'failed' ? 'warning' : 'copy'} />
      <span className="visually-hidden" role="status">
        {state === 'ok' ? 'Copied' : state === 'failed' ? 'Copy failed' : ''}
      </span>
    </button>
  );
}

/** A monospace id with a copy button. */
export function Id({ value, label = 'Copy id' }: { value: string; label?: string }) {
  return (
    <span className="copyable">
      <span className="mono" title={value}>
        {value}
      </span>
      <CopyButton text={value} label={label} />
    </span>
  );
}

/** Untrusted text with matched spans marked. Rendered as text nodes only. */
export function Highlighted({ text, needles, caseSensitive }: { text: string; needles: readonly string[]; caseSensitive?: boolean }) {
  const segs = splitHighlight(text, needles, caseSensitive);
  return (
    <>
      {segs.map((s, i) => (s.hit ? <mark key={i}>{s.text}</mark> : <span key={i}>{s.text}</span>))}
    </>
  );
}

/** Long untrusted text: cut at `limit` characters with a button to show all (unless a match is beyond the cut). */
export function TruncatedText({ text, limit = 600, needles = [] }: { text: string; limit?: number; needles?: readonly string[] }) {
  const [open, setOpen] = useState(false);
  const long = text.length > limit;
  const shown = !long || open ? text : text.slice(0, limit);
  return (
    <>
      <Highlighted text={shown} needles={needles} />
      {long && (
        <>
          {!open && <span className="faint">...</span>}{' '}
          <button type="button" className="linklike" onClick={() => setOpen(!open)} aria-expanded={open}>
            {open ? 'Show less' : `Show all (${text.length.toLocaleString('en-US')} characters)`}
          </button>
        </>
      )}
    </>
  );
}

export function Button({
  children,
  kind,
  icon,
  ...rest
}: { children?: ReactNode; kind?: 'primary' | 'danger' | 'ghost'; icon?: IconName } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type="button" {...rest} className={`btn${kind ? ` ${kind}` : ''}${rest.className ? ` ${rest.className}` : ''}`}>
      {icon && <Icon name={icon} />}
      {children}
    </button>
  );
}

// ---- states ----------------------------------------------------------------------------------

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="state" data-kind="empty">
      <div className="state-title">{title}</div>
      {children && <p>{children}</p>}
    </div>
  );
}

export function describeError(error: ApiError): string {
  if (error.status === 0) return `Could not reach the API: ${error.message}`;
  if (error.status === 403) return `Not permitted: ${error.message}.`;
  return `${error.status} from ${error.path.split('?')[0]}: ${error.message}`;
}

export function ErrorState({ what, error, onRetry }: { what: string; error: ApiError; onRetry?: () => void }) {
  return (
    <div className="state" data-kind="error" role="alert">
      <div className="state-title">
        <Icon name="warning" />
        Could not load {what}
      </div>
      <p>{describeError(error)}</p>
      {onRetry && error.status !== 403 && (
        <Button icon="refresh" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

/** One-line error above data that is still shown (a failed reload keeps the previous rows). */
export function ErrorNotice({ what, error, onRetry }: { what: string; error: ApiError; onRetry?: () => void }) {
  return (
    <div className="notice" data-kind="error" role="alert">
      <Icon name="warning" />
      <span>
        Could not refresh {what}. {describeError(error)} Showing the last loaded data.
      </span>
      {onRetry && (
        <Button icon="refresh" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function ModelOffline() {
  return (
    <div className="state" data-kind="offline" role="status">
      <div className="state-title">
        <Icon name="warning" />
        Model offline
      </div>
      <p>
        No model endpoint is configured on the API (SENTINEL_LLM_BASE_URL and SENTINEL_LLM_MODEL). Findings and Ask are
        unavailable; alerts, incidents and evidence are not affected.
      </p>
    </div>
  );
}

export function SkeletonLines({ lines = 4 }: { lines?: number }) {
  return (
    <div className="state" role="status" aria-busy="true" aria-label="Loading">
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="skeleton-bar" style={{ width: `${[60, 85, 40, 70][i % 4]}%`, minWidth: 120 }} />
      ))}
    </div>
  );
}

// ---- dialog ----------------------------------------------------------------------------------

/** Modal on the native <dialog>: focus is trapped by the browser, Esc closes, focus returns to the opener. */
export function Dialog({ title, onClose, children, footer }: { title: string; onClose: () => void; children: ReactNode; footer?: ReactNode }) {
  const ref = useRef<HTMLDialogElement | null>(null);
  useEffect(() => {
    const el = ref.current;
    if (el && !el.open) el.showModal();
  }, []);
  return (
    <dialog
      ref={ref}
      className="dialog"
      aria-label={title}
      onClose={onClose}
    >
      <div className="dialog-head">
        <h2>{title}</h2>
        <button type="button" className="btn ghost icon-only" onClick={() => ref.current?.close()} aria-label="Close">
          <Icon name="close" />
        </button>
      </div>
      <div className="dialog-body">{children}</div>
      {footer && <div className="dialog-foot">{footer}</div>}
    </dialog>
  );
}

// ---- error boundary ----------------------------------------------------------------------------

/** A screen that throws while rendering shows this instead of a blank page; the shell stays usable. */
export class ScreenBoundary extends Component<{ children: ReactNode; resetKey: string }, { error: Error | null; key: string }> {
  state = { error: null as Error | null, key: this.props.resetKey };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  static getDerivedStateFromProps(props: { resetKey: string }, state: { error: Error | null; key: string }) {
    return props.resetKey !== state.key ? { error: null, key: props.resetKey } : null;
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('screen failed to render', error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="state" data-kind="error" role="alert">
        <div className="state-title">
          <Icon name="warning" />
          This screen failed to render
        </div>
        <p>
          A console error stopped the screen: <span className="mono">{this.state.error.message}</span>. No data was changed. Other screens still work.
        </p>
        <Button icon="refresh" onClick={() => this.setState({ error: null })}>
          Try again
        </Button>
      </div>
    );
  }
}

// ---- page pattern (DESIGN.md 5): header, sections, tabs, KPI row ------------------------------

export interface Crumb {
  label: string;
  href?: string;
}

/**
 * The header of every screen: optional breadcrumb, the title, the one question the screen answers,
 * and the primary action on the right. `bar` is the slim variant above a split pane.
 */
export function PageHeader({ title, purpose, crumbs, actions, bar }: { title: ReactNode; purpose?: ReactNode; crumbs?: readonly Crumb[]; actions?: ReactNode; bar?: boolean }) {
  return (
    <header className={`page-header${bar ? ' bar' : ''}`}>
      {crumbs && crumbs.length > 0 && (
        <nav className="crumbs" aria-label="Breadcrumb">
          {crumbs.map((c, i) => (
            <span key={i}>
              {c.href ? <a href={c.href}>{c.label}</a> : c.label}
              {i < crumbs.length - 1 && <span aria-hidden="true"> /</span>}
            </span>
          ))}
        </nav>
      )}
      <h1>{title}</h1>
      {purpose && <p className="purpose">{purpose}</p>}
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

/** A scrolling page: max content width, the header, then sections. */
export function Page({ children, className, label }: { children: ReactNode; className?: string; label?: string }) {
  return (
    <div className={`page${className ? ` ${className}` : ''}`} aria-label={label}>
      <div className="page-inner">{children}</div>
    </div>
  );
}

/** A titled block of a page. `description` is one line; `actions` sit right of the title. */
export function Section({ id, title, description, actions, children, className }: { id?: string; title: ReactNode; description?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  const hid = id ? `${id}-t` : undefined;
  return (
    <section className={`sec${className ? ` ${className}` : ''}`} id={id} aria-labelledby={hid}>
      <div className="sec-head">
        <div>
          <h2 id={hid}>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        {actions && <div className="actions">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

export interface TabItem<T extends string> {
  id: T;
  label: ReactNode;
  count?: number | string;
}

/**
 * Tab list (WAI-ARIA tabs: roving tabindex, Left / Right / Home / End). The caller renders the panel
 * with `role="tabpanel"`, `id={`${idBase}-panel-${id}`}` and `aria-labelledby={`${idBase}-tab-${id}`}`.
 */
export function Tabs<T extends string>({ tabs, value, onChange, label, idBase, inset }: { tabs: readonly TabItem<T>[]; value: T; onChange: (id: T) => void; label: string; idBase: string; inset?: boolean }) {
  const onKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const i = tabs.findIndex((t) => t.id === value);
    const n = tabs.length;
    const to = e.key === 'ArrowRight' ? (i + 1) % n : e.key === 'ArrowLeft' ? (i - 1 + n) % n : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : -1;
    const next = tabs[to];
    if (!next) return;
    e.preventDefault();
    onChange(next.id);
    document.getElementById(`${idBase}-tab-${next.id}`)?.focus();
  };
  return (
    <div className={`tabs${inset ? ' inset' : ''}`} role="tablist" aria-label={label} onKeyDown={onKey}>
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          id={`${idBase}-tab-${t.id}`}
          aria-selected={t.id === value}
          aria-controls={`${idBase}-panel-${t.id}`}
          tabIndex={t.id === value ? 0 : -1}
          onClick={() => onChange(t.id)}
        >
          {t.label}
          {t.count !== undefined && <span className="count num">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

/** One cell of a `.kpi-row`: label, value, one line of context; a link when `href` is set. */
export function Kpi({ label, value, hint, href }: { label: ReactNode; value: ReactNode; hint?: ReactNode; href?: string }) {
  const body = (
    <>
      <span className="kpi-label">{label}</span>
      <span className="kpi-value num">{value}</span>
      {hint && <span className="kpi-hint">{hint}</span>}
    </>
  );
  return href ? (
    <a className="kpi" href={href}>
      {body}
    </a>
  ) : (
    <div className="kpi">{body}</div>
  );
}

/** Key facts as a definition grid (label over value). */
export function DefGrid({ items }: { items: readonly { label: ReactNode; value: ReactNode }[] }) {
  return (
    <dl className="def-grid">
      {items.map((it, i) => (
        <div key={i}>
          <dt>{it.label}</dt>
          <dd>{it.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Secondary detail behind a disclosure (native details: keyboard and find-in-page work). */
export function Disclosure({ summary, children, open, onToggle }: { summary: ReactNode; children: ReactNode; open?: boolean; onToggle?: (open: boolean) => void }) {
  return (
    <details className="disclosure" open={open} onToggle={onToggle ? (e) => onToggle(e.currentTarget.open) : undefined}>
      <summary>
        <Icon name="chevronRight" />
        {summary}
      </summary>
      {children}
    </details>
  );
}
