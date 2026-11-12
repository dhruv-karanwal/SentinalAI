// Frame shared by every chart (DESIGN.md 11.3): title, the decision the chart supports, legend,
// a tooltip with exact values (text nodes only, so log and rule text stays escaped), and a
// visually hidden table with the same numbers as the text alternative.

import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';

import { Explain, Term } from '../components/Term.tsx';

export type Tone = 'wazuh' | 'suricata' | 'aminer' | 'sigma' | 'high' | 'medium' | 'low' | 'accent' | 'ref' | 'muted';

export const TONE_VAR: Record<Tone, string> = {
  wazuh: 'var(--det-wazuh)',
  suricata: 'var(--det-suricata)',
  aminer: 'var(--det-aminer)',
  sigma: 'var(--det-sigma)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  accent: 'var(--accent)',
  ref: 'var(--ref)',
  muted: 'var(--text-faint)',
};

/** Dash patterns that tell detectors apart without colour (graph edges, legend marks). */
export const DETECTOR_DASH: Record<string, string | undefined> = { wazuh: undefined, suricata: '4 2', aminer: '1 2', sigma: '6 2 1 2' };
export const DETECTOR_ORDER = ['wazuh', 'suricata', 'aminer', 'sigma'];

export function detectorTone(det: string): Tone {
  return (DETECTOR_ORDER.includes(det) ? det : 'muted') as Tone;
}

export function sevTone(sev: string | null | undefined): Tone {
  const v = (sev ?? '').toLowerCase();
  return v === 'high' ? 'high' : v === 'medium' ? 'medium' : v === 'low' ? 'low' : 'muted';
}

export interface LegendItem {
  key: string;
  label: string;
  tone: Tone;
  /** 'bar' (filled square), 'line' (with the detector dash), 'ref' (dashed rule), 'dot', 'hollow' */
  mark?: 'bar' | 'line' | 'ref' | 'dot' | 'hollow' | 'square';
  dash?: string;
  value?: string;
}

export interface TableSpec {
  columns: string[];
  rows: Array<Array<string | number>>;
}

interface Tip {
  x: number;
  y: number;
  lines: string[];
}

interface TipApi {
  show: (target: Element | { x: number; y: number }, lines: string[]) => void;
  hide: () => void;
}

const TipContext = createContext<TipApi | null>(null);

/** Charts inside a frame call this to show exact values on hover and on keyboard focus. */
export function useTip(): TipApi {
  return useContext(TipContext) ?? { show: () => undefined, hide: () => undefined };
}

export function Legend({ items }: { items: LegendItem[] }) {
  if (items.length === 0) return null;
  return (
    <ul className="chart-legend" aria-label="Legend">
      {items.map((it) => (
        <li key={it.key}>
          <LegendMark item={it} />
          <span>{it.label}</span>
          {it.value && <span className="faint num">{it.value}</span>}
        </li>
      ))}
    </ul>
  );
}

function LegendMark({ item }: { item: LegendItem }) {
  const colour = TONE_VAR[item.tone];
  const mark = item.mark ?? 'bar';
  return (
    <svg width="18" height="10" viewBox="0 0 18 10" aria-hidden="true" focusable="false">
      {mark === 'bar' && <rect x="2" y="1" width="12" height="8" fill={colour} />}
      {mark === 'square' && <rect x="5" y="1" width="8" height="8" fill={colour} />}
      {mark === 'dot' && <circle cx="9" cy="5" r="4" fill={colour} />}
      {mark === 'hollow' && <circle cx="9" cy="5" r="3.5" fill="none" stroke={colour} strokeWidth="1.5" />}
      {(mark === 'line' || mark === 'ref') && (
        <line x1="1" y1="5" x2="17" y2="5" stroke={colour} strokeWidth={mark === 'ref' ? 1.5 : 2.5} strokeDasharray={item.dash ?? (mark === 'ref' ? '3 2' : undefined)} />
      )}
    </svg>
  );
}

export function HiddenTable({ caption, table }: { caption: string; table: TableSpec }) {
  return (
    <table className="visually-hidden">
      <caption>{caption}</caption>
      <thead>
        <tr>
          {table.columns.map((c) => (
            <th key={c} scope="col">
              {c}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {table.rows.map((r, i) => (
          <tr key={i}>
            {r.map((c, j) => (j === 0 ? <th key={j} scope="row">{String(c)}</th> : <td key={j}>{String(c)}</td>))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

interface FrameProps {
  title: string;
  /** the decision the chart supports, one line */
  question: string;
  legend?: LegendItem[];
  table: TableSpec;
  actions?: ReactNode;
  note?: ReactNode;
  children: ReactNode;
  /** shown instead of the chart when there is nothing to draw */
  empty?: ReactNode;
  className?: string;
  id?: string;
  /** glossary id: a "?" after the title */
  term?: string;
  /** plain-language pair shown instead of the question line (explainable console) */
  what?: ReactNode;
  why?: ReactNode;
}

export function ChartFrame({ title, question, legend = [], table, actions, note, children, empty, className, id, term, what, why }: FrameProps) {
  const ref = useRef<HTMLElement | null>(null);
  const [tip, setTip] = useState<Tip | null>(null);
  const show = useCallback((target: Element | { x: number; y: number }, lines: string[]) => {
    const host = ref.current?.getBoundingClientRect();
    if (!host) return;
    if (target instanceof Element) {
      const r = target.getBoundingClientRect();
      setTip({ x: r.left + r.width / 2 - host.left, y: r.top - host.top, lines });
    } else {
      setTip({ x: target.x - host.left, y: target.y - host.top, lines });
    }
  }, []);
  const hide = useCallback(() => setTip(null), []);
  const api = useMemo(() => ({ show, hide }), [show, hide]);
  const width = ref.current?.clientWidth ?? 0;
  return (
    <section className={`chart${className ? ` ${className}` : ''}`} ref={ref} aria-labelledby={id ? `${id}-t` : undefined} id={id}>
      <header className="chart-head">
        <div>
          <h3 className="chart-title" id={id ? `${id}-t` : undefined}>
            {term ? <Term id={term}>{title}</Term> : title}
          </h3>
          {what || why ? <Explain what={what ?? question} why={why ?? ''} /> : <p className="chart-q">{question}</p>}
        </div>
        {actions && <div className="chart-actions">{actions}</div>}
      </header>
      {empty ? (
        <div className="chart-empty">{empty}</div>
      ) : (
        <>
          <Legend items={legend} />
          <TipContext.Provider value={api}>
            <div className="chart-body">{children}</div>
          </TipContext.Provider>
          <HiddenTable caption={title} table={table} />
        </>
      )}
      {note && <p className="chart-note">{note}</p>}
      {tip && (
        <div
          className="chart-tip"
          role="status"
          style={{ left: Math.max(8, Math.min(tip.x, width - 8)), top: tip.y, transform: `translate(${tip.x > width - 160 ? '-100%' : tip.x < 160 ? '0' : '-50%'}, calc(-100% - 6px))` }}
        >
          {tip.lines.map((l, i) => (
            <div key={i} className={i === 0 ? 'chart-tip-head' : undefined}>
              {l}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
