// Bar charts drawn as HTML + inline SVG marks (labels stay real text, rows are buttons):
// horizontal bars with direct labels and optional reference lines, stacked horizontal bars,
// paired before / after dots, and the tiny inline bar used in facet lists.

import type { ReactNode } from 'react';

import { SeverityGlyph } from '../icons.tsx';
import { fmtInt } from '../lib/format.ts';
import { fmtPct, linearScale, niceMax } from '../lib/scale.ts';
import { TONE_VAR, useTip, type Tone } from './ChartFrame.tsx';

export interface RefLine {
  key: string;
  label: string;
  value: number;
  dash: string;
}

export interface HBarRow {
  key: string;
  label: ReactNode;
  /** plain text for the tooltip and the accessible name */
  text: string;
  value: number;
  /** display of the value (defaults to the integer) */
  display?: string;
  tone: Tone;
  /** severity glyph next to the label (never colour alone) */
  sev?: 0 | 1 | 2 | 3;
  detail?: string[];
  refs?: RefLine[];
  onActivate?: () => void;
}

export function HBars({ rows, max, unit, pct = false }: { rows: HBarRow[]; max?: number; unit: string; pct?: boolean }) {
  const tip = useTip();
  const top = max ?? niceMax(Math.max(0, ...rows.map((r) => r.value), ...rows.flatMap((r) => (r.refs ?? []).map((f) => f.value))));
  const x = linearScale([0, top || 1], [0, 100]);
  return (
    <div className="hbars" role="list">
      {rows.map((r) => {
        const lines = [r.text, `${r.display ?? (pct ? fmtPct(r.value) : fmtInt(r.value))} ${unit}`, ...(r.detail ?? []), ...(r.refs ?? []).map((f) => `${f.label}: ${pct ? fmtPct(f.value) : fmtInt(f.value)}`)];
        const body = (
          <>
            <span className="hbar-label">
              {r.sev ? (
                <span className="sev" data-sev={['', 'low', 'medium', 'high'][r.sev]}>
                  <SeverityGlyph level={r.sev} />
                </span>
              ) : null}
              {r.label}
            </span>
            <span className="hbar-track" aria-hidden="true">
              <span className="hbar-fill" style={{ width: `${Math.max(r.value > 0 ? 0.5 : 0, x(r.value))}%`, background: TONE_VAR[r.tone] }} />
              {(r.refs ?? []).map((f) => (
                <svg key={f.key} className="hbar-ref" style={{ left: `${x(f.value)}%` }} width="2" height="100%" preserveAspectRatio="none" viewBox="0 0 2 10">
                  <line x1="1" y1="0" x2="1" y2="10" stroke="var(--ref)" strokeWidth="2" strokeDasharray={f.dash} vectorEffect="non-scaling-stroke" />
                </svg>
              ))}
            </span>
            <span className="hbar-value num">{r.display ?? (pct ? fmtPct(r.value) : fmtInt(r.value))}</span>
          </>
        );
        const events = {
          onPointerEnter: (e: React.PointerEvent<HTMLElement>) => tip.show(e.currentTarget, lines),
          onPointerLeave: () => tip.hide(),
          onFocus: (e: React.FocusEvent<HTMLElement>) => tip.show(e.currentTarget, lines),
          onBlur: () => tip.hide(),
        };
        return (
          <div role="listitem" key={r.key}>
            {r.onActivate ? (
              <button type="button" className="hbar" onClick={r.onActivate} aria-label={lines.join(', ')} {...events}>
                {body}
              </button>
            ) : (
              <div className="hbar" tabIndex={0} aria-label={lines.join(', ')} {...events}>
                {body}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export interface Segment {
  key: string;
  label: string;
  value: number;
  tone: Tone;
  /** hatched (for e.g. "closed"), so segments differ without colour */
  pattern?: 'solid' | 'hatch' | 'outline';
}

export function StackedHBars({ rows, unit }: { rows: Array<{ key: string; label: ReactNode; text: string; segments: Segment[]; onActivate?: () => void }>; unit: string }) {
  const tip = useTip();
  const top = niceMax(Math.max(0, ...rows.map((r) => r.segments.reduce((s, g) => s + g.value, 0))));
  return (
    <div className="hbars" role="list">
      {rows.map((r) => {
        const total = r.segments.reduce((s, g) => s + g.value, 0);
        const lines = [r.text, `${fmtInt(total)} ${unit}`, ...r.segments.map((g) => `${g.label}: ${fmtInt(g.value)}`)];
        let acc = 0;
        return (
          <div role="listitem" key={r.key}>
            <button
              type="button"
              className="hbar"
              disabled={!r.onActivate}
              onClick={r.onActivate}
              aria-label={lines.join(', ')}
              onPointerEnter={(e) => tip.show(e.currentTarget, lines)}
              onPointerLeave={() => tip.hide()}
              onFocus={(e) => tip.show(e.currentTarget, lines)}
              onBlur={() => tip.hide()}
            >
              <span className="hbar-label">{r.label}</span>
              <span className="hbar-track" aria-hidden="true">
                {r.segments.map((g) => {
                  const left = (acc / top) * 100;
                  acc += g.value;
                  if (!g.value) return null;
                  return (
                    <span
                      key={g.key}
                      className="hbar-seg"
                      data-pattern={g.pattern ?? 'solid'}
                      style={{ left: `${left}%`, width: `${(g.value / top) * 100}%`, ['--seg' as string]: TONE_VAR[g.tone] }}
                    />
                  );
                })}
              </span>
              <span className="hbar-value num">{fmtInt(total)}</span>
            </button>
          </div>
        );
      })}
    </div>
  );
}

/** Paired dots on a 0-100 % axis: hollow = before, filled = after (e.g. the verifier). */
export function DotPairs({ rows, beforeLabel, afterLabel }: { rows: Array<{ key: string; label: string; before: number | null; after: number | null }>; beforeLabel: string; afterLabel: string }) {
  const tip = useTip();
  const W = 100;
  return (
    <div className="dotpairs" role="list">
      {rows.map((r) => {
        const lines = [r.label, `${beforeLabel}: ${fmtPct(r.before)}`, `${afterLabel}: ${fmtPct(r.after)}`];
        return (
          <div
            role="listitem"
            key={r.key}
            className="dotpair"
            tabIndex={0}
            aria-label={lines.join(', ')}
            onPointerEnter={(e) => tip.show(e.currentTarget, lines)}
            onPointerLeave={() => tip.hide()}
            onFocus={(e) => tip.show(e.currentTarget, lines)}
            onBlur={() => tip.hide()}
          >
            <span className="hbar-label">{r.label}</span>
            <svg viewBox={`0 0 ${W} 10`} preserveAspectRatio="none" className="dotpair-svg" aria-hidden="true">
              <line x1="0" x2={W} y1="5" y2="5" stroke="var(--grid)" vectorEffect="non-scaling-stroke" />
              {r.before !== null && r.after !== null && <line x1={r.before * W} x2={r.after * W} y1="5" y2="5" stroke="var(--text-faint)" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />}
            </svg>
            <span className="dotpair-marks" aria-hidden="true">
              {r.before !== null && <span className="dot hollow" style={{ left: `${r.before * 100}%` }} />}
              {r.after !== null && <span className="dot filled" style={{ left: `${r.after * 100}%` }} />}
            </span>
            <span className="hbar-value num">
              {fmtPct(r.before, 0)} → {fmtPct(r.after, 0)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/** Tiny inline bar for facet lists: share of the largest value, with the count printed next to it. */
export function MiniBar({ value, max, tone = 'accent' }: { value: number; max: number; tone?: Tone }) {
  return (
    <span className="minibar" aria-hidden="true">
      <span style={{ width: `${max > 0 ? Math.max(2, (value / max) * 100) : 0}%`, background: TONE_VAR[tone] }} />
    </span>
  );
}
