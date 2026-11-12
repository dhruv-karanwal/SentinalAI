// ATT&CK charts: the matrix heat strip (tactics as columns, techniques as cells with the count
// printed in each), the kill-chain strip (tactics in ATT&CK order, gaps as empty cells) and the
// tactic lanes of an incident (binned ticks per tactic on a shared time axis).

import { useMemo, useState, type KeyboardEvent } from 'react';

import { useElementSize } from '../hooks.ts';
import { fmtInt, fmtStep } from '../lib/format.ts';
import { compact, heatStep, linearScale, timeTicks } from '../lib/scale.ts';
import { useTip } from './ChartFrame.tsx';

export interface TechniqueCell {
  technique_id: string;
  name: string | null;
  alerts: number;
}

export interface TacticColumn {
  tactic: string;
  name: string;
  alerts: number;
  techniques: TechniqueCell[];
}

export function HeatStrip({ tactics, onPick, selected }: { tactics: TacticColumn[]; onPick?: (tid: string) => void; selected?: string | null }) {
  const tip = useTip();
  const max = Math.max(0, ...tactics.flatMap((t) => t.techniques.map((c) => c.alerts)));
  return (
    <div className="heat" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(0, 1fr))` }}>
      {tactics.map((t) => (
        <div key={t.tactic} className="heat-col">
          <div className="heat-head" title={t.name}>
            <span className="heat-name">{t.name}</span>
            <span className="faint num">{t.techniques.length ? fmtInt(t.alerts) : '-'}</span>
          </div>
          {t.techniques.length === 0 && <div className="heat-cell heat-none">none</div>}
          {t.techniques.map((c) => {
            const lines = [`${c.technique_id}${c.name ? ` ${c.name}` : ''}`, `${t.name}`, `${fmtInt(c.alerts)} alerts`];
            return (
              <button
                type="button"
                key={c.technique_id}
                className="heat-cell"
                data-step={heatStep(c.alerts, max)}
                aria-pressed={selected === c.technique_id}
                aria-label={lines.join(', ')}
                onClick={() => onPick?.(c.technique_id)}
                onPointerEnter={(e) => tip.show(e.currentTarget, lines)}
                onPointerLeave={() => tip.hide()}
                onFocus={(e) => tip.show(e.currentTarget, lines)}
                onBlur={() => tip.hide()}
              >
                <span className="mono">{c.technique_id}</span>
                <span className="num">{compact(c.alerts)}</span>
              </button>
            );
          })}
        </div>
      ))}
    </div>
  );
}

export interface Stage {
  tactic: string;
  name: string;
  alerts: number;
  techniques: TechniqueCell[];
  first_ts?: string | null;
  last_ts?: string | null;
}

export function ChainStrip({ stages }: { stages: Stage[] }) {
  const tip = useTip();
  return (
    <ol className="chain">
      {stages.map((s, i) => {
        const lines = s.alerts
          ? [s.name, `${fmtInt(s.alerts)} alerts`, ...s.techniques.slice(0, 4).map((t) => `${t.technique_id}${t.name ? ` ${t.name}` : ''}: ${fmtInt(t.alerts)}`), s.first_ts ? `${s.first_ts} to ${s.last_ts}` : '']
          : [s.name, 'no mapped alert (gap)'];
        return (
          <li
            key={s.tactic}
            className="chain-cell"
            data-empty={s.alerts === 0 || undefined}
            tabIndex={0}
            aria-label={lines.filter(Boolean).join(', ')}
            onPointerEnter={(e) => tip.show(e.currentTarget, lines.filter(Boolean))}
            onPointerLeave={() => tip.hide()}
            onFocus={(e) => tip.show(e.currentTarget, lines.filter(Boolean))}
            onBlur={() => tip.hide()}
          >
            <span className="chain-step faint num">{i + 1}</span>
            <span className="chain-name">{s.name}</span>
            <span className="chain-count num">{s.alerts ? compact(s.alerts) : 'gap'}</span>
          </li>
        );
      })}
    </ol>
  );
}

export interface Lane {
  tactic: string;
  name: string;
  bins: Array<[number, number]>;
}

const LM = { left: 150, right: 10, top: 4, bottom: 24 };
const LANE = 20;

export function Lanes({ lanes, bins, start, binSeconds, onPick }: { lanes: Lane[]; bins: number; start: number; binSeconds: number; onPick?: (from: number, to: number) => void }) {
  const [ref, size] = useElementSize<HTMLDivElement>();
  const tip = useTip();
  const [cursor, setCursor] = useState<{ lane: number; bin: number } | null>(null);
  const width = Math.max(240, size.width);
  const plotW = width - LM.left - LM.right;
  const height = LM.top + lanes.length * LANE + LM.bottom;
  const step = plotW / Math.max(1, bins);
  const max = Math.max(1, ...lanes.flatMap((l) => l.bins.map(([, c]) => c)));
  const end = start + bins * binSeconds;
  const x = linearScale([start, end], [LM.left, LM.left + plotW]);
  const xt = timeTicks(start, end, Math.max(2, Math.floor(plotW / 120)));
  const h = (c: number) => 3 + (LANE - 8) * (Math.log10(1 + c) / Math.log10(1 + max));
  const lookup = useMemo(() => lanes.map((l) => new Map(l.bins)), [lanes]);
  const lines = (li: number, b: number): string[] => {
    const t = start + b * binSeconds;
    return [lanes[li]!.name, `${new Date(t * 1000).toISOString().replace('.000Z', 'Z')} + ${fmtStep(binSeconds)}`, `${fmtInt(lookup[li]!.get(b) ?? 0)} alerts`];
  };
  const onKey = (e: KeyboardEvent<SVGSVGElement>) => {
    if (lanes.length === 0) return;
    const c = cursor ?? { lane: 0, bin: lanes[0]!.bins[0]?.[0] ?? 0 };
    let next = c;
    const nonEmpty = (li: number) => lanes[li]!.bins.map(([b]) => b);
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      const list = nonEmpty(c.lane);
      const idx = list.findIndex((b) => (e.key === 'ArrowRight' ? b > c.bin : false));
      const prev = [...list].reverse().find((b) => b < c.bin);
      next = { lane: c.lane, bin: e.key === 'ArrowRight' ? (idx >= 0 ? list[idx]! : c.bin) : prev ?? c.bin };
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      const lane = Math.max(0, Math.min(lanes.length - 1, c.lane + (e.key === 'ArrowDown' ? 1 : -1)));
      next = { lane, bin: nonEmpty(lane)[0] ?? 0 };
    } else if (e.key === 'Enter' && onPick) {
      onPick(start + c.bin * binSeconds, start + (c.bin + 1) * binSeconds);
      e.preventDefault();
      return;
    } else return;
    e.preventDefault();
    setCursor(next);
    const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
    tip.show({ x: r.left + LM.left + (next.bin + 0.5) * step, y: r.top + LM.top + next.lane * LANE + 2 }, lines(next.lane, next.bin));
  };
  return (
    <div ref={ref} className="chart-plot">
      <svg width={width} height={height} className="chart-svg" role="group" tabIndex={0} aria-label="ATT&CK tactic lanes. Arrow keys move between alert bins, Enter filters the alerts to that bin." onKeyDown={onKey} onBlur={() => tip.hide()}>
        {lanes.map((l, li) => {
          const y0 = LM.top + li * LANE;
          return (
            <g key={l.tactic}>
              <line x1={LM.left} x2={LM.left + plotW} y1={y0 + LANE - 2} y2={y0 + LANE - 2} stroke="var(--grid)" />
              <text x={LM.left - 8} y={y0 + LANE - 6} textAnchor="end" className="axis-text">
                {l.name}
              </text>
              {l.bins.map(([b, c]) => {
                const hh = h(c);
                return (
                  <rect
                    key={b}
                    x={LM.left + b * step}
                    width={Math.max(1.5, step - 0.5)}
                    y={y0 + LANE - 2 - hh}
                    height={hh}
                    fill="var(--accent)"
                    onPointerEnter={(e) => tip.show(e.currentTarget, lines(li, b))}
                    onPointerLeave={() => tip.hide()}
                    onClick={() => onPick?.(start + b * binSeconds, start + (b + 1) * binSeconds)}
                    style={{ cursor: onPick ? 'pointer' : undefined }}
                  />
                );
              })}
            </g>
          );
        })}
        {cursor && (
          <rect x={LM.left + cursor.bin * step - 1} width={Math.max(3, step + 1)} y={LM.top + cursor.lane * LANE} height={LANE - 1} fill="none" stroke="var(--text)" pointerEvents="none" />
        )}
        <line x1={LM.left} x2={LM.left + plotW} y1={height - LM.bottom} y2={height - LM.bottom} stroke="var(--border-strong)" />
        {xt.map((t) => (
          <text key={t.t} x={x(t.t)} y={height - 8} textAnchor="middle" className="axis-text">
            {t.label}
          </text>
        ))}
      </svg>
      <div className="axis-caption faint">UTC time · tick height = alerts per {fmtStep(binSeconds)} (log scale, max {fmtInt(max)})</div>
    </div>
  );
}
