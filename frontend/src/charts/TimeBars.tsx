// Alerts over time: bars per time bin, stacked by detector (linear or log1p axis), incident-start
// markers under the time axis, brush to select a time range. Bins come from the API (no raw
// records). Keyboard: the plot is one tab stop; Left / Right move a cursor bin and show its
// values, Shift extends a selection, Enter applies it, Esc clears it.

import { useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react';

import { detectorName } from '../components/ui.tsx';
import { useElementSize } from '../hooks.ts';
import { fmtInt, fmtStep } from '../lib/format.ts';
import { bandRange, compact, linearScale, logScale, niceMax, timeTicks } from '../lib/scale.ts';
import { DETECTOR_ORDER, TONE_VAR, detectorTone, useTip, type Tone } from './ChartFrame.tsx';

export interface Marker {
  t: number;
  severity: string;
  label: string;
}

interface Props {
  series: Record<string, number[]>;
  /** epoch seconds of bin 0 */
  start: number;
  binSeconds: number;
  log?: boolean;
  height?: number;
  markers?: Marker[];
  /** selected bin range (inclusive) */
  selection?: [number, number] | null;
  onSelect?: (bins: [number, number] | null) => void;
  onMarker?: (m: Marker) => void;
  label: string;
  /** colours and names for series that are not detectors (audit actions) */
  tones?: Record<string, Tone>;
  names?: Record<string, string>;
}

const M = { left: 52, right: 10, top: 8, bottom: 34 };

export function TimeBars({ series, start, binSeconds, log = false, height = 180, markers = [], selection = null, onSelect, onMarker, label, tones, names }: Props) {
  const [ref, size] = useElementSize<HTMLDivElement>();
  const tip = useTip();
  const [cursor, setCursor] = useState<number | null>(null);
  const [anchor, setAnchor] = useState<number | null>(null);
  const [drag, setDrag] = useState<[number, number] | null>(null);
  const plotRef = useRef<SVGSVGElement | null>(null);

  const dets = useMemo(() => [...DETECTOR_ORDER.filter((d) => d in series), ...Object.keys(series).filter((d) => !DETECTOR_ORDER.includes(d)).sort()], [series]);
  const n = Math.max(0, ...dets.map((d) => series[d]!.length));
  const totals = useMemo(() => Array.from({ length: n }, (_, i) => dets.reduce((s, d) => s + (series[d]![i] ?? 0), 0)), [series, dets, n]);
  const peak = Math.max(0, ...totals);
  const width = Math.max(200, size.width);
  const plotW = width - M.left - M.right;
  const plotH = height - M.top - M.bottom;
  const step = n > 0 ? plotW / n : plotW;
  const y = log ? logScale([0, peak], [M.top + plotH, M.top]) : linearScale([0, niceMax(peak)], [M.top + plotH, M.top]);
  const yTicks = log ? y.ticks() : y.ticks(4);
  const end = start + n * binSeconds;
  const x = linearScale([start, end], [M.left, M.left + plotW]);
  const xTicks = timeTicks(start, end, Math.max(2, Math.floor(plotW / 110)));
  const sel = drag ?? selection;

  const binAt = (clientX: number): number => {
    const r = plotRef.current?.getBoundingClientRect();
    if (!r || n === 0) return 0;
    return bandRange(clientX - r.left, clientX - r.left, M.left, step, n)[0];
  };
  const binLines = (i: number): string[] => {
    const t = start + i * binSeconds;
    return [
      `${new Date(t * 1000).toISOString().replace('.000Z', 'Z')} + ${fmtStep(binSeconds)}`,
      `${fmtInt(totals[i] ?? 0)} alerts`,
      ...dets.map((d) => `${names?.[d] ?? detectorName(d)}: ${fmtInt(series[d]![i] ?? 0)}`),
    ];
  };
  const showBin = (i: number) => {
    const r = plotRef.current?.getBoundingClientRect();
    if (!r) return;
    tip.show({ x: r.left + M.left + (i + 0.5) * step, y: r.top + y(totals[i] ?? 0) }, binLines(i));
  };

  const onPointerDown = (e: PointerEvent<SVGSVGElement>) => {
    if (!onSelect || e.button !== 0) return;
    const b = binAt(e.clientX);
    (e.target as Element).setPointerCapture?.(e.pointerId);
    setDrag([b, b]);
  };
  const onPointerMove = (e: PointerEvent<SVGSVGElement>) => {
    const b = binAt(e.clientX);
    if (drag) setDrag([drag[0], b]);
    showBin(b);
  };
  const onPointerUp = () => {
    if (!drag || !onSelect) return;
    const [a, b] = drag;
    setDrag(null);
    onSelect([Math.min(a, b), Math.max(a, b)]);
  };
  const onKey = (e: KeyboardEvent<SVGSVGElement>) => {
    if (n === 0) return;
    const cur = cursor ?? 0;
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      const next = Math.max(0, Math.min(n - 1, cur + (e.key === 'ArrowRight' ? 1 : -1) * (e.altKey ? 10 : 1)));
      if (e.shiftKey) {
        const a = anchor ?? cur;
        setAnchor(a);
        setDrag([Math.min(a, next), Math.max(a, next)]);
      } else {
        setAnchor(null);
        setDrag(null);
      }
      setCursor(next);
      showBin(next);
      e.preventDefault();
    } else if (e.key === 'Enter' && onSelect) {
      onSelect(drag ? [Math.min(...drag), Math.max(...drag)] : [cur, cur]);
      setDrag(null);
      setAnchor(null);
      e.preventDefault();
    } else if (e.key === 'Escape' && onSelect && (selection || drag)) {
      setDrag(null);
      setAnchor(null);
      onSelect(null);
      e.preventDefault();
      e.stopPropagation();
    }
  };

  return (
    <div ref={ref} className="chart-plot">
      <svg
        ref={plotRef}
        width={width}
        height={height}
        role="group"
        aria-label={`${label}. Left and Right arrows read the bins${onSelect ? ', Shift selects a range, Enter filters the table, Escape clears' : ''}.`}
        tabIndex={0}
        className="chart-svg"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={() => tip.hide()}
        onKeyDown={onKey}
        onBlur={() => tip.hide()}
        style={{ cursor: onSelect ? 'crosshair' : undefined }}
      >
        {yTicks.map((t) => (
          <g key={`y${t}`}>
            <line x1={M.left} x2={M.left + plotW} y1={y(t)} y2={y(t)} stroke="var(--grid)" />
            <text x={M.left - 6} y={y(t) + 4} textAnchor="end" className="axis-text">
              {compact(t)}
            </text>
          </g>
        ))}
        <text x={12} y={M.top + plotH / 2} transform={`rotate(-90 12 ${M.top + plotH / 2})`} textAnchor="middle" className="axis-text">
          {`alerts per ${fmtStep(binSeconds)}${log ? ' (log)' : ''}`}
        </text>
        {totals.map((_, i) => {
          let acc = 0;
          return (
            <g key={i}>
              {dets.map((d) => {
                const v = series[d]![i] ?? 0;
                if (!v) return null;
                const y0 = y(acc);
                acc += v;
                const y1 = y(acc);
                return <rect key={d} x={M.left + i * step + (step > 3 ? 0.5 : 0)} width={Math.max(0.6, step - (step > 3 ? 1 : 0))} y={y1} height={Math.max(0.5, y0 - y1)} fill={TONE_VAR[tones?.[d] ?? detectorTone(d)]} />;
              })}
            </g>
          );
        })}
        {sel && n > 0 && (
          <rect
            x={M.left + Math.min(...sel) * step}
            width={(Math.abs(sel[1] - sel[0]) + 1) * step}
            y={M.top}
            height={plotH}
            fill="var(--accent)"
            fillOpacity={0.12}
            stroke="var(--accent)"
            strokeWidth={1}
            pointerEvents="none"
          />
        )}
        {cursor !== null && n > 0 && <rect x={M.left + cursor * step} width={Math.max(1, step)} y={M.top} height={plotH} fill="none" stroke="var(--text)" strokeWidth={1} pointerEvents="none" />}
        <line x1={M.left} x2={M.left + plotW} y1={M.top + plotH} y2={M.top + plotH} stroke="var(--border-strong)" />
        {xTicks.map((t) => (
          <g key={`x${t.t}`}>
            <line x1={x(t.t)} x2={x(t.t)} y1={M.top + plotH} y2={M.top + plotH + 4} stroke="var(--border-strong)" />
            <text x={x(t.t)} y={height - 6} textAnchor="middle" className="axis-text">
              {t.label}
            </text>
          </g>
        ))}
        {markers.map((m, i) => {
          const mx = x(m.t);
          const high = m.severity === 'High';
          const my = M.top + plotH + 6;
          return (
            <path
              key={i}
              d={`M${mx} ${my}l-4 7h8z`}
              fill={high ? 'var(--sev-high)' : 'none'}
              stroke={high ? 'var(--sev-high)' : 'var(--sev-medium)'}
              strokeWidth={1.2}
              className="marker"
              onPointerEnter={(e) => tip.show(e.currentTarget, [`${m.severity} incident starts`, m.label, new Date(m.t * 1000).toISOString().replace('.000Z', 'Z')])}
              onPointerLeave={() => tip.hide()}
              onPointerDown={(e) => e.stopPropagation()}
              onClick={() => onMarker?.(m)}
            />
          );
        })}
      </svg>
      <div className="axis-caption faint">
        UTC time{markers.length > 0 ? ' · triangles under the axis: incident starts (filled = High, outline = Medium)' : ''}
      </div>
    </div>
  );
}
