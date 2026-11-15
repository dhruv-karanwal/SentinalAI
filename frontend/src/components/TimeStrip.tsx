// Time-axis strip: one row per detector, alerts binned per pixel column, bar height = count on
// a log scale. One canvas pass over the bins, so an 11,208-alert burst costs the same as 20
// alerts. A hidden table carries the same counts for screen readers.

import { useEffect, useMemo, useRef, useState } from 'react';

import { useApp, useElementSize } from '../hooks.ts';
import { barHeight, binRange, binTicks, type Tick } from '../lib/bins.ts';
import { fmtDuration, fmtInt, isoUtc } from '../lib/format.ts';
import { Button, DetectorTag, detectorName } from './ui.tsx';

const ROW = 22;
const BAR = 16;
const COL = 3; // pixels per bin
const ORDER = ['wazuh', 'suricata', 'aminer', 'sigma'];

export interface TimeRange {
  from: number;
  to: number;
}

interface Props {
  ticks: readonly Tick[];
  /** epoch seconds */
  t0: number;
  t1: number;
  selection: TimeRange | null;
  onSelect: (range: TimeRange | null) => void;
}

export function TimeStrip({ ticks, t0, t1, selection, onSelect }: Props) {
  const { theme } = useApp();
  const [plotRef, size] = useElementSize<HTMLDivElement>();
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [cursor, setCursor] = useState<number | null>(null);
  const [anchor, setAnchor] = useState<number | null>(null);
  const drag = useRef<number | null>(null);

  const detectors = useMemo(() => {
    const present = new Set(ticks.map((t) => t.detector));
    return [...ORDER.filter((d) => present.has(d)), ...[...present].filter((d) => !ORDER.includes(d)).sort()];
  }, [ticks]);

  const bins = Math.max(1, Math.floor(size.width / COL));
  const binned = useMemo(() => binTicks(ticks, t0, t1, bins, detectors), [ticks, t0, t1, bins, detectors]);
  const totals = useMemo(() => {
    const m = new Map<string, number>();
    for (const t of ticks) m.set(t.detector, (m.get(t.detector) ?? 0) + 1);
    return m;
  }, [ticks]);
  const height = Math.max(1, detectors.length) * ROW;
  const span = Math.max(0, t1 - t0);
  const binSeconds = span / bins;

  const selBins = useMemo(() => {
    if (!selection || span <= 0) return null;
    const a = Math.floor(((selection.from - t0) / span) * bins);
    const b = Math.ceil(((selection.to - t0) / span) * bins) - 1;
    return { a: Math.max(0, a), b: Math.min(bins - 1, Math.max(a, b)) };
  }, [selection, span, t0, bins]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || size.width <= 0) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(size.width * dpr);
    canvas.height = Math.round(height * dpr);
    canvas.style.height = `${height}px`;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, size.width, height);
    const css = getComputedStyle(document.documentElement);
    const token = (name: string) => css.getPropertyValue(name).trim();

    if (selBins) {
      ctx.fillStyle = token('--selected');
      ctx.fillRect(selBins.a * COL, 0, (selBins.b - selBins.a + 1) * COL, height);
    }
    detectors.forEach((det, r) => {
      const base = r * ROW + ROW - 3;
      ctx.fillStyle = token('--border');
      ctx.fillRect(0, base, size.width, 1);
      const row = binned.rows.get(det);
      if (!row) return;
      const color = token(`--det-${det}`) || token('--text-muted');
      ctx.fillStyle = color;
      ctx.strokeStyle = color;
      ctx.lineWidth = 1;
      for (let i = 0; i < row.length; i++) {
        const n = row[i]!;
        if (n === 0) continue;
        const h = barHeight(n, binned.max, BAR);
        const w = COL - 1;
        if (det === 'sigma') ctx.strokeRect(i * COL + 0.5, base - h + 0.5, Math.max(1, w - 1), h - 1);
        else ctx.fillRect(i * COL, base - h, w, h);
      }
    });
    if (cursor !== null) {
      ctx.fillStyle = token('--accent');
      ctx.fillRect(cursor * COL, 0, 1, height);
      ctx.fillRect(cursor * COL + COL - 1, 0, 1, height);
    }
  }, [binned, detectors, size.width, height, theme, selBins, cursor]);

  const binAt = (clientX: number): number => {
    const box = plotRef.current?.getBoundingClientRect();
    if (!box) return 0;
    return Math.min(bins - 1, Math.max(0, Math.floor((clientX - box.left) / COL)));
  };

  const select = (a: number, b: number) => onSelect(binRange(a, b, binned));

  const onKeyDown = (e: React.KeyboardEvent) => {
    const step = e.ctrlKey ? 10 : 1;
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      const cur = cursor ?? (e.key === 'ArrowRight' ? -1 : bins);
      const next = Math.min(bins - 1, Math.max(0, cur + (e.key === 'ArrowRight' ? step : -step)));
      if (e.shiftKey) {
        const start = anchor ?? cursor ?? next;
        setAnchor(start);
        select(start, next);
      } else {
        setAnchor(null);
      }
      setCursor(next);
    } else if (e.key === 'Enter' || e.key === ' ') {
      if (cursor !== null) select(anchor ?? cursor, cursor);
    } else if (e.key === 'Escape') {
      if (selection) {
        onSelect(null);
        e.stopPropagation();
      }
      setAnchor(null);
      setCursor(null);
    } else return;
    e.preventDefault();
  };

  const cursorText = (() => {
    if (cursor === null) return null;
    const r = binRange(cursor, cursor, binned);
    const parts = detectors.map((d) => `${detectorName(d)} ${fmtInt(binned.rows.get(d)?.[cursor] ?? 0)}`);
    return `${isoUtc(r.from * 1000)}: ${parts.join(', ')}`;
  })();

  // screen-reader table: at most 24 buckets of the same counts
  const buckets = Math.min(24, bins);
  const coarse = useMemo(() => binTicks(ticks, t0, t1, buckets, detectors), [ticks, t0, t1, buckets, detectors]);

  return (
    <div className="ts">
      <div className="ts-grid">
        <div className="ts-labels">
          {detectors.map((d) => (
            <div key={d} style={{ height: ROW }}>
              <DetectorTag value={d} />
              <span className="num">{fmtInt(totals.get(d) ?? 0)}</span>
            </div>
          ))}
        </div>
        <div
          ref={plotRef}
          className="ts-plot"
          tabIndex={0}
          role="group"
          aria-label={`Alerts over time, ${fmtInt(ticks.length)} alerts in ${fmtDuration(span)}. Left and right arrows move, Shift extends a range, Enter filters the alert table, Escape clears.`}
          onKeyDown={onKeyDown}
          onBlur={() => setCursor(null)}
          onPointerDown={(e) => {
            e.currentTarget.setPointerCapture(e.pointerId);
            drag.current = binAt(e.clientX);
            setCursor(drag.current);
          }}
          onPointerMove={(e) => {
            const b = binAt(e.clientX);
            setCursor(b);
            if (drag.current !== null && b !== drag.current) select(drag.current, b);
          }}
          onPointerUp={(e) => {
            const start = drag.current;
            drag.current = null;
            if (start === null) return;
            const b = binAt(e.clientX);
            select(start, b);
          }}
          onPointerLeave={() => {
            if (drag.current === null) setCursor(null);
          }}
        >
          <canvas ref={canvasRef} aria-hidden="true" />
        </div>
        <div />
        <div>
          <div className="ts-axis mono num">
            <span>{isoUtc(t0 * 1000)}</span>
            <span>{fmtDuration(span)}</span>
            <span>{isoUtc(t1 * 1000)}</span>
          </div>
          <div className="ts-note">
            <span>
              Bar height: alerts per column, log scale, max {fmtInt(binned.max)}. 1 column ={' '}
              {binSeconds >= 1 ? fmtDuration(binSeconds) : `${binSeconds.toFixed(2)} s`}. UTC.
            </span>
            {selection && (
              <>
                <span className="mono num">
                  Range {isoUtc(selection.from * 1000)} to {isoUtc(Math.min(selection.to, t1) * 1000)}
                </span>
                <Button kind="ghost" icon="close" onClick={() => onSelect(null)}>
                  Clear range
                </Button>
              </>
            )}
          </div>
          <div className={`ts-cursor num${cursorText ? ' mono' : ''}`} aria-live="polite">
            {cursorText ?? (selection ? '' : 'Drag, or use the arrow keys with Shift, to filter the alert table by time.')}
          </div>
        </div>
      </div>
      <table className="visually-hidden">
        <caption>Alerts per time bucket and detector</caption>
        <thead>
          <tr>
            <th scope="col">Bucket start (UTC)</th>
            {detectors.map((d) => (
              <th key={d} scope="col">
                {detectorName(d)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: buckets }, (_, i) => (
            <tr key={i}>
              <th scope="row">{isoUtc(binRange(i, i, coarse).from * 1000)}</th>
              {detectors.map((d) => (
                <td key={d}>{coarse.rows.get(d)?.[i] ?? 0}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
