// "How it works" (DESIGN.md 7): twelve detector marks move once through the five pipeline stages
// when the flow scrolls into view, one short step per stage (step time from the duration tokens),
// then stop; "Replay" plays it again. Each stage is an accordion button that opens what the stage
// does and its real components. Reduced motion shows the final state at once.

import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';

import type { Overview } from '../../api.ts';
import { PIPELINE } from '../../content/about.ts';
import { Icon } from '../../icons.tsx';
import { FLOW_LAST, interleave, markAt, parseMs, shareSplit, stepMs } from '../../lib/flow.ts';
import { prefersReducedMotion } from '../../lib/motion.ts';
import { useSeen } from '../motion.tsx';
import { Button, detectorName } from '../ui.tsx';

const N = 12;
export const FLOW_DETECTORS = ['wazuh', 'suricata', 'aminer'] as const;

/** One detector per mark, in the scenario's real detector shares (equal split before data arrives). */
export function flowDetectors(overview: Overview | null): string[] {
  const counts = FLOW_DETECTORS.map((d) => ({ key: d, count: overview?.detectors.find((r) => r.detector === d)?.alerts ?? 0 }));
  return interleave(shareSplit(counts, N));
}

function tokenMs(name: string): number {
  try {
    return parseMs(getComputedStyle(document.documentElement).getPropertyValue(name));
  } catch {
    return 0;
  }
}

export function PipelineFlow({ overview }: { overview: Overview | null }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const seen = useSeen(ref, '0px 0px -25% 0px');
  const [step, setStep] = useState(-1);
  const [run, setRun] = useState(0);
  const [open, setOpen] = useState<number | null>(null);
  const dets = useMemo(() => flowDetectors(overview), [overview]);

  useEffect(() => {
    if (!seen) return;
    const each = stepMs(tokenMs('--dur-slow'), tokenMs('--stagger'), N);
    if (prefersReducedMotion() || each <= 0) {
      setStep(FLOW_LAST);
      return;
    }
    setStep(-1);
    const timers: number[] = [];
    // one frame at -1 so the marks start off-track, then one step per stage; the last step ends it
    const raf = requestAnimationFrame(() => {
      for (let s = 0; s <= FLOW_LAST; s += 1) timers.push(window.setTimeout(() => setStep(s), s * each));
    });
    return () => {
      cancelAnimationFrame(raf);
      timers.forEach((t) => window.clearTimeout(t));
    };
  }, [seen, run]);

  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const btns = Array.from(e.currentTarget.querySelectorAll<HTMLButtonElement>('.ab-stage-btn'));
    const i = btns.indexOf(document.activeElement as HTMLButtonElement);
    if (i < 0) return;
    const to = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? (i + 1) % btns.length : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? (i - 1 + btns.length) % btns.length : e.key === 'Home' ? 0 : e.key === 'End' ? btns.length - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    btns[to]?.focus();
  };

  const done = step >= FLOW_LAST;
  return (
    <div className="ab-flow" ref={ref}>
      <div className="ab-flow-bar">
        <ul className="ab-legend" aria-label="Marks in the flow">
          {FLOW_DETECTORS.map((d) => (
            <li key={d}>
              <i className="ab-mark" data-det={d} aria-hidden="true" />
              {detectorName(d)} alert
            </li>
          ))}
        </ul>
        <span className="ab-tag">Schematic</span>
        <Button className="ab-replay" kind="ghost" icon="refresh" onClick={() => setRun((r) => r + 1)} disabled={!seen || !done}>
          Replay
        </Button>
      </div>
      <div
        className="ab-track"
        role="img"
        aria-label={`Schematic: ${N} alerts (${FLOW_DETECTORS.map((d) => `${dets.filter((x) => x === d).length} ${detectorName(d)}`).join(', ')}) enter at Ingest, are grouped into one incident at Detect and triage, read at Investigate; at Verify 3 unsupported citations drop out; the rest reach Report and review.`}
      >
        <div className="ab-rail" aria-hidden="true" />
        {PIPELINE.map((s, i) => (
          <span key={s.n} className="ab-station" style={{ '--st': i } as React.CSSProperties} data-reached={step >= i ? '' : undefined} aria-hidden="true" />
        ))}
        {dets.map((d, i) => {
          const p = markAt(i, N, step);
          return (
            <i
              key={i}
              className="ab-mark ab-move"
              data-det={d}
              data-shown={p.shown ? '' : undefined}
              aria-hidden="true"
              style={{ '--st': p.stage, '--dx': p.dx, '--dy': p.dy, '--i': i } as React.CSSProperties}
            />
          );
        })}
      </div>

      <div className="ab-stages" onKeyDown={onKey}>
        {PIPELINE.map((s, i) => {
          const isOpen = open === i;
          return (
            <div key={s.n} className="ab-stage" style={{ '--c': i + 1 } as React.CSSProperties}>
              <h3 className="ab-stage-h">
                <button
                  type="button"
                  className="ab-stage-btn"
                  id={`ab-stage-${s.n}`}
                  aria-expanded={isOpen}
                  aria-controls={`ab-stage-panel-${s.n}`}
                  data-reached={step >= i ? '' : undefined}
                  onClick={() => setOpen(isOpen ? null : i)}
                >
                  <span className="ab-stage-n num">{s.n}</span>
                  <span className="ab-stage-name">{s.name}</span>
                  <Icon name="chevronDown" />
                </button>
              </h3>
              <div className="ab-stage-panel" id={`ab-stage-panel-${s.n}`} role="region" aria-labelledby={`ab-stage-${s.n}`} hidden={!isOpen}>
                <p>{s.plain}</p>
                <ul className="ab-comps">
                  {s.components.map((c) => (
                    <li key={c}>{c}</li>
                  ))}
                </ul>
              </div>
            </div>
          );
        })}
      </div>
      {open === null && <p className="ab-hint">Select a stage to see what it does and the components behind it.</p>}
    </div>
  );
}
