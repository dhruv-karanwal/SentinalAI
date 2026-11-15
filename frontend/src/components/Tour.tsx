// Guided tour ("Start here"): six stops, About -> Overview -> Incidents -> Alerts -> Approvals ->
// Study. A small non-modal panel (bottom left, never over the chat launcher): Back, Next, Skip;
// Esc ends the tour. It moves the hash route; the screens themselves are unchanged.

import { useEffect, useRef } from 'react';

import { TOUR } from '../content/about.ts';
import { Button } from './ui.tsx';

export function TourPanel({ step, onStep, onClose }: { step: number; onStep: (n: number) => void; onClose: () => void }) {
  const stop = TOUR[step];
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (stop && window.location.hash.replace(/^#/, '').split('?')[0] !== stop.path) window.location.hash = `#${stop.path}`;
    ref.current?.querySelector<HTMLElement>('h2')?.focus();
  }, [stop]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && ref.current?.contains(document.activeElement)) {
        onClose();
        e.preventDefault();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  if (!stop) return null;
  const last = step === TOUR.length - 1;
  return (
    <div className="tour no-print" ref={ref} role="region" aria-label="Guided tour" aria-live="polite">
      <h2 tabIndex={-1}>{stop.title}</h2>
      <p>{stop.text}</p>
      <span className="visually-hidden">Stop {step + 1} of {TOUR.length}</span>
      <div className="tour-progress" aria-hidden="true">
        {TOUR.map((s, i) => (
          <span key={s.path} data-on={i <= step || undefined} />
        ))}
      </div>
      <div className="tour-actions">
        <Button kind="ghost" onClick={onClose}>
          Skip tour
        </Button>
        <span className="spacer" />
        <Button onClick={() => onStep(step - 1)} disabled={step === 0}>
          Back
        </Button>
        <Button kind="primary" onClick={() => (last ? onClose() : onStep(step + 1))}>
          {last ? 'Finish' : 'Next'}
        </Button>
      </div>
    </div>
  );
}
