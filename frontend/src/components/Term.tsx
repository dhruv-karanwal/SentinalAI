// <Term>: a word with a "?" that explains it from the one glossary (src/content/glossary.ts).
// The tooltip opens on hover and on keyboard focus of the "?" button, closes on Esc, blur or
// pointer leave, and is tied to the button with aria-describedby, so screen readers read the
// definition too. Text nodes only.

import { useEffect, useId, useRef, useState, type ReactNode } from 'react';

import { glossaryTerm } from '../content/glossary.ts';

export function Term({ id, children, plain = false }: { id: string; children?: ReactNode; plain?: boolean }) {
  const t = glossaryTerm(id);
  const tipId = useId();
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ left: number; top: number; above: boolean }>({ left: 0, top: 0, above: false });
  const btn = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
        e.stopPropagation();
      }
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [open]);
  if (!t) return <>{children}</>;
  const show = () => {
    // fixed position from the button, so a scrolling pane never clips the tooltip
    const r = btn.current?.getBoundingClientRect();
    if (r) {
      const above = r.bottom + 180 > window.innerHeight;
      setPos({ left: Math.max(8, Math.min(r.left - 8, window.innerWidth - 328)), top: above ? r.top - 6 : r.bottom + 6, above });
    }
    setOpen(true);
  };
  return (
    <span className={`term${plain ? ' term-plain' : ''}`} onPointerEnter={show} onPointerLeave={() => setOpen(false)}>
      {children ?? t.term}
      <button
        ref={btn}
        type="button"
        className="term-q"
        aria-label={`What is ${t.term}?`}
        aria-describedby={tipId}
        aria-expanded={open}
        onFocus={show}
        onBlur={() => setOpen(false)}
        onClick={() => (open ? setOpen(false) : show())}
      >
        ?
      </button>
      <span id={tipId} role="tooltip" className="term-tip" data-open={open || undefined}
        style={{ left: pos.left, top: pos.top, transform: pos.above ? 'translateY(-100%)' : undefined }}
      >
        <span className="term-tip-head">{t.term}</span>
        <span>{t.definition}</span>
        <span className="term-tip-why">
          <strong>Why it matters here:</strong> {t.why}
        </span>
      </span>
    </span>
  );
}

/** The one-line "What you're looking at / Why it matters" pair under a section title. */
export function Explain({ what, why }: { what: ReactNode; why: ReactNode }) {
  return (
    <div className="explain">
      <p>
        <span className="explain-k">What you're looking at:</span> {what}
      </p>
      <p>
        <span className="explain-k">Why it matters:</span> {why}
      </p>
    </div>
  );
}
