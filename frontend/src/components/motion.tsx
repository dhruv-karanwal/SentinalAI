// Motion primitives (DESIGN.md 13.2): scroll reveal, count-up numbers, chart draw-in on first view,
// pointer tilt. IntersectionObserver + requestAnimationFrame only; every one shows the final state
// at once under prefers-reduced-motion.

import { useEffect, useRef, useState, type RefObject } from 'react';

import { countAt, prefersReducedMotion } from '../lib/motion.ts';
import { fmtInt } from '../lib/format.ts';

/** True once the element has been on screen (fires once, then disconnects). */
export function useSeen<T extends Element>(ref: RefObject<T | null>, rootMargin = '0px 0px -10% 0px'): boolean {
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el || seen) return;
    if (prefersReducedMotion() || typeof IntersectionObserver === 'undefined') {
      setSeen(true);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setSeen(true);
          io.disconnect();
        }
      },
      { rootMargin },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [ref, rootMargin, seen]);
  return seen;
}

/** Wrapper that fades/slides its children in the first time they scroll into view. */
export function Reveal({ children, i = 0, as: Tag = 'div', className, id, sev, ...rest }: { children: React.ReactNode; i?: number; as?: 'div' | 'section' | 'li'; className?: string; id?: string; sev?: string; 'aria-labelledby'?: string }) {
  const ref = useRef<HTMLElement | null>(null);
  const seen = useSeen(ref);
  return (
    <Tag
      ref={ref as never}
      id={id}
      className={className}
      data-reveal=""
      data-sev={sev}
      data-shown={seen ? '' : undefined}
      style={{ '--i': i } as React.CSSProperties}
      {...rest}
    >
      {children}
    </Tag>
  );
}

/** A number that counts up from 0 once it is seen; prints the exact value for screen readers. */
export function Count({ value, duration = 900 }: { value: number; duration?: number }) {
  const ref = useRef<HTMLSpanElement | null>(null);
  const seen = useSeen(ref);
  const [shown, setShown] = useState(0);
  useEffect(() => {
    if (!seen) return;
    const d = prefersReducedMotion() ? 0 : duration;
    if (d === 0) {
      setShown(value);
      return;
    }
    let raf = 0;
    const t0 = performance.now();
    const tick = (now: number) => {
      const v = countAt(value, now - t0, d);
      setShown(v);
      if (v !== value) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [seen, value, duration]);
  return (
    <span ref={ref} className="num" aria-label={fmtInt(value)}>
      <span aria-hidden="true">{fmtInt(seen ? shown : 0)}</span>
    </span>
  );
}

/** data-drawn="0" until first seen, then "1": motion.css grows bars and fades lines in once. */
export function DrawOnView({ children, className }: { children: React.ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const seen = useSeen(ref);
  return (
    <div ref={ref} className={className} data-drawn={seen ? '1' : '0'}>
      {children}
    </div>
  );
}

/** Pointer tilt for a card: sets --rx / --ry / --gx / --gy (transform only). */
export function tiltHandlers() {
  if (prefersReducedMotion()) return {};
  return {
    onPointerMove: (e: React.PointerEvent<HTMLElement>) => {
      const el = e.currentTarget;
      const r = el.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width;
      const y = (e.clientY - r.top) / r.height;
      el.style.setProperty('--ry', `${(x - 0.5) * 8}deg`);
      el.style.setProperty('--rx', `${(0.5 - y) * 8}deg`);
      el.style.setProperty('--gx', `${e.clientX - r.left}px`);
      el.style.setProperty('--gy', `${e.clientY - r.top}px`);
    },
    onPointerLeave: (e: React.PointerEvent<HTMLElement>) => {
      const el = e.currentTarget;
      el.style.setProperty('--rx', '0deg');
      el.style.setProperty('--ry', '0deg');
    },
  };
}
